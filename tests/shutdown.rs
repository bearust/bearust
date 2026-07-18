#![cfg(unix)]

use bearust::{
    config,
    reload::signal_loop,
    runtime::{RuntimeSnapshot, RuntimeStore},
};
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::{mpsc, Arc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

static PROCESS_LIFECYCLE: OnceLock<Mutex<()>> = OnceLock::new();

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = kill(Pid::from_raw(self.0.id() as i32), Signal::SIGKILL);
            let _ = self.0.wait();
        }
    }
}

struct Backend {
    address: std::net::SocketAddr,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Backend {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_backend() -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, rx) = mpsc::channel();
    let thread = thread::spawn(move || loop {
        if rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while request.len() < 8192 {
                        if stream.read_exact(&mut byte).is_err() {
                            break;
                        }
                        request.push(byte[0]);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let health = request.windows(16).any(|w| w == b"GET /health HTTP");
                    if !health {
                        thread::sleep(Duration::from_millis(200));
                    }
                    let body = if health { "ok" } else { "slow-response" };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => break,
        }
    });
    Backend {
        address,
        stop: Some(stop),
        thread: Some(thread),
    }
}

fn wait_for_port(address: std::net::SocketAddr, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(address).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("listener {address} did not become ready");
}

#[tokio::test]
async fn signal_loop_rejects_invalid_hup_then_stops_workers_on_term() {
    let _lock = PROCESS_LIFECYCLE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot = RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = Arc::new(RuntimeStore::new(snapshot));
    let task = tokio::spawn(signal_loop(
        Arc::clone(&store),
        path.clone(),
        Duration::from_millis(250),
    ));
    // Give Tokio a scheduling turn to install the process signal handlers
    // before delivering the first signal.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    std::fs::write(&path, "[server]\nbind = \"broken\"\n").unwrap();
    kill(Pid::this(), Signal::SIGHUP).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.load().generation(), 1);

    kill(Pid::this(), Signal::SIGTERM).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn serve_exits_promptly_on_sigterm() {
    let _lock = PROCESS_LIFECYCLE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("bearust.toml");
    let pid = temp.path().join("bearust.pid");
    let text = include_str!("fixtures/valid.toml").replace(
        "bind = \"127.0.0.1:18080\"",
        &format!(
            "bind = \"127.0.0.1:18180\"\ngraceful_shutdown_seconds = 1\npid_file = \"{}\"",
            pid.display()
        ),
    );
    std::fs::write(&config, text).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_bearust"))
            .args(["serve", "--config"])
            .arg(&config)
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if pid.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(pid.exists(), "server did not create pid file");
    wait_for_port("127.0.0.1:18180".parse().unwrap(), Duration::from_secs(2));
    kill(Pid::from_raw(child.0.id() as i32), Signal::SIGTERM).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if child.0.try_wait().unwrap().is_some() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "server did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = child.0.wait().unwrap();
    assert!(
        status.success(),
        "server did not exit successfully: {status:?}"
    );
}

#[test]
fn sigterm_drains_active_request_and_stops_accepting() {
    let _lock = PROCESS_LIFECYCLE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let backend = spawn_backend();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("bearust.toml");
    let pid = temp.path().join("bearust.pid");
    let config_text = format!(
        r#"[server]
bind = "{proxy_address}"
graceful_shutdown_seconds = 1
pid_file = "{}"

[health]
interval_seconds = 1
timeout_seconds = 1
healthy_threshold = 1
unhealthy_threshold = 1

[[upstream_pools]]
name = "api"
algorithm = "round_robin"
connect_timeout_seconds = 1
request_timeout_seconds = 2

[[upstream_pools.backends]]
address = "{}"
health_check = "http"
health_path = "/health"

[[routes]]
name = "api"
host = "api.example.com"
path_prefix = "/"
upstream_pool = "api"
"#,
        pid.display(),
        backend.address
    );
    std::fs::write(&config, config_text).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_bearust"))
            .args(["serve", "--config"])
            .arg(&config)
            .spawn()
            .unwrap(),
    );
    wait_for_port(proxy_address, Duration::from_secs(3));
    // Allow the one-success health threshold to admit the backend before
    // starting the request that exercises graceful draining.
    thread::sleep(Duration::from_millis(250));
    let request_address = proxy_address;
    let request = thread::spawn(move || {
        let mut stream = TcpStream::connect(request_address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
            .unwrap();
        let start = Instant::now();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        (start.elapsed(), response)
    });
    thread::sleep(Duration::from_millis(50));
    kill(Pid::from_raw(child.0.id() as i32), Signal::SIGTERM).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        TcpStream::connect(proxy_address).is_err(),
        "new connections accepted after SIGTERM"
    );
    let (elapsed, response) = request.join().unwrap();
    assert!(
        elapsed >= Duration::from_millis(150),
        "request was not allowed to drain: {elapsed:?}"
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "in-flight request failed: {response:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "server exceeded graceful shutdown bound"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "server exited unsuccessfully: {status}");
}
