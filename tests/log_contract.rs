#![cfg(unix)]

use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use tempfile::tempdir;

fn backend(listener: TcpListener) {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_backend(stream);
        }
    });
}

fn handle_backend(mut stream: TcpStream) {
    let mut buf = [0u8; 2048];
    let _ = stream.read(&mut buf);
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
    let _ = stream.write_all(response);
}

#[test]
fn json_logs_are_parseable_and_redacted_for_success_and_404() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    backend(backend_listener);
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bearust.toml");
    let pid_path = dir.path().join("bearust.pid");
    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
bind = "{proxy_addr}"
control_bind = "127.0.0.1:0"
pid_file = "{}"
graceful_shutdown_seconds = 1
[health]
interval_seconds = 1
timeout_seconds = 1
healthy_threshold = 1
unhealthy_threshold = 1
[[upstream_pools]]
name = "api"
algorithm = "round_robin"
[[upstream_pools.backends]]
address = "{backend_addr}"
health_check = "tcp"
health_path = ""
[[routes]]
name = "api"
host = "api.example.test"
path_prefix = "/"
upstream_pool = "api"
"#,
            pid_path.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .env("DATABASE_URL", "sqlite::memory:")
        .args(["--json-logs"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client = reqwest::blocking::Client::new();
    let mut success = false;
    for _ in 0..40 {
        if let Ok(response) = client
            .get(format!("http://{proxy_addr}/ok"))
            .header("Host", "api.example.test")
            .header("X-Request-Id", "req-1")
            .body("super-secret-body")
            .send()
        {
            if response.status().is_success() {
                success = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
    assert!(success, "proxy never became healthy");
    let not_found = client
        .get(format!("http://{proxy_addr}/missing"))
        .header("Host", "unknown.example.test")
        .send()
        .unwrap();
    assert_eq!(not_found.status(), reqwest::StatusCode::NOT_FOUND);
    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    child.wait().unwrap();
    let events: Vec<Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let completes: Vec<&Value> = events
        .iter()
        .filter(|event| event.get("event") == Some(&Value::String("request_complete".into())))
        .collect();
    assert!(completes
        .iter()
        .any(|event| event.get("status") == Some(&Value::from(200))));
    assert!(completes
        .iter()
        .any(|event| event.get("status") == Some(&Value::from(404))));
    for event in completes {
        for field in ["request_id", "route", "upstream", "status", "latency_ms"] {
            assert!(event.get(field).is_some(), "missing {field}: {event}");
        }
        assert!(event.get("body").is_none() && event.get("headers").is_none());
    }
    assert!(!output.contains("super-secret-body"));
}
