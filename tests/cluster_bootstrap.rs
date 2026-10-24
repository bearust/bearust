#![cfg(unix)]

//! Process-level regression coverage for production cluster bootstrap:
//! `bearust serve` must initialize Raft membership at startup so a
//! configured multi-node cluster elects a leader, replicates proxy-host
//! writes, and re-elects after the leader stops. The in-process Raft
//! tests cannot see a missing startup bootstrap; only real processes can.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // Each node runs in its own process group (supervisor + proxy
            // child); kill the whole group so no grandchild lingers.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(self.0.id() as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Option<(u16, String, Vec<String>)> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut request = format!("{method} {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n");
    if let Some(cookie) = cookie {
        request += &format!("cookie: {cookie}\r\n");
    }
    if let Some(csrf) = csrf {
        request += &format!("x-csrf-token: {csrf}\r\n");
    }
    if let Some(body) = body {
        request += "content-type: application/json\r\n";
        request += &format!("content-length: {}\r\n", body.len());
        request += "\r\n";
        request += body;
    } else {
        request += "\r\n";
    }
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&raw);
            if let Some(len) = text.split("\r\n").find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            {
                let header_end = text.find("\r\n\r\n").unwrap() + 4;
                if raw.len() >= header_end + len {
                    break;
                }
            }
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let set_cookies = text
        .lines()
        .filter_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("set-cookie:")
                .map(|_value| line[lower.find(':').unwrap() + 1..].trim().to_owned())
        })
        .collect();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_default();
    Some((status, body, set_cookies))
}

fn wait_until(deadline: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    check()
}

struct Node {
    control: String,
    child: Option<ChildGuard>,
    cookie: String,
    csrf: String,
}

impl Node {
    fn status_role(&mut self) -> String {
        let Some((_, body, _)) = http(
            &self.control,
            "GET",
            "/api/cluster/status",
            None,
            Some(&self.cookie.clone()),
            None,
        ) else {
            return String::new();
        };
        if body.contains("\"raft_role\":\"leader\"") {
            "leader".into()
        } else if body.contains("\"raft_role\":\"follower\"") {
            "follower".into()
        } else {
            String::new()
        }
    }
}

#[test]
fn serve_bootstraps_cluster_elects_leader_replicates_and_fails_over() {
    let dir = tempfile::tempdir().unwrap();
    let ids = ["node1", "node2", "node3"];
    let proxies: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let controls: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let clusters: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let token = "cluster-bootstrap-test-token-32-plus-chars";

    let mut children = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let peers = ids
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer != &id)
            .map(|(peer_index, peer)| {
                format!(
                    "{{ node_id = \"{peer}\", address = \"127.0.0.1:{}\" }}",
                    clusters[peer_index]
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "[server]\nbind = \"127.0.0.1:{}\"\ncontrol_bind = \"127.0.0.1:{}\"\ncontrol_database = \"{}\"\npid_file = \"{}\"\ncertificate_store = \"{}\"\n\n[cluster]\nnode_id = \"{id}\"\nbind = \"127.0.0.1:{}\"\nauth_token = \"{token}\"\npeers = [{peers}]\n",
            proxies[index],
            controls[index],
            dir.path().join(format!("{id}.sqlite")).display(),
            dir.path().join(format!("{id}.pid")).display(),
            dir.path().join(format!("certs-{id}")).display(),
            clusters[index],
        );
        let config_path = dir.path().join(format!("{id}.toml"));
        std::fs::write(&config_path, config).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_bearust"));
        command
            .args(["serve", "--config"])
            .arg(&config_path)
            .env("BEARUST_SETUP_TOKEN", "cluster-bootstrap-token")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let child = command.spawn().unwrap();
        children.push(ChildGuard(child));
    }

    // Wait for the control planes, then initialize and log in everywhere.
    let mut nodes: Vec<Node> = Vec::new();
    for (index, child) in children.into_iter().enumerate() {
        let control = format!("127.0.0.1:{}", controls[index]);
        let healthy = wait_until(Duration::from_secs(30), || {
            matches!(
                http(&control, "GET", "/api/health", None, None, None),
                Some((200, _, _))
            )
        });
        assert!(healthy, "control plane {control} never became healthy");
        let (status, _, _) = http(
            &control,
            "POST",
            "/api/setup/initialize",
            Some(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"cluster-bootstrap-token"}"#),
            None,
            None,
        )
        .expect("setup initialize request");
        assert_eq!(status, 201, "setup initialize on {control}");
        let (status, _, set_cookies) = http(
            &control,
            "POST",
            "/api/auth/login",
            Some(r#"{"email":"admin@example.com","password":"correct horse battery"}"#),
            None,
            None,
        )
        .expect("login request");
        assert_eq!(status, 200, "login on {control}");
        let mut session = String::new();
        let mut csrf = String::new();
        for raw in &set_cookies {
            let pair = raw.split(';').next().unwrap_or_default().trim();
            if let Some(value) = pair.strip_prefix("bearust_session=") {
                session = value.to_owned();
            }
            if let Some(value) = pair.strip_prefix("bearust_csrf=") {
                csrf = value.to_owned();
            }
        }
        assert!(!session.is_empty() && !csrf.is_empty(), "login cookies on {control}");
        nodes.push(Node {
            control,
            child: Some(child),
            cookie: format!("bearust_session={session}; bearust_csrf={csrf}"),
            csrf,
        });
    }

    // Exactly one leader must emerge from the startup bootstrap.
    let mut leader = None;
    let elected = wait_until(Duration::from_secs(30), || {
        for (index, node) in nodes.iter_mut().enumerate() {
            if node.status_role() == "leader" {
                leader = Some(index);
                return true;
            }
        }
        false
    });
    assert!(elected, "no leader elected after startup bootstrap");
    let leader = leader.unwrap();

    // A proxy-host write on the leader must replicate to the followers.
    let node = &nodes[leader];
    let (status, body, _) = http(
        &node.control.clone(),
        "POST",
        "/api/proxy-hosts",
        Some(r#"{"name":"cluster-demo","domain":"demo.local","upstream_host":"127.0.0.1","upstream_port":9001}"#),
        Some(&node.cookie.clone()),
        Some(&node.csrf.clone()),
    )
    .expect("create proxy host request");
    assert_eq!(status, 201, "create proxy host on leader: {body}");
    for node in nodes.iter_mut() {
        let control = node.control.clone();
        let cookie = node.cookie.clone();
        let replicated = wait_until(Duration::from_secs(15), || {
            matches!(
                http(&control, "GET", "/api/proxy-hosts", None, Some(&cookie), None),
                Some((_, body, _)) if body.contains("demo.local")
            )
        });
        assert!(replicated, "proxy host not replicated to {control}");
    }

    // Stopping the leader must trigger a re-election among the survivors.
    let mut leader_node = nodes.remove(leader);
    let child = leader_node.child.take().unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(-(child.0.id() as i32)),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    drop(child);
    let reelected = wait_until(Duration::from_secs(30), || {
        nodes.iter_mut().any(|node| node.status_role() == "leader")
    });
    assert!(reelected, "no re-election after leader shutdown");
}
