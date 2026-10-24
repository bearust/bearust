//! Layer-4 TCP/UDP proxying: forwarding, backend failover, per-client UDP
//! sessions, IP policy, and config validation.

use bearust::config::{StreamConfig, StreamProtocol};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn config(protocol: StreamProtocol, listen: SocketAddr, backends: Vec<SocketAddr>) -> StreamConfig {
    StreamConfig {
        name: "test".into(),
        protocol,
        listen,
        backends,
        connect_timeout_ms: 500,
        idle_timeout_seconds: 2,
        max_connections: 16,
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0
                        || socket
                            .write_all(&[b"echo:", &buf[..n]].concat())
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// An address nothing listens on.
fn dead() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test]
async fn tcp_forwards_and_fails_over_from_a_dead_backend() {
    let backend = tcp_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let (_stop, shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(bearust::stream_proxy::serve_tcp_listener(
        listener,
        config(StreamProtocol::Tcp, proxy, vec![dead(), backend]),
        None,
        shutdown,
    ));
    for _ in 0..3 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"echo:ping");
    }
}

#[tokio::test]
async fn tcp_respects_the_ip_policy() {
    let dir = tempfile::tempdir().unwrap();
    let state = bearust::control_plane::build_state("sqlite::memory:", dir.path(), "setup")
        .await
        .unwrap();
    bearust::control_plane::repository::insert_ip_security_rule(
        &state.db,
        &bearust::control_plane::models::IpSecurityRule {
            id: 0,
            cidr: "127.0.0.1/32".into(),
            action: bearust::control_plane::models::IpSecurityAction::Block,
            score: 100,
            country_code: None,
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .await
    .unwrap();
    state.ip_security.reload(&state.db).await.unwrap();
    let backend = tcp_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let (_stop, shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(bearust::stream_proxy::serve_tcp_listener(
        listener,
        config(StreamProtocol::Tcp, proxy, vec![backend]),
        Some(state.ip_security.clone()),
        shutdown,
    ));
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let _ = client.write_all(b"ping").await;
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "blocked client must be closed"
    );
}

#[tokio::test]
async fn udp_keeps_a_session_per_client() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let (n, from) = backend.recv_from(&mut buf).await.unwrap();
            let reply = [b"echo:", &buf[..n]].concat();
            backend.send_to(&reply, from).await.unwrap();
        }
    });
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = socket.local_addr().unwrap();
    let (_stop, shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(bearust::stream_proxy::serve_udp_socket(
        socket,
        config(StreamProtocol::Udp, proxy, vec![backend_addr]),
        None,
        shutdown,
    ));
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..2 {
        a.send_to(b"from-a", proxy).await.unwrap();
        b.send_to(b"from-b", proxy).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), a.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"echo:from-a");
        let n = tokio::time::timeout(Duration::from_secs(2), b.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"echo:from-b");
    }
}

#[test]
fn config_validation_rejects_bad_streams() {
    let toml = |stream: &str| {
        format!(
            r#"
[server]
bind = "127.0.0.1:8080"
control_bind = "127.0.0.1:8081"
control_database = "sqlite::memory:"
certificate_store = "./target/certs"
pid_file = "./target/pid"
{stream}
"#
        )
    };
    let parse = |stream: &str| {
        toml::from_str::<bearust::config::Config>(&toml(stream))
            .unwrap()
            .validate()
    };
    assert!(parse(
        r#"
[[streams]]
name = "pg"
protocol = "tcp"
listen = "127.0.0.1:5433"
backends = ["127.0.0.1:5432"]
"#
    )
    .is_ok());
    for bad in [
        // No backends.
        r#"[[streams]]
name = "x"
protocol = "tcp"
listen = "127.0.0.1:9000"
backends = []"#,
        // Collides with the HTTP listener.
        r#"[[streams]]
name = "x"
protocol = "tcp"
listen = "127.0.0.1:8080"
backends = ["127.0.0.1:1"]"#,
        // Duplicate TCP listen address.
        r#"[[streams]]
name = "a"
protocol = "tcp"
listen = "127.0.0.1:9000"
backends = ["127.0.0.1:1"]
[[streams]]
name = "b"
protocol = "tcp"
listen = "127.0.0.1:9000"
backends = ["127.0.0.1:1"]"#,
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}
