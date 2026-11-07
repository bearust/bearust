//! HTTP/3 upstreams: the QUIC client against a local h3 server, and the
//! Pingora proxy forwarding an HTTP/1.1 request to an HTTP/3 pool.

use bearust::config::UpstreamHttp3Config;
use bearust::h3_upstream::H3Upstream;
use bytes::{Buf, Bytes};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Upstream {
    addr: SocketAddr,
    ca_pem: String,
    connections: Arc<AtomicUsize>,
}

/// An h3 server for `localhost` that answers `<method> <path> <body>` and
/// sets `x-upstream: h3`.
async fn spawn_h3_upstream() -> Upstream {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca_pem = cert.cert.pem();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(quic)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        let mut body = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                        }
                        let reply = format!(
                            "{} {} {}",
                            request.method(),
                            request.uri().path(),
                            String::from_utf8_lossy(&body)
                        );
                        let response = http::Response::builder()
                            .status(201)
                            .header("x-upstream", "h3")
                            .body(())
                            .unwrap();
                        stream.send_response(response).await.unwrap();
                        stream.send_data(Bytes::from(reply)).await.unwrap();
                        stream.finish().await.unwrap();
                    });
                }
            });
        }
    });
    Upstream {
        addr,
        ca_pem,
        connections,
    }
}

fn tls(
    upstream: &Upstream,
    dir: &std::path::Path,
    server_name: &str,
    insecure: bool,
) -> UpstreamHttp3Config {
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, &upstream.ca_pem).unwrap();
    UpstreamHttp3Config {
        server_name: server_name.into(),
        ca_file: (!insecure).then_some(ca),
        insecure_skip_verify: insecure,
    }
}

async fn call(client: &H3Upstream, addr: SocketAddr, body: &str) -> Result<(u16, String), String> {
    let request = http::Request::post("https://localhost/echo")
        .body(())
        .unwrap();
    let mut response = client
        .send(
            addr,
            request,
            Bytes::from(body.to_owned()),
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        out.extend_from_slice(&chunk);
    }
    Ok((
        response.head.status().as_u16(),
        String::from_utf8(out).unwrap(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_verifies_tls_and_reuses_the_connection() {
    let upstream = spawn_h3_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let client = H3Upstream::new(&tls(&upstream, dir.path(), "localhost", false)).unwrap();
    for body in ["one", "two"] {
        assert_eq!(
            call(&client, upstream.addr, body).await.unwrap(),
            (201, format!("POST /echo {body}"))
        );
    }
    assert_eq!(
        upstream.connections.load(Ordering::SeqCst),
        1,
        "connection is reused"
    );

    // Wrong name for the certificate: refused.
    let wrong = H3Upstream::new(&tls(&upstream, dir.path(), "evil.example", false)).unwrap();
    assert!(call(&wrong, upstream.addr, "x").await.is_err());
    // Explicitly insecure: accepted.
    let insecure = H3Upstream::new(&tls(&upstream, dir.path(), "localhost", true)).unwrap();
    assert!(call(&insecure, upstream.addr, "x").await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts a process-wide Pingora server; run with cargo test --test h3_upstream -- --ignored"]
async fn pingora_forwards_http1_requests_to_an_http3_pool() {
    use bearust::config::*;
    use bearust::proxy::{http_service, BearustProxy};
    use bearust::runtime::{RuntimeSnapshot, RuntimeStore};
    use pingora_core::server::{configuration::ServerConf, Server};

    let upstream = spawn_h3_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let h3 = tls(&upstream, dir.path(), "localhost", false);
    let config = Config {
        server: ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            control_bind: "127.0.0.1:0".parse().unwrap(),
            control_database: "./target/test.sqlite".into(),
            certificate_store: "./target/test-certs".into(),
            graceful_shutdown_seconds: 1,
            pid_file: "./target/test.pid".into(),
            tls: None,
            http3: Default::default(),
            trusted_proxy_cidrs: Vec::new(),
            geoip_database: None,
            https_bind: None,
            https_public_port: None,
        },
        health: Default::default(),
        upstream_pools: vec![PoolConfig {
            name: "quic".into(),
            algorithm: Algorithm::RoundRobin,
            connect_timeout_seconds: 2,
            request_timeout_seconds: 5,
            passive_health: false,
            http3: Some(h3),
            backends: vec![BackendConfig {
                address: upstream.addr,
                health_check: HealthCheckKind::Tcp,
                health_path: None,
                weight: 1,
            }],
        }],
        routes: vec![RouteConfig {
            rate_limit: None,
            max_body_bytes: None,
            paused: false,
            waf: None,
            name: "default".into(),
            host: "example.test".into(),
            path_prefix: "/".into(),
            upstream_pool: "quic".into(),
        }],
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
        streams: Vec::new(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    snapshot.pool("quic").unwrap().set_healthy(0.into(), true);
    let runtime = Arc::new(RuntimeStore::new(snapshot));
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut server = Server::new(None).unwrap();
    let conf = Arc::new(ServerConf::default());
    let mut service = http_service(BearustProxy::new(runtime), &conf);
    service.add_tcp(&address.to_string());
    server.add_service(service);
    server.bootstrap();
    std::thread::spawn(move || server.run_forever());
    tokio::time::sleep(Duration::from_millis(300)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/echo"))
        .header("Host", "example.test")
        .body("over-quic")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(response.headers()["x-upstream"], "h3");
    assert_eq!(response.text().await.unwrap(), "POST /echo over-quic");
}
