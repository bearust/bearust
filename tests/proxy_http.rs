use bearust::observability::{append_forwarded_for, validated_request_id};
use bearust::{config::{Algorithm, BackendConfig, Config, HealthCheckKind, PoolConfig, RouteConfig, ServerConfig}, proxy::{http_service, BeaRustProxy}, runtime::{RuntimeSnapshot, RuntimeStore}};
use pingora_http::RequestHeader;
use pingora_core::server::{configuration::ServerConf, Server};
use std::{net::TcpListener, sync::Arc, time::Duration};

mod support;

#[test]
fn forwarding_headers_append_ip_and_request_id_is_safe() {
    let mut request = RequestHeader::build("GET", b"/", Some(2)).unwrap();
    request.insert_header("Host", "api.example.test").unwrap();
    request
        .insert_header("X-Forwarded-For", "10.0.0.1")
        .unwrap();
    append_forwarded_for(&mut request, Some("[2001:db8::1]:8080"));
    assert_eq!(request.headers.get("host").unwrap(), "api.example.test");
    assert_eq!(
        request.headers.get("x-forwarded-for").unwrap(),
        "10.0.0.1, 2001:db8::1"
    );
    assert_eq!(request.headers.get("x-forwarded-proto").unwrap(), "http");
    assert_eq!(validated_request_id(Some(b"req-1")), "req-1");
}

/// End-to-end harness for the Pingora service. It is ignored in normal unit runs because
/// Pingora's server owns a process-wide listener loop; run explicitly with `--ignored`.
#[tokio::test]
#[ignore = "starts a process-wide Pingora server; run with cargo test --test proxy_http -- --ignored"]
async fn local_pingora_service_routes_and_returns_503_without_healthy_backend() {
    let backend = support::spawn_http_backend(Arc::new(std::sync::atomic::AtomicU16::new(200)), "stream-body").await;
    let backend_addr = backend.address;
    let config = Config {
        server: ServerConfig { bind: "127.0.0.1:0".parse().unwrap(), graceful_shutdown_seconds: 1, pid_file: "./target/test.pid".into() },
        health: Default::default(),
        upstream_pools: vec![PoolConfig { name: "main".into(), algorithm: Algorithm::RoundRobin, connect_timeout_seconds: 1, request_timeout_seconds: 1, backends: vec![BackendConfig { address: backend_addr, health_check: HealthCheckKind::Tcp, health_path: None }] }],
        routes: vec![RouteConfig { name: "default".into(), host: "example.test".into(), path_prefix: "/".into(), upstream_pool: "main".into() }],
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    let pool = snapshot.pool("main").unwrap();
    // Start unhealthy first: this validates a clean downstream 503.
    let runtime = Arc::new(RuntimeStore::new(snapshot));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut server = Server::new(None).unwrap();
    let conf = Arc::new(ServerConf::default());
    let mut service = http_service(BeaRustProxy::new(Arc::clone(&runtime)), &conf);
    service.add_tcp(&address.to_string());
    server.add_service(service);
    server.bootstrap();
    std::thread::spawn(move || server.run_forever());
    tokio::time::sleep(Duration::from_millis(250)).await;
    let response = reqwest::Client::new().get(format!("http://{address}/missing")).header("Host", "example.test").send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pool.total_inflight(), 0);
    let unknown = reqwest::Client::new().get(format!("http://{address}/missing")).header("Host", "unknown.test").send().await.unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
    pool.set_healthy(0.into(), true);
    let success = reqwest::Client::new().get(format!("http://{address}/stream")).header("Host", "example.test").send().await.unwrap();
    assert_eq!(success.status(), reqwest::StatusCode::OK);
    assert_eq!(success.text().await.unwrap(), "stream-body");
    backend.shutdown().await;
}
