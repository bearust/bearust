use bearust::{
    config::{
        Algorithm, BackendConfig, Config, HealthCheckKind, PoolConfig, RouteConfig, RouteRateLimit,
        ServerConfig,
    },
    proxy::{http_service, BearustProxy},
    runtime::{RuntimeSnapshot, RuntimeStore},
};
use pingora_core::server::{configuration::ServerConf, Server};
use std::{net::TcpListener, sync::Arc, time::Duration};

mod support;

/// End-to-end harness for the Pingora service. It is ignored in normal unit runs because
/// Pingora's server owns a process-wide listener loop; run explicitly with `--ignored`.
#[tokio::test]
#[ignore = "starts a process-wide Pingora server; run with cargo test --test proxy_route_limits -- --ignored"]
async fn route_rate_limit_and_body_limit_are_enforced() {
    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "stream-body",
    )
    .await;
    let backend_addr = backend.address;
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
            name: "main".into(),
            algorithm: Algorithm::RoundRobin,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            passive_health: false,
            http3: None,
            backends: vec![BackendConfig {
                address: backend_addr,
                health_check: HealthCheckKind::Tcp,
                health_path: None,
                weight: 1,
            }],
        }],
        routes: vec![RouteConfig {
            rate_limit: Some(RouteRateLimit {
                requests_per_second: 1,
                burst: 2,
            }),
            max_body_bytes: Some(8),
            name: "default".into(),
            host: "example.test".into(),
            path_prefix: "/".into(),
            upstream_pool: "main".into(),
        }],
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
        streams: Vec::new(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    let pool = snapshot.pool("main").unwrap();
    pool.set_healthy(0.into(), true);
    let runtime = Arc::new(RuntimeStore::new(snapshot));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut server = Server::new(None).unwrap();
    let conf = Arc::new(ServerConf::default());
    let mut service = http_service(BearustProxy::new(Arc::clone(&runtime)), &conf);
    service.add_tcp(&address.to_string());
    server.add_service(service);
    server.bootstrap();
    std::thread::spawn(move || server.run_forever());
    tokio::time::sleep(Duration::from_millis(250)).await;
    let client = reqwest::Client::new();

    // Declared body over the limit is refused before reaching the backend.
    let too_large = client
        .post(format!("http://{address}/upload"))
        .header("Host", "example.test")
        .body("0123456789")
        .send()
        .await
        .unwrap();
    assert_eq!(too_large.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    // The 413 above took one token; one more fits the burst of 2.
    let ok = client
        .get(format!("http://{address}/"))
        .header("Host", "example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let limited = client
        .get(format!("http://{address}/"))
        .header("Host", "example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().get("retry-after").is_some());
    backend.shutdown().await;
}
