//! End-to-end: a request-body transform plugin rewrites what the upstream
//! receives (with chunked upstream framing), and a response-header plugin
//! rewrites what the client sees, through the real Pingora service.

use axum::{body::Bytes, http::HeaderMap, routing::post, Router};
use bearust::config::{
    Algorithm, BackendConfig, Config, HealthCheckKind, PluginConfig, PoolConfig, RouteConfig,
    ServerConfig,
};
use bearust::plugin_runtime::PluginManager;
use bearust::proxy::{http_service, BearustProxy};
use bearust::runtime::{RuntimeSnapshot, RuntimeStore};
use pingora_core::server::{configuration::ServerConf, Server};
use std::{net::TcpListener, sync::Arc, time::Duration};

fn install(root: &std::path::Path, name: &str) {
    let source = std::path::Path::new("tests/fixtures/plugins").join(name);
    let target = root.join(name.replace('_', "-"));
    std::fs::create_dir_all(&target).unwrap();
    std::fs::copy(source.join("plugin.toml"), target.join("plugin.toml")).unwrap();
    let wat = std::fs::read_to_string(source.join(format!("{name}.wat"))).unwrap();
    std::fs::write(
        target.join(format!("{name}.wasm")),
        wat::parse_str(&wat).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts a process-wide Pingora server; run with cargo test --test proxy_body_transform -- --ignored"]
async fn request_body_and_response_header_transforms_through_pingora() {
    // Upstream echoes the body it received and how it was framed.
    let app = Router::new().route(
        "/echo",
        post(|headers: HeaderMap, body: Bytes| async move {
            let framing = headers
                .get("transfer-encoding")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_else(|| "none".into());
            ([("x-upstream-framing", framing)], body)
        }),
    );
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(upstream, app).await.unwrap() });

    let plugins = tempfile::tempdir().unwrap();
    install(plugins.path(), "transform_request_body_v2");
    install(plugins.path(), "transform_response_headers_v2");
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: plugins.path().to_path_buf(),
        max_output_bytes: 2 * 1024 * 1024,
        ..PluginConfig::default()
    });
    assert_eq!(manager.reload_from_disk().unwrap().failed, 0);

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
            request_timeout_seconds: 2,
            passive_health: false,
            http3: None,
            backends: vec![BackendConfig {
                address: upstream_addr,
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
            upstream_pool: "main".into(),
        }],
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
        streams: Vec::new(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    snapshot.pool("main").unwrap().set_healthy(0.into(), true);
    let runtime = Arc::new(RuntimeStore::new(snapshot));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut server = Server::new(None).unwrap();
    let conf = Arc::new(ServerConf::default());
    let mut service = http_service(
        BearustProxy::new(Arc::clone(&runtime)).with_plugin_manager(manager),
        &conf,
    );
    service.add_tcp(&address.to_string());
    server.add_service(service);
    server.bootstrap();
    std::thread::spawn(move || server.run_forever());
    tokio::time::sleep(Duration::from_millis(300)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/echo"))
        .header("Host", "example.test")
        .header("Content-Type", "text/plain")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["x-plugin"], "yes");
    // The header plugin replaced everything else (framing is restored).
    assert!(response.headers().get("x-upstream-framing").is_none());
    assert_eq!(response.text().await.unwrap(), "transformed");
}
