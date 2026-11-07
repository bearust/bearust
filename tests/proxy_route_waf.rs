use bearust::{
    config::{
        Algorithm, BackendConfig, Config, HealthCheckKind, PoolConfig, RouteConfig, RouteWafPolicy,
        ServerConfig,
    },
    control_plane::models::WafMode,
    proxy::{http_service, BearustProxy},
    runtime::{RuntimeSnapshot, RuntimeStore},
};
use pingora_core::server::{configuration::ServerConf, Server};
use std::{net::TcpListener, sync::Arc, time::Duration};

mod support;

fn route(name: &str, host: &str, mode: Option<WafMode>) -> RouteConfig {
    RouteConfig {
        name: name.into(),
        host: host.into(),
        path_prefix: "/".into(),
        upstream_pool: "main".into(),
        rate_limit: None,
        max_body_bytes: None,
        paused: false,
        waf: mode.map(|mode| RouteWafPolicy {
            mode,
            builtins: vec!["sqli".into(), "xss".into()],
            crs: None,
            rules: Vec::new(),
        }),
    }
}

/// End-to-end harness for the Pingora service. It is ignored in normal unit runs because
/// Pingora's server owns a process-wide listener loop; run explicitly with `--ignored`.
#[tokio::test]
#[ignore = "starts a process-wide Pingora server; run with cargo test --test proxy_route_waf -- --ignored"]
async fn route_waf_policies_are_isolated_per_tenant() {
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
        routes: vec![
            route("blocking", "block.test", Some(WafMode::Block)),
            route("monitoring", "monitor.test", Some(WafMode::MonitorOnly)),
            route("standalone", "plain.test", None),
        ],
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
    // No node-wide WafStore: route policies must work on their own.
    let mut service = http_service(BearustProxy::new(Arc::clone(&runtime)), &conf);
    service.add_tcp(&address.to_string());
    server.add_service(service);
    server.bootstrap();
    std::thread::spawn(move || server.run_forever());
    tokio::time::sleep(Duration::from_millis(250)).await;
    let client = reqwest::Client::new();
    let attack = "/search?q=1%20union%20select%20password%20from%20users";
    let status = |host: &'static str, body: Option<&'static str>| {
        let client = client.clone();
        async move {
            let request = match body {
                Some(body) => client.post(format!("http://{address}/submit")).body(body),
                None => client.get(format!("http://{address}{attack}")),
            };
            request.header("Host", host).send().await.unwrap().status()
        }
    };

    // The same attack: blocked by the tenant in block mode, only logged by
    // the tenant in monitor mode, untouched on a route without a policy.
    assert_eq!(
        status("block.test", None).await,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(status("monitor.test", None).await, reqwest::StatusCode::OK);
    assert_eq!(status("plain.test", None).await, reqwest::StatusCode::OK);

    // Body-only attacks follow the same per-route policy.
    let xss = "comment=<script>alert(1)</script>";
    assert_eq!(
        status("block.test", Some(xss)).await,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        status("monitor.test", Some(xss)).await,
        reqwest::StatusCode::OK
    );
}
