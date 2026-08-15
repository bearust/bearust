use bearust::{
    analytics::{AnalyticsCollector, AnalyticsFilter},
    bot_challenge::ChallengeService,
    bot_protection::{BotConfig, BotMode, BotRule},
    bot_store::BotStore,
    config::{
        Algorithm, BackendConfig, Config, HealthCheckKind, PluginConfig, PoolConfig, RouteConfig,
        ServerConfig,
    },
    control_plane::{
        models::{WafAction, WafRule},
        repository,
    },
    http3,
    http3::{AnalyticsContext, BotContext, RateLimitContext},
    plugin_notify::NotificationSink,
    plugin_runtime::PluginManager,
    rate_limit::{RateLimitAction, RateLimitPolicy},
    rate_limit_store::{IpNetSet, RateLimiterStore},
    runtime::{RuntimeSnapshot, RuntimeStore},
    waf_store::WafStore,
};
use bytes::Buf;
use std::fs;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

mod support;

/// A minimal HTTP backend that counts every request it receives, for tests
/// that must assert the upstream was (or was not) contacted at all -- e.g.
/// C3's "an oversized body is rejected with 413 and the upstream receives
/// zero requests", and I7(b)'s strengthened WAF-block-reaches-zero-requests
/// assertion. Deliberately a small local helper (not added to
/// `tests/support/mod.rs`) since this task's scope is limited to
/// `tests/http3_listener.rs`.
struct CountingBackend {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl CountingBackend {
    fn request_count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn spawn_counting_backend(body: &'static str) -> CountingBackend {
    use axum::{extract::State, response::IntoResponse, routing::any, Router};

    let count = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    async fn handler(
        State((count, body)): State<(Arc<AtomicUsize>, &'static str)>,
    ) -> impl IntoResponse {
        count.fetch_add(1, Ordering::SeqCst);
        (axum::http::StatusCode::OK, body)
    }

    let app = Router::new()
        .fallback(any(handler))
        .with_state((count.clone(), body));
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    CountingBackend {
        address,
        count,
        shutdown: Some(tx),
    }
}

/// Builds a `WafStore` whose snapshot blocks any request whose path
/// contains `/blocked`, mirroring the exact construction pattern used by
/// `tests/proxy_waf.rs` (in-memory sqlite, migrate, insert a `WafRule`
/// with a JSON matcher, then `WafStore::load`) rather than inventing a
/// new one.
async fn waf_store_blocking_path(needle: &str) -> WafStore {
    let db = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&db).await.unwrap();
    let rule = WafRule {
        id: 0,
        name: "block-test-path".into(),
        source: "custom".into(),
        category: "custom".into(),
        severity: "high".into(),
        enabled: true,
        action: WafAction::Block,
        matcher_json: format!(r#"{{"field":"path","pattern":"{needle}"}}"#),
        created_at: String::new(),
        updated_at: String::new(),
    };
    repository::insert_waf_rule(&db, &rule).await.unwrap();
    WafStore::load(&db).await.unwrap()
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a `RuntimeStore` whose single "main" pool holds `backend_addr` as
/// its only backend, routed to by host `host` for any path -- mirrors the
/// `Config`/`RuntimeSnapshot::build` construction pattern used by
/// `tests/proxy_http.rs`'s
/// `local_pingora_service_routes_and_returns_503_without_healthy_backend`
/// test rather than inventing a new one. The backend is marked healthy
/// immediately (`RuntimeSnapshot::build` always starts backends unhealthy,
/// same as that test works around) since these tests exercise
/// `PoolState::select` succeeding, not health-check convergence.
fn runtime_store_routing_to(host: &str, backend_addr: SocketAddr) -> Arc<RuntimeStore> {
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
        },
        health: Default::default(),
        upstream_pools: vec![PoolConfig {
            name: "main".into(),
            algorithm: Algorithm::RoundRobin,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            backends: vec![BackendConfig {
                address: backend_addr,
                health_check: HealthCheckKind::Tcp,
                health_path: None,
            }],
        }],
        routes: vec![RouteConfig {
            name: "default".into(),
            host: host.into(),
            path_prefix: "/".into(),
            upstream_pool: "main".into(),
        }],
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    let pool = snapshot.pool("main").unwrap();
    pool.set_healthy(0.into(), true);
    Arc::new(RuntimeStore::new(snapshot))
}

/// Like `runtime_store_routing_to`, but the "main" pool holds two backends
/// (`first` at index 0, `second` at index 1) -- for the `balance.select`
/// test, whose fixture plugin always picks `backend_id: 0`.
fn runtime_store_routing_to_two_backends(
    host: &str,
    first: SocketAddr,
    second: SocketAddr,
) -> Arc<RuntimeStore> {
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
        },
        health: Default::default(),
        upstream_pools: vec![PoolConfig {
            name: "main".into(),
            algorithm: Algorithm::RoundRobin,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            backends: vec![
                BackendConfig {
                    address: first,
                    health_check: HealthCheckKind::Tcp,
                    health_path: None,
                },
                BackendConfig {
                    address: second,
                    health_check: HealthCheckKind::Tcp,
                    health_path: None,
                },
            ],
        }],
        routes: vec![RouteConfig {
            name: "default".into(),
            host: host.into(),
            path_prefix: "/".into(),
            upstream_pool: "main".into(),
        }],
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    let pool = snapshot.pool("main").unwrap();
    pool.set_healthy(0.into(), true);
    pool.set_healthy(1.into(), true);
    Arc::new(RuntimeStore::new(snapshot))
}

/// Builds an empty `RuntimeStore` (no pools, no routes) for tests where
/// routing/forwarding is never reached (e.g. the WAF blocks the request
/// first).
fn empty_runtime_store() -> Arc<RuntimeStore> {
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
        },
        health: Default::default(),
        upstream_pools: Vec::new(),
        routes: Vec::new(),
        rate_limit: Default::default(),
        prometheus: Default::default(),
        cluster: Default::default(),
        plugins: Default::default(),
    };
    let snapshot = RuntimeSnapshot::build(config, None).unwrap();
    Arc::new(RuntimeStore::new(snapshot))
}

fn self_signed_server_config() -> (
    quinn::ServerConfig,
    rustls_pki_types::CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
    (
        quinn::ServerConfig::with_crypto(Arc::new(quic_config)),
        cert_der,
    )
}

fn client_config(cert_der: rustls_pki_types::CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    quinn::ClientConfig::new(Arc::new(quic_config))
}

#[tokio::test]
async fn http3_listener_responds_to_a_real_h3_client() {
    install_crypto_provider();

    let (server_config, cert_der) = self_signed_server_config();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind).unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                // Mirrors http3::handle_connection's shape without
                // depending on its private visibility -- this test
                // exercises the same public building blocks
                // (h3_quinn::Connection, h3::server::builder) the
                // library function itself uses.
                let h3_conn = h3_quinn::Connection::new(conn);
                if let Ok(mut h3_conn) = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_conn)
                    .await
                {
                    // Loop on accept() (as http3::handle_connection does)
                    // rather than returning immediately after the first
                    // request: returning drops `conn`/`h3_conn`, and
                    // quinn::Connection's Drop sends an immediate
                    // CONNECTION_CLOSE, which raced ahead of the buffered
                    // response actually reaching the client in practice
                    // (reproduced: the client's `recv_response()` failed
                    // deterministically with
                    // `ConnectionError(Remote(ApplicationClose(H3_NO_ERROR)))`
                    // without this loop). Looping keeps the connection
                    // alive until the client closes it, after it has read
                    // the response.
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some(resolver)) => {
                                let Ok((_req, mut stream)) = resolver.resolve_request().await
                                else {
                                    break;
                                };
                                let resp = http::Response::builder()
                                    .status(http::StatusCode::OK)
                                    .body(())
                                    .unwrap();
                                let _ = stream.send_response(resp).await;
                                let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                                let _ = stream.finish().await;
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    });

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config(cert_der));

    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let quinn_conn = connecting.await.unwrap();
    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await.unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/hello")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"ok");
    drive.abort();
}

/// Builds an `rustls::ServerConfig` (h3 ALPN) plus the matching cert DER
/// clients need to trust it, for driving `http3::serve` directly (as
/// opposed to `self_signed_server_config`/`client_config` above, which
/// build a raw `quinn::ServerConfig` for tests that call
/// `h3::server::builder()` directly instead of the public `serve` fn).
fn serve_tls_config() -> (
    Arc<rustls::ServerConfig>,
    rustls_pki_types::CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    (Arc::new(tls_config), cert_der)
}

/// Reserves a free UDP port by binding it, reading back the OS-assigned
/// address, then releasing it -- mirrors this repo's existing
/// `TcpListener::bind("127.0.0.1:0")`-then-reuse pattern (see
/// `tests/proxy_http.rs`, `tests/shutdown.rs`, etc.) adapted to UDP,
/// since `http3::serve` binds its own `quinn::Endpoint` internally and
/// does not hand back the address it chose.
fn reserve_udp_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

async fn connect_h3_client(
    server_addr: SocketAddr,
    cert_der: rustls_pki_types::CertificateDer<'static>,
) -> (
    tokio::task::JoinHandle<()>,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) {
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config(cert_der));
    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let quinn_conn = connecting.await.unwrap();
    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, send_request) = h3::client::new(h3_conn).await.unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (drive, send_request)
}

#[tokio::test]
async fn http3_listener_blocks_a_request_the_waf_rule_engine_would_block() {
    install_crypto_provider();

    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let store = empty_runtime_store();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/blocked")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"Request blocked");
    drive.abort();
    server.abort();
}

#[tokio::test]
async fn http3_listener_allows_a_request_the_waf_rule_engine_would_allow() {
    install_crypto_provider();

    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "backend-body",
    )
    .await;
    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/allowed")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"backend-body");
    drive.abort();
    server.abort();
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_forwards_an_allowed_request_to_the_resolved_backend() {
    install_crypto_provider();

    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "resolved-backend-body",
    )
    .await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, store, Default::default(), shutdown_rx).await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    // The backend's own response header must survive to the H3 client --
    // axum sets this for a plain (StatusCode, &str) handler response.
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"resolved-backend-body");
    drive.abort();
    server.abort();
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_returns_404_for_an_unmatched_host() {
    install_crypto_provider();

    let store = empty_runtime_store();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, store, Default::default(), shutdown_rx).await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

    drive.abort();
    server.abort();
}

/// Headers captured from a single request, shared between the backend
/// handler and the test asserting on them.
type CapturedHeaders = Arc<std::sync::Mutex<Option<Vec<(String, String)>>>>;

/// A backend that captures the headers of the last request it received, for
/// C2's spoofing-defeat test (need to see exactly what reached upstream).
struct HeaderCapturingBackend {
    address: SocketAddr,
    captured: CapturedHeaders,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl HeaderCapturingBackend {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn spawn_header_capturing_backend() -> HeaderCapturingBackend {
    use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::any, Router};

    let captured: CapturedHeaders = Arc::new(std::sync::Mutex::new(None));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    async fn handler(
        State(captured): State<CapturedHeaders>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        let pairs = headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<Vec<_>>();
        *captured.lock().unwrap() = Some(pairs);
        (axum::http::StatusCode::OK, "captured")
    }

    let app = Router::new()
        .fallback(any(handler))
        .with_state(captured.clone());
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    HeaderCapturingBackend {
        address,
        captured,
        shutdown: Some(tx),
    }
}

/// C2 regression test: a client that sends a spoofed `X-Forwarded-For`
/// claiming an internal-looking address must not have it survive to the
/// upstream unchanged -- `X-Forwarded-For` must have the real QUIC peer
/// address appended as the final, authoritative hop. Also confirms `Host`
/// reaching the upstream is exactly the real `:authority` the client
/// connected with (this listener's `h3` client library itself refuses to
/// send a conflicting regular `host` header alongside `:authority` --
/// `send_request` fails outright with "Failed to build request headers" if
/// attempted -- so a compliant h3 client cannot even construct the
/// Host-header half of this spoofing attempt; that half of C2 is instead
/// covered directly by the `build_request_headers_prefers_authority_over_a_spoofed_host_header`
/// unit test in `src/http3.rs`, which exercises the server-side parsing
/// logic against a raw `http::Request` with both fields set, bypassing the
/// client library's validation the way a non-compliant/malicious client
/// could).
#[tokio::test]
async fn http3_listener_reasserts_host_and_rebuilds_x_forwarded_for_defeating_a_spoofing_client() {
    install_crypto_provider();

    let backend = spawn_header_capturing_backend().await;
    let store = runtime_store_routing_to("victim.example", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, store, Default::default(), shutdown_rx).await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://victim.example/anything")
        // Spoof attempt: claims to already be forwarded from an internal
        // address, hoping downstream IP-based logic trusts it.
        .header("x-forwarded-for", "10.0.0.1")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    drive.abort();
    server.abort();

    let captured = backend
        .captured
        .lock()
        .unwrap()
        .clone()
        .expect("backend must have received exactly one request");
    let host = captured
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone());
    assert_eq!(
        host.as_deref(),
        Some("victim.example"),
        "Host reaching the upstream must be exactly the real :authority -- got {host:?}"
    );
    let xff = captured
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, value)| value.clone())
        .expect("x-forwarded-for must be present");
    assert!(
        xff.starts_with("10.0.0.1, 127.0.0.1"),
        "XFF must keep the client's claimed chain but append the real peer address as the last, authoritative hop -- got {xff:?}"
    );
    let request_id = captured
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
        .map(|(_, value)| value.clone());
    assert!(
        request_id.is_some_and(|id| !id.is_empty()),
        "x-request-id must always be stamped"
    );
    backend.shutdown().await;
}

/// C3 regression test: a body larger than `waf::MAX_INSPECTION_BODY_BYTES`
/// must be rejected outright (413) rather than silently truncated and
/// forwarded -- and, critically, the upstream backend must never see any
/// part of an oversized request.
#[tokio::test]
async fn http3_listener_rejects_an_oversized_body_with_413_and_never_contacts_the_backend() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, store, Default::default(), shutdown_rx).await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("POST")
        .uri("https://localhost/upload")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    let oversized = vec![b'a'; bearust::waf::MAX_INSPECTION_BODY_BYTES + 4096];
    let _ = stream.send_data(bytes::Bytes::from(oversized)).await;
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::PAYLOAD_TOO_LARGE);

    drive.abort();
    server.abort();
    assert_eq!(
        backend.request_count(),
        0,
        "an oversized body must be rejected before the upstream is ever contacted"
    );
    backend.shutdown().await;
}

/// I7(a): a route that resolves to a healthy-marked backend nobody is
/// actually listening on must surface as 502, not hang or panic.
#[tokio::test]
async fn http3_listener_returns_502_when_the_upstream_connection_fails() {
    install_crypto_provider();

    // Reserve then immediately release a TCP port -- nothing listens on it,
    // so any connection attempt fails fast with connection-refused.
    let backend_addr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let store = runtime_store_routing_to("localhost", backend_addr);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, store, Default::default(), shutdown_rx).await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);

    drive.abort();
    server.abort();
}

/// I7(b), strengthened: a request the WAF blocks must never reach the
/// upstream backend, verified via a real backend with a request counter
/// (the pre-existing WAF-block test only proved this indirectly, by using
/// a `RuntimeStore` with no routes at all).
#[tokio::test]
async fn http3_listener_waf_block_never_reaches_the_backend() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/blocked")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

    drive.abort();
    server.abort();
    assert_eq!(
        backend.request_count(),
        0,
        "a WAF-blocked request must never reach the upstream backend"
    );
    backend.shutdown().await;
}

#[test]
fn build_rustls_server_config_reads_the_configured_cert_and_key() {
    // Exercises http3::build_rustls_server_config against a real,
    // temporary self-signed cert/key pair on disk (not the fixed test
    // fixtures used elsewhere in this repo, since those are for the
    // Pingora TLS listener's own tests) -- confirms the PEM-loading
    // path this task added works end to end.
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let tls = bearust::config::TlsConfig {
        cert_path,
        key_path,
    };
    let result = http3::build_rustls_server_config(&tls);
    assert!(result.is_ok(), "{:?}", result.err());
}

#[tokio::test]
async fn http3_listener_records_an_analytics_event_for_an_allowed_request() {
    install_crypto_provider();

    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "analytics-backend-body",
    )
    .await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let collector = Arc::new(AnalyticsCollector::default());
    let host_ids = Arc::new(std::collections::HashMap::from([(
        "localhost".to_string(),
        42i64,
    )]));
    let analytics = Arc::new(AnalyticsContext {
        collector: collector.clone(),
        host_ids,
        changed: None,
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                analytics: Some(analytics),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    while stream.recv_data().await.unwrap().is_some() {}

    drive.abort();
    server.abort();
    backend.shutdown().await;

    let summary = collector.summary(AnalyticsFilter {
        proxy_host_id: Some(42),
        ..Default::default()
    });
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.status_2xx, 1);
    assert_eq!(summary.waf_blocks, 0);
}

#[tokio::test]
async fn http3_listener_records_a_waf_block_analytics_event_with_zero_backend_requests() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let collector = Arc::new(AnalyticsCollector::default());
    let host_ids = Arc::new(std::collections::HashMap::from([(
        "localhost".to_string(),
        7i64,
    )]));
    let analytics = Arc::new(AnalyticsContext {
        collector: collector.clone(),
        host_ids,
        changed: None,
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                analytics: Some(analytics),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/blocked")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    while stream.recv_data().await.unwrap().is_some() {}

    drive.abort();
    server.abort();
    assert_eq!(backend.request_count(), 0);
    backend.shutdown().await;

    let summary = collector.summary(AnalyticsFilter {
        proxy_host_id: Some(7),
        ..Default::default()
    });
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.status_4xx, 1);
    assert_eq!(summary.waf_blocks, 1);
}

/// Builds a `RateLimiterStore` whose global policy has capacity `1` and the
/// minimum valid refill rate (`0.001`/s, per `rate_limit::MIN_REFILL_PER_SECOND`)
/// -- the first request in a test always succeeds (consumes the single
/// token), and a second request sent immediately after is deterministically
/// over the limit, since real elapsed time between two local H3 requests
/// never approaches the ~1000s it would take to refill one token.
fn rate_limiter_with_capacity_one(action: RateLimitAction) -> Arc<RateLimiterStore> {
    let store = RateLimiterStore::new(16, std::time::Duration::from_secs(60));
    store.set_policy(RateLimitPolicy {
        enabled: true,
        action,
        capacity: 1,
        refill_per_second: 0.001,
        ..RateLimitPolicy::default()
    });
    Arc::new(store)
}

#[tokio::test]
async fn http3_listener_blocks_a_rate_limited_request_in_block_mode() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let rate_limit = Arc::new(RateLimitContext {
        limiter: rate_limiter_with_capacity_one(RateLimitAction::Block),
        trusted_proxies: Arc::new(IpNetSet::new(Vec::<String>::new())),
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                rate_limit: Some(rate_limit),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;

    // First request consumes the single token and must succeed.
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/first")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    while stream.recv_data().await.unwrap().is_some() {}

    // Second request, sent immediately after, is over the limit.
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/second")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"Rate limit exceeded");

    drive.abort();
    server.abort();
    assert_eq!(
        backend.request_count(),
        1,
        "only the first, non-limited request should have reached the backend"
    );
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_allows_a_rate_limited_request_in_monitor_mode() {
    install_crypto_provider();

    let backend = spawn_counting_backend("still-served").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let rate_limit = Arc::new(RateLimitContext {
        limiter: rate_limiter_with_capacity_one(RateLimitAction::Monitor),
        trusted_proxies: Arc::new(IpNetSet::new(Vec::<String>::new())),
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                rate_limit: Some(rate_limit),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    for path in ["/first", "/second"] {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://localhost{path}"))
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        while stream.recv_data().await.unwrap().is_some() {}
    }

    drive.abort();
    server.abort();
    assert_eq!(
        backend.request_count(),
        2,
        "monitor mode must never block a request, even over the limit"
    );
    backend.shutdown().await;
}

/// Fixed test key for `ChallengeService`/`BotConfig::fingerprint_key`,
/// mirroring the exact string used by `tests/proxy_bot.rs`'s fixtures --
/// only needs to be consistent between the store and the service.
const BOT_TEST_FINGERPRINT_KEY: &[u8] = b"http3-listener-test-key";

/// Builds a `BotStore` whose single rule (`ua_missing`, weight 100,
/// threshold 1 -- mirroring `tests/proxy_bot.rs`'s fixture) fires for any
/// request missing a `User-Agent` header, which every H3 client in this
/// test file's `connect_h3_client` sends none of, in `mode`.
async fn bot_store_with_missing_ua_rule(mode: BotMode) -> BotStore {
    let db = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&db).await.unwrap();
    repository::update_bot_config(
        &db,
        &BotConfig {
            mode,
            threshold: 1,
            ttl_seconds: 300,
            fingerprint_key: BOT_TEST_FINGERPRINT_KEY.to_vec(),
        },
    )
    .await
    .unwrap();
    repository::insert_bot_rule(&db, &BotRule::signal("ua_missing", 100))
        .await
        .unwrap();
    BotStore::load(&db).await.unwrap()
}

#[tokio::test]
async fn http3_listener_blocks_a_bot_detected_request_in_block_mode() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let bot = Arc::new(BotContext {
        store: Arc::new(bot_store_with_missing_ua_rule(BotMode::Block).await),
        challenges: None,
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                bot: Some(bot),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"Request blocked");

    drive.abort();
    server.abort();
    assert_eq!(backend.request_count(), 0);
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_challenges_a_bot_detected_request_in_challenge_mode() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let bot = Arc::new(BotContext {
        store: Arc::new(bot_store_with_missing_ua_rule(BotMode::Challenge).await),
        challenges: Some(Arc::new(
            ChallengeService::from_key(BOT_TEST_FINGERPRINT_KEY.to_vec()).unwrap(),
        )),
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                bot: Some(bot),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["challenge_url"]
        .as_str()
        .unwrap()
        .starts_with("/bot-challenge?fingerprint_prefix="));

    drive.abort();
    server.abort();
    assert_eq!(backend.request_count(), 0);
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_allows_a_challenge_triggering_request_with_valid_clearance() {
    install_crypto_provider();

    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "cleared-backend-body",
    )
    .await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let bot_store = bot_store_with_missing_ua_rule(BotMode::Challenge).await;
    let challenges =
        Arc::new(ChallengeService::from_key(BOT_TEST_FINGERPRINT_KEY.to_vec()).unwrap());

    // Compute the same fingerprint the server will derive for this exact
    // request (no headers, method GET, path /anything) so a real clearance
    // token can be issued for it ahead of time, mirroring how a real client
    // would present a token obtained from a prior /bot-challenge round trip.
    let snapshot = bearust::bot_protection::compile_snapshot(
        BotConfig {
            mode: BotMode::Challenge,
            threshold: 1,
            ttl_seconds: 300,
            fingerprint_key: BOT_TEST_FINGERPRINT_KEY.to_vec(),
        },
        vec![BotRule::signal("ua_missing", 100)],
    )
    .unwrap();
    let inspection = bearust::bot_protection::BotInspectionContext::new(
        "GET",
        "/anything",
        vec![("host".to_string(), "localhost".to_string())],
    );
    let evaluation = bearust::bot_protection::evaluate(&snapshot, &inspection);
    let clearance = challenges
        .issue_clearance(&evaluation.fingerprint, bearust::bot_challenge::unix_now())
        .unwrap();

    let bot = Arc::new(BotContext {
        store: Arc::new(bot_store),
        challenges: Some(challenges),
    });
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                bot: Some(bot),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .header("cookie", format!("bearust_bot_clear={clearance}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"cleared-backend-body");

    drive.abort();
    server.abort();
    backend.shutdown().await;
}

/// Loads the checked-in `waf_detect_v2` fixture (always returns
/// `{"decision":"block","category":"custom_detector","score":10}`,
/// ignoring its input -- see `tests/fixtures/plugins/waf_detect_v2/README.md`)
/// into a fresh `PluginManager`, mirroring `src/proxy.rs`'s own
/// `waf_detector_manager` test helper.
fn waf_detect_plugin_manager() -> Arc<PluginManager> {
    let root = tempfile::tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager
}

/// Loads the checked-in `transform_request_v2` fixture (always returns the
/// fixed header list `[["x-transformed","yes"]]`, ignoring its input -- see
/// `tests/fixtures/plugins/transform_request_v2/README.md`).
fn transform_request_plugin_manager() -> Arc<PluginManager> {
    let root = tempfile::tempdir().unwrap();
    let plugin = root.path().join("transform-request-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_request_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_request_v2/transform_request_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager
}

/// Loads the checked-in `balance_select_v2` fixture (always returns
/// `{"backend_id":0}`, ignoring its input -- see
/// `tests/fixtures/plugins/balance_select_v2/README.md`).
fn balance_select_plugin_manager() -> Arc<PluginManager> {
    let root = tempfile::tempdir().unwrap();
    let plugin = root.path().join("balance-select-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/balance_select_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/balance_select_v2/balance_select_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("balance_select_v2.wasm"), &module).unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager
}

/// Loads the checked-in `notify_sink_v2` fixture (always returns status `0`,
/// ignoring its input -- see `tests/fixtures/plugins/notify_sink_v2/README.md`).
fn notify_sink_plugin_manager() -> Arc<PluginManager> {
    let root = tempfile::tempdir().unwrap();
    let plugin = root.path().join("notify-sink-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/notify_sink_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager
}

#[tokio::test]
async fn http3_listener_escalates_an_otherwise_allowed_request_via_waf_detect_plugin() {
    install_crypto_provider();

    let backend = spawn_counting_backend("should-never-be-seen").await;
    let store = runtime_store_routing_to("localhost", backend.address);
    // A fresh WafStore (migrated, no custom block rule) defaults to
    // monitor-only mode, so the built-in rule engine alone would allow
    // this ordinary request -- only the waf.detect plugin's fixed block
    // verdict should cause the 403 this test asserts.
    let db = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&db).await.unwrap();
    let waf = Arc::new(WafStore::load(&db).await.unwrap());
    let plugin_manager = waf_detect_plugin_manager();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                plugin_manager: Some(plugin_manager),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/harmless")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"Request blocked");

    drive.abort();
    server.abort();
    assert_eq!(backend.request_count(), 0);
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_applies_a_transform_request_plugin_while_preserving_forced_headers() {
    install_crypto_provider();

    let backend = spawn_header_capturing_backend().await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let plugin_manager = transform_request_plugin_manager();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                plugin_manager: Some(plugin_manager),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .header("x-original", "should-be-dropped")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    while stream.recv_data().await.unwrap().is_some() {}

    drive.abort();
    server.abort();

    let received = backend.captured.lock().unwrap().clone().unwrap();
    backend.shutdown().await;
    // The plugin's fixed output wholesale-replaces the header list with
    // only x-transformed -- proving the transform actually ran and its
    // output reached the upstream request.
    assert!(received.contains(&("x-transformed".to_string(), "yes".to_string())));
    assert!(!received.iter().any(|(name, _)| name == "x-original"));
    // Host must still be the trusted value, forced back on unconditionally
    // *after* the transform runs, exactly like Host/X-Forwarded-For/
    // X-Request-Id are in src/proxy.rs -- otherwise a transform plugin that
    // drops or spoofs Host would reach the upstream unchecked.
    assert_eq!(
        received
            .iter()
            .find(|(name, _)| name == "host")
            .map(|(_, value)| value.as_str()),
        Some("localhost")
    );
    assert!(received.iter().any(|(name, _)| name == "x-forwarded-for"));
    assert!(received.iter().any(|(name, _)| name == "x-request-id"));
}

#[tokio::test]
async fn http3_listener_uses_a_balance_select_plugins_chosen_backend() {
    install_crypto_provider();

    let chosen = spawn_counting_backend("chosen-backend").await;
    let other = spawn_counting_backend("other-backend").await;
    // Index 0 must be `chosen` for this test to actually exercise the
    // fixture's fixed `{"backend_id":0}` pick -- both are otherwise
    // interchangeable round-robin candidates.
    let store = runtime_store_routing_to_two_backends("localhost", chosen.address, other.address);
    let plugin_manager = balance_select_plugin_manager();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                plugin_manager: Some(plugin_manager),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    while stream.recv_data().await.unwrap().is_some() {}

    drive.abort();
    server.abort();
    assert_eq!(chosen.request_count(), 1);
    assert_eq!(other.request_count(), 0);
    chosen.shutdown().await;
    other.shutdown().await;
}

#[tokio::test]
async fn http3_listener_notifies_a_waf_block_sink_plugin() {
    install_crypto_provider();

    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let store = empty_runtime_store();
    let plugin_manager = notify_sink_plugin_manager();
    let plugin_notify = NotificationSink::spawn(Arc::clone(&plugin_manager));
    let metrics_manager = Arc::clone(&plugin_manager);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                waf: Some(waf),
                plugin_manager: Some(plugin_manager),
                plugin_notify: Some(plugin_notify),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/blocked")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    while stream.recv_data().await.unwrap().is_some() {}

    drive.abort();
    server.abort();

    // The notification worker runs off the request's own call stack (a
    // bounded channel + background task, matching src/proxy.rs's existing
    // notify.waf_block behavior), so poll its Prometheus-rendered metrics
    // rather than asserting immediately.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        if metrics_manager
            .metrics()
            .render_prometheus()
            .contains("bearust_plugins_notify_invocations_total 1")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "notify.waf_block sink was not invoked within 1s"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Loads the checked-in `transform_response_v2` fixture (always returns the
/// fixed body `hello`, ignoring its input -- see
/// `tests/fixtures/plugins/transform_response_v2/README.md`). The host
/// ceiling (`PluginConfig::max_output_bytes`) is raised to 2 MiB, mirroring
/// `src/proxy.rs`'s own `transform_response_manager` test helper -- the
/// fixture's declared `max_output_bytes` (1.5 MiB, per its `plugin.toml`)
/// exceeds the default 64 KiB ceiling.
fn transform_response_plugin_manager() -> Arc<PluginManager> {
    let root = tempfile::tempdir().unwrap();
    let plugin = root.path().join("transform-response-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_response_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_response_v2/transform_response_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        max_output_bytes: 2 * 1024 * 1024,
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager
}

// transform.response uses tokio::task::block_in_place internally
// (src/proxy.rs's apply_transform_response_plugin), which panics on a
// current-thread runtime -- the default #[tokio::test] flavor. Matches
// src/proxy.rs's own a_successful_response_transform_replaces_the_body
// test, and the real multi-thread runtime bearust serve always runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_listener_transforms_an_eligible_response_body() {
    install_crypto_provider();

    let backend = support::spawn_http_backend(
        Arc::new(std::sync::atomic::AtomicU16::new(200)),
        "original-backend-body",
    )
    .await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let plugin_manager = transform_response_plugin_manager();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                plugin_manager: Some(plugin_manager),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    // The stale upstream content-length (22 bytes, for
    // "original-backend-body") must not survive the transform to a
    // different-length body.
    assert!(resp.headers().get("content-length").is_none());

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"hello");

    drive.abort();
    server.abort();
    backend.shutdown().await;
}

#[tokio::test]
async fn http3_listener_fails_open_and_streams_unmodified_for_an_oversized_response() {
    install_crypto_provider();

    // One byte past RESPONSE_BODY_TRANSFORM_CAP_BYTES (1 MiB), so buffering
    // aborts partway through and the fail-open path is exercised.
    let large_body: &'static str = Box::leak(
        vec![b'x'; 1024 * 1024 + 1]
            .into_iter()
            .map(|b| b as char)
            .collect::<String>()
            .into_boxed_str(),
    );
    let backend =
        support::spawn_http_backend(Arc::new(std::sync::atomic::AtomicU16::new(200)), large_body)
            .await;
    let store = runtime_store_routing_to("localhost", backend.address);
    let plugin_manager = transform_response_plugin_manager();
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(
            bind,
            tls_config,
            store,
            http3::Http3Options {
                plugin_manager: Some(plugin_manager),
                ..Default::default()
            },
            shutdown_rx,
        )
        .await;
    });

    let (drive, mut send_request) = connect_h3_client(bind, cert_der).await;
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/anything")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    // Fail-open: the original, untransformed body reaches the client in
    // full -- not the fixture's fixed "hello" output, and not truncated.
    assert_eq!(body.len(), large_body.len());
    assert_eq!(body, large_body.as_bytes());

    drive.abort();
    server.abort();
    backend.shutdown().await;
}
