use bearust::{
    analytics::{AnalyticsCollector, AnalyticsFilter},
    config::{
        Algorithm, BackendConfig, Config, HealthCheckKind, PoolConfig, RouteConfig, ServerConfig,
    },
    control_plane::{
        models::{WafAction, WafRule},
        repository,
    },
    http3,
    http3::AnalyticsContext,
    runtime::{RuntimeSnapshot, RuntimeStore},
    waf_store::WafStore,
};
use bytes::Buf;
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
        let _ = http3::serve(bind, tls_config, store, Some(waf), None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, Some(waf), None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, Some(waf), None, shutdown_rx).await;
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
        let _ = http3::serve(bind, tls_config, store, None, Some(analytics), shutdown_rx).await;
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
            Some(waf),
            Some(analytics),
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
