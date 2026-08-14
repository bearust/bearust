use bearust::{
    control_plane::{
        models::{WafAction, WafRule},
        repository,
    },
    http3,
    waf_store::WafStore,
};
use bytes::Buf;
use std::net::SocketAddr;
use std::sync::Arc;

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

fn self_signed_server_config() -> (quinn::ServerConfig, rustls_pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
        rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
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
    let quic_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
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
                if let Ok(mut h3_conn) =
                    h3::server::builder().build::<_, bytes::Bytes>(h3_conn).await
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
fn serve_tls_config() -> (Arc<rustls::ServerConfig>, rustls_pki_types::CertificateDer<'static>) {
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
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, Some(waf), shutdown_rx).await;
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

    let waf = Arc::new(waf_store_blocking_path("/blocked").await);
    let (tls_config, cert_der) = serve_tls_config();
    let bind = reserve_udp_addr();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let _ = http3::serve(bind, tls_config, Some(waf), shutdown_rx).await;
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
    assert_eq!(body, b"ok");
    drive.abort();
    server.abort();
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
