//! HTTP/3 (QUIC) listener, independent of Pingora's TCP/TLS listener.
//!
//! Reuses the same certificate/key files as the existing HTTP/1.1/HTTP/2
//! listener, and (from a later task) the same WAF/routing/load-balancing
//! logic `src/proxy.rs` already uses — but runs as a fully separate
//! listener stack, since Pingora has no HTTP/3 support to extend (verified
//! against `pingora-core` 0.8.1's own source and Cargo.toml: no `quic`/`h3`
//! feature, no QUIC dependency, no QUIC source file anywhere in the crate).

use crate::config::TlsConfig;
use crate::runtime::RuntimeStore;
use crate::waf_store::WafStore;
use bytes::Buf;
use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Http3Error {
    #[error("HTTP/3 certificate file is not readable")]
    Certificate(#[source] io::Error),
    #[error("HTTP/3 private key file is not readable or missing")]
    PrivateKey(#[source] io::Error),
    #[error("HTTP/3 TLS configuration is invalid")]
    InvalidTls,
    #[error("HTTP/3 UDP socket could not be bound")]
    Bind(#[source] io::Error),
}

/// Builds the `rustls::ServerConfig` `quinn` needs, from the same
/// cert/key PEM files the Pingora TLS listener already validates and
/// uses. ALPN is set to `h3` only -- this listener never negotiates
/// anything but HTTP/3.
///
/// Callers must have already called
/// `rustls::crypto::ring::default_provider().install_default().ok();`
/// once during process startup (see `src/cli.rs`) -- this function does
/// not call it itself, to avoid every call site racing to install a
/// provider; it is a documented process-wide precondition instead.
pub fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, Http3Error> {
    let certs = load_certs(&tls.cert_path)?;
    let key = load_key(&tls.key_path)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| Http3Error::InvalidTls)?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Http3Error> {
    let file = std::fs::File::open(path).map_err(Http3Error::Certificate)?;
    let mut reader = io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Http3Error::Certificate)
}

fn load_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>, Http3Error> {
    let file = std::fs::File::open(path).map_err(Http3Error::PrivateKey)?;
    let mut reader = io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(Http3Error::PrivateKey)?
        .ok_or_else(|| {
            Http3Error::PrivateKey(io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
        })
}

fn quinn_server_config(tls_config: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, Http3Error> {
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|_| Http3Error::InvalidTls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_tls)))
}

/// Runs the HTTP/3 listener until `shutdown` fires. Every request is
/// evaluated against the WAF rule engine (when `waf` is provided) before
/// receiving a fixed `200 ok` response -- upstream routing is added in a
/// later task. Bounded, graceful: `shutdown` firing stops accepting new
/// connections; in-flight connections are given until the endpoint is
/// dropped to finish (the caller in `src/cli.rs`, from a later task,
/// bounds this the same way it already bounds other spawned tasks'
/// shutdown).
pub async fn serve(
    bind: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    store: Arc<RuntimeStore>,
    waf: Option<Arc<WafStore>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Http3Error> {
    let server_config = quinn_server_config(tls_config)?;
    let endpoint = quinn::Endpoint::server(server_config, bind).map_err(Http3Error::Bind)?;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let waf = waf.clone();
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        handle_connection(conn, store, waf).await;
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn handle_connection(conn: quinn::Connection, store: Arc<RuntimeStore>, waf: Option<Arc<WafStore>>) {
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> =
        match h3::server::builder().build(h3_conn).await {
            Ok(conn) => conn,
            Err(_) => return,
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let Ok((req, stream)) = resolver.resolve_request().await else {
                    break;
                };
                let waf = waf.clone();
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    handle_request(req, stream, store, waf).await;
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

/// Maps a request's raw fields into the same `InspectionContext` shape
/// `src/proxy.rs`'s HTTP/1.1/HTTP/2 path builds (see its `InspectionContext {
/// ... }` construction around line 1048), so the same logical request
/// produces the same WAF verdict regardless of which listener handled it.
fn build_inspection_context(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> crate::waf::InspectionContext {
    crate::waf::InspectionContext {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers: headers.to_vec(),
        body,
    }
}

async fn handle_request<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, bytes::Bytes>,
    store: Arc<RuntimeStore>,
    waf: Option<Arc<WafStore>>,
) where
    S: h3::quic::BidiStream<bytes::Bytes>,
{
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    // Single-phase evaluation (buffer the whole body up to
    // MAX_INSPECTION_BODY_BYTES, then evaluate once): this task
    // deliberately does not replicate src/proxy.rs's two-phase
    // header-then-body optimization -- see this plan's Global Constraints.
    let mut body = Vec::new();
    while let Ok(Some(mut chunk)) = stream.recv_data().await {
        if body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES {
            break;
        }
        while chunk.has_remaining() && body.len() < crate::waf::MAX_INSPECTION_BODY_BYTES {
            let take = chunk
                .remaining()
                .min(crate::waf::MAX_INSPECTION_BODY_BYTES - body.len());
            body.extend_from_slice(&chunk.chunk()[..take]);
            chunk.advance(take);
        }
    }

    if let Some(waf) = &waf {
        let snapshot = waf.snapshot();
        let context = build_inspection_context(&method, &path, &query, &headers, body.clone());
        let evaluation = crate::waf::evaluate(&snapshot, &context);
        if evaluation.decision == crate::waf::WafDecision::Block {
            let resp = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let _ = stream
                .send_data(bytes::Bytes::from_static(b"Request blocked"))
                .await;
            let _ = stream.finish().await;
            return;
        }
    }

    // Not blocked (or WAF not configured): route and forward.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or_default();
    let snapshot = store.load();
    let Some((_route, pool)) = snapshot.route(authority, &path) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return;
    };
    let Some(lease) = pool.select(None) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return;
    };

    let target = format!(
        "http://{}{}",
        lease.address(),
        req.uri().path_and_query().map(|p| p.as_str()).unwrap_or(&path)
    );
    let client = reqwest::Client::new();
    let mut builder = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &target,
    );
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body.clone());
    }

    match builder.send().await {
        Ok(upstream_resp) => {
            let status = http::StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(http::StatusCode::BAD_GATEWAY);
            let resp = http::Response::builder()
                .status(status)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let mut body_stream = upstream_resp.bytes_stream();
            use futures_util::StreamExt as _;
            while let Some(chunk) = body_stream.next().await {
                let Ok(chunk) = chunk else { break };
                if stream.send_data(chunk).await.is_err() {
                    break;
                }
            }
            let _ = stream.finish().await;
        }
        Err(_) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn build_inspection_context_matches_the_http1_http2_paths_field_shape() {
        let headers = vec![("x-test".to_owned(), "1".to_owned())];
        let context =
            super::build_inspection_context("GET", "/hello", "q=1", &headers, b"body".to_vec());
        assert_eq!(
            context,
            crate::waf::InspectionContext {
                method: "GET".to_owned(),
                path: "/hello".to_owned(),
                query: "q=1".to_owned(),
                headers: vec![("x-test".to_owned(), "1".to_owned())],
                body: b"body".to_vec(),
            }
        );
    }
}
