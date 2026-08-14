//! HTTP/3 (QUIC) listener, independent of Pingora's TCP/TLS listener.
//!
//! Reuses the same certificate/key files as the existing HTTP/1.1/HTTP/2
//! listener, and (from a later task) the same WAF/routing/load-balancing
//! logic `src/proxy.rs` already uses — but runs as a fully separate
//! listener stack, since Pingora has no HTTP/3 support to extend (verified
//! against `pingora-core` 0.8.1's own source and Cargo.toml: no `quic`/`h3`
//! feature, no QUIC dependency, no QUIC source file anywhere in the crate).

use crate::config::TlsConfig;
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

/// Runs the HTTP/3 listener until `shutdown` fires. Every request
/// currently receives a fixed `200 ok` response -- WAF evaluation and
/// upstream routing are added in later tasks. Bounded, graceful:
/// `shutdown` firing stops accepting new connections; in-flight
/// connections are given until the endpoint is dropped to finish (the
/// caller in `src/cli.rs`, from a later task, bounds this the same way
/// it already bounds other spawned tasks' shutdown).
pub async fn serve(
    bind: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Http3Error> {
    let server_config = quinn_server_config(tls_config)?;
    let endpoint = quinn::Endpoint::server(server_config, bind).map_err(Http3Error::Bind)?;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        handle_connection(conn).await;
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

async fn handle_connection(conn: quinn::Connection) {
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> =
        match h3::server::builder().build(h3_conn).await {
            Ok(conn) => conn,
            Err(_) => return,
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let Ok((_req, mut stream)) = resolver.resolve_request().await else {
                    break;
                };
                tokio::spawn(async move {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(())
                        .expect("static response head is always valid");
                    let _ = stream.send_response(resp).await;
                    let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                    let _ = stream.finish().await;
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}
