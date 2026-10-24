//! HTTP/3 (QUIC) client for upstream pools configured with `[http3]`.
//!
//! One QUIC connection is kept per backend address and reused across
//! requests (RFC 9114 asks clients not to open more than one per address);
//! a failed or closed connection is replaced on the next request. TLS is
//! always on: certificates are verified against the configured CA file or
//! the system roots, for `server_name`, unless `insecure_skip_verify`.

use crate::config::UpstreamHttp3Config;
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Debug, thiserror::Error)]
pub enum H3UpstreamError {
    #[error("invalid HTTP/3 upstream TLS configuration: {0}")]
    Config(String),
    #[error("HTTP/3 upstream connection failed: {0}")]
    Connect(String),
    #[error("HTTP/3 upstream request failed: {0}")]
    Request(String),
    #[error("HTTP/3 upstream timed out")]
    Timeout,
}

pub struct H3Upstream {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    server_name: String,
    connections: Mutex<HashMap<SocketAddr, SendRequest>>,
}

/// A response head plus a stream of body chunks.
pub struct H3Response {
    pub head: http::Response<()>,
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl H3Response {
    /// The next body chunk, or `None` at the end of the body.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, H3UpstreamError> {
        match self.stream.recv_data().await {
            Ok(Some(mut data)) => Ok(Some(data.copy_to_bytes(data.remaining()))),
            Ok(None) => Ok(None),
            Err(error) => Err(H3UpstreamError::Request(error.to_string())),
        }
    }
}

#[derive(Debug)]
struct NoVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl H3Upstream {
    pub fn new(config: &UpstreamHttp3Config) -> Result<Self, H3UpstreamError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| H3UpstreamError::Config(e.to_string()))?;
        let mut tls = if config.insecure_skip_verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match &config.ca_file {
                Some(path) => {
                    let pem = std::fs::read(path)
                        .map_err(|e| H3UpstreamError::Config(format!("{}: {e}", path.display())))?;
                    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                        let cert = cert.map_err(|e| H3UpstreamError::Config(e.to_string()))?;
                        roots
                            .add(cert)
                            .map_err(|e| H3UpstreamError::Config(e.to_string()))?;
                    }
                }
                None => {
                    for cert in rustls_native_certs::load_native_certs().certs {
                        let _ = roots.add(cert);
                    }
                }
            }
            if roots.is_empty() {
                return Err(H3UpstreamError::Config("no trusted CA certificates".into()));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| H3UpstreamError::Config(e.to_string()))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic));
        let endpoint = quinn::Endpoint::client("[::]:0".parse().expect("static address"))
            .or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().expect("static address")))
            .map_err(|e| H3UpstreamError::Config(e.to_string()))?;
        Ok(Self {
            endpoint,
            client_config,
            server_name: config.server_name.clone(),
            connections: Mutex::new(HashMap::new()),
        })
    }

    async fn connect(&self, backend: SocketAddr) -> Result<SendRequest, H3UpstreamError> {
        let connecting = self
            .endpoint
            .connect_with(self.client_config.clone(), backend, &self.server_name)
            .map_err(|e| H3UpstreamError::Connect(e.to_string()))?;
        let connection = connecting
            .await
            .map_err(|e| H3UpstreamError::Connect(e.to_string()))?;
        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| H3UpstreamError::Connect(e.to_string()))?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(send_request)
    }

    /// Send one request with a fully buffered body and return the response
    /// head and body stream. Retries once on a stale pooled connection.
    pub async fn send(
        &self,
        backend: SocketAddr,
        request: http::Request<()>,
        body: Bytes,
        timeout: Duration,
    ) -> Result<H3Response, H3UpstreamError> {
        tokio::time::timeout(timeout, async {
            let mut last_error = None;
            for attempt in 0..2 {
                let cached = self.connections.lock().await.get(&backend).cloned();
                let mut sender = match cached {
                    Some(sender) if attempt == 0 => sender,
                    _ => {
                        let sender = self.connect(backend).await?;
                        self.connections
                            .lock()
                            .await
                            .insert(backend, sender.clone());
                        sender
                    }
                };
                match Self::exchange(&mut sender, clone_head(&request), body.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(error) => {
                        self.connections.lock().await.remove(&backend);
                        last_error = Some(error);
                    }
                }
            }
            Err(last_error.unwrap_or(H3UpstreamError::Request("unknown".into())))
        })
        .await
        .map_err(|_| H3UpstreamError::Timeout)?
    }

    async fn exchange(
        sender: &mut SendRequest,
        request: http::Request<()>,
        body: Bytes,
    ) -> Result<H3Response, H3UpstreamError> {
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|e| H3UpstreamError::Request(e.to_string()))?;
        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| H3UpstreamError::Request(e.to_string()))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| H3UpstreamError::Request(e.to_string()))?;
        let head = stream
            .recv_response()
            .await
            .map_err(|e| H3UpstreamError::Request(e.to_string()))?;
        Ok(H3Response { head, stream })
    }
}

fn clone_head(request: &http::Request<()>) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone());
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder.body(()).expect("cloned from a valid request")
}

/// Hop-by-hop headers that HTTP/3 forbids (RFC 9114 section 4.2).
pub fn strip_connection_headers(headers: &mut http::HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
        "host",
    ] {
        headers.remove(name);
    }
}

/// Per-pool clients, built lazily from the pool's `[http3]` settings.
#[derive(Default)]
pub struct H3UpstreamRegistry {
    clients: std::sync::Mutex<HashMap<String, Arc<H3Upstream>>>,
}

impl H3UpstreamRegistry {
    pub fn client(
        &self,
        pool: &str,
        config: &UpstreamHttp3Config,
    ) -> Result<Arc<H3Upstream>, H3UpstreamError> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| H3UpstreamError::Config("registry poisoned".into()))?;
        // Keyed by settings too, so a reloaded config gets a fresh client.
        let key = format!("{pool}|{config:?}");
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        let client = Arc::new(H3Upstream::new(config)?);
        clients.insert(key, client.clone());
        Ok(client)
    }
}
