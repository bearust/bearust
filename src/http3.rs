//! HTTP/3 (QUIC) listener, independent of Pingora's TCP/TLS listener.
//!
//! Reuses the same certificate/key files as the existing HTTP/1.1/HTTP/2
//! listener, and (from a later task) the same WAF/routing/load-balancing
//! logic `src/proxy.rs` already uses — but runs as a fully separate
//! listener stack, since Pingora has no HTTP/3 support to extend (verified
//! against `pingora-core` 0.8.1's own source and Cargo.toml: no `quic`/`h3`
//! feature, no QUIC dependency, no QUIC source file anywhere in the crate).

use crate::analytics::AnalyticsCollector;
use crate::config::TlsConfig;
use crate::observability::validated_request_id;
use crate::rate_limit::{Decision as RateLimitDecision, RateLimitAction, RateLimitKey};
use crate::rate_limit_store::{client_ip, IpNetSet, RateLimiterStore};
use crate::runtime::RuntimeStore;
use crate::waf_store::WafStore;
use bytes::Buf;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
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
    #[error("HTTP/3 upstream HTTP client could not be constructed")]
    HttpClient(#[source] reqwest::Error),
}

/// Request timeout applied to every upstream `reqwest` request the H3
/// listener makes. There is no single global constant for this in the
/// codebase -- `PoolConfig::request_timeout_seconds` is configured per
/// upstream pool (see `src/config/mod.rs`) and threaded into Pingora's own
/// peer options in `src/proxy.rs` -- so this picks a value consistent with
/// that config's typical default (30s, see e.g. the fixture pools in
/// `src/proxy.rs`'s tests) rather than inventing an unrelated number.
const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Hop-by-hop headers (RFC 9110 §7.6.1) that must never be forwarded
/// verbatim by a proxy -- they describe the semantics of one specific
/// connection (this H3 client<->listener leg), not the end-to-end request,
/// and blindly copying them to the upstream `reqwest` connection is
/// incorrect (e.g. a client-supplied `Connection`/`Upgrade` could attempt to
/// influence the listener<->upstream leg, which is plain HTTP/1.1 over
/// `reqwest` and shares none of the H3 stream's framing).
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
];

/// Bundles what's needed to record a completion event for an H3 request,
/// mirroring `BeaRustProxy::record_completion`'s dependencies
/// (`src/proxy.rs`) without requiring any Pingora type: `host_ids` maps a
/// normalized proxy-host name to its analytics id (built once at startup,
/// same as `BeaRustProxy::analytics_host_ids`), and `changed` is the
/// realtime-dashboard notifier, invoked after every recorded event.
pub struct AnalyticsContext {
    pub collector: Arc<AnalyticsCollector>,
    pub host_ids: Arc<HashMap<String, i64>>,
    pub changed: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Bundles what's needed to apply rate limiting to an H3 request, mirroring
/// `BeaRustProxy`'s `rate_limiter`/`trusted_proxies` fields (`src/proxy.rs`)
/// without requiring any Pingora type.
pub struct RateLimitContext {
    pub limiter: Arc<RateLimiterStore>,
    pub trusted_proxies: Arc<IpNetSet>,
}

/// Everything `handle_connection`/`handle_request` need that's invariant
/// across every connection and request the listener handles -- bundled into
/// one `Arc` (built once in `serve`) so it can be cheaply cloned per
/// connection/request with a single clone instead of one per field.
struct HandlerState {
    store: Arc<RuntimeStore>,
    waf: Option<Arc<WafStore>>,
    client: Arc<reqwest::Client>,
    analytics: Option<Arc<AnalyticsContext>>,
    rate_limit: Option<Arc<RateLimitContext>>,
}

/// Records one completion event, reusing `src/proxy.rs`'s pure
/// `completion_event`/`analytics_security_counters` helpers (they take no
/// Pingora type, so they're directly callable here). `host` is looked up
/// against `AnalyticsContext::host_ids` to find the proxy host id -- `None`
/// or an unmapped host falls back to id `0`, matching
/// `BeaRustProxy::record_completion`'s behavior when a request never
/// resolved a route. `bot`/`bot_challenge` are always `false` here: neither
/// hook exists on the H3 path yet (see the Phase 15 PRD status for the
/// current scope). A `None` `analytics` context (analytics disabled) is a
/// no-op.
fn record_analytics_event(
    analytics: &Option<Arc<AnalyticsContext>>,
    host: Option<&str>,
    status: u16,
    start: Instant,
    waf_blocked: bool,
    rate_limited: bool,
) {
    let Some(analytics) = analytics else { return };
    let proxy_host_id = host
        .and_then(|host| analytics.host_ids.get(host).copied())
        .unwrap_or(0);
    let security =
        crate::proxy::analytics_security_counters(waf_blocked, false, false, rate_limited);
    analytics.collector.record(crate::proxy::completion_event(
        proxy_host_id,
        status,
        start.elapsed().as_millis() as u64,
        security,
    ));
    if let Some(changed) = &analytics.changed {
        changed();
    }
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
pub fn build_rustls_server_config(
    tls: &TlsConfig,
) -> Result<Arc<rustls::ServerConfig>, Http3Error> {
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
            Http3Error::PrivateKey(io::Error::new(
                io::ErrorKind::InvalidData,
                "no private key found",
            ))
        })
}

fn quinn_server_config(
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, Http3Error> {
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|_| Http3Error::InvalidTls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_tls)))
}

/// Runs the HTTP/3 listener until `shutdown` fires. Every request is
/// evaluated against the WAF rule engine (when `waf` is provided), routed
/// and load-balanced the same way the HTTP/1.1/HTTP/2 path is, and
/// forwarded upstream. Bounded, graceful: `shutdown` firing stops accepting
/// new connections, then `endpoint.wait_idle()` gives already-accepted
/// connections a chance to finish their in-flight streams before the
/// endpoint is hard-closed. The caller (`serve_proxy` in `src/cli.rs`)
/// bounds the whole of this function's execution by wrapping the task join
/// in `tokio::time::timeout(graceful_shutdown_seconds)`, so a connection
/// that never goes idle cannot hang shutdown forever -- it just stops being
/// awaited once the timeout elapses.
pub async fn serve(
    bind: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    store: Arc<RuntimeStore>,
    waf: Option<Arc<WafStore>>,
    analytics: Option<Arc<AnalyticsContext>>,
    rate_limit: Option<Arc<RateLimitContext>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Http3Error> {
    let server_config = quinn_server_config(tls_config)?;
    let endpoint = quinn::Endpoint::server(server_config, bind).map_err(Http3Error::Bind)?;
    let client = reqwest::Client::builder()
        .timeout(UPSTREAM_REQUEST_TIMEOUT)
        .build()
        .map_err(Http3Error::HttpClient)?;
    let state = Arc::new(HandlerState {
        store,
        waf,
        client: Arc::new(client),
        analytics,
        rate_limit,
    });

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let state = Arc::clone(&state);
                // NOTE (known gap, not fixed here): there is no bound on the
                // number of concurrent connections or, within a connection,
                // concurrent request streams -- every accepted connection and
                // every resolved request is spawned unconditionally. Admission
                // control / concurrency limits for this listener are left as
                // future work; this comment documents the gap rather than
                // attempting to fix it, since doing so is out of this task's
                // scope.
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        handle_connection(conn, state).await;
                    }
                });
            }
            result = shutdown.changed() => {
                match result {
                    Ok(()) => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                    // The `watch::Sender` was dropped without ever sending a
                    // final `true` -- treat that the same as an explicit
                    // shutdown signal instead of looping on an `Err` forever.
                    Err(_) => break,
                }
            }
        }
    }
    endpoint.wait_idle().await;
    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn handle_connection(conn: quinn::Connection, state: Arc<HandlerState>) {
    // The real QUIC peer address -- never client-suppliable, unlike any
    // header -- used for X-Forwarded-For attribution (see C2 in the review
    // this module was hardened against).
    let remote_addr = conn.remote_address();
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
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_request(req, stream, state, remote_addr).await;
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

/// Derives the trusted `Host` value for a request. Unlike HTTP/1.1, where
/// `Host` is an ordinary header, HTTP/3 carries request authority in the
/// `:authority` pseudo-header, which the `http`/`h3` crates surface via
/// `req.uri().authority()` rather than as a regular header entry --
/// `req.headers()` will *not* contain a `host` entry for a normal H3
/// request. `:authority` is preferred here (it is the protocol-level source
/// of truth); an explicit `host` regular header is only consulted as a
/// fallback for the rare case a request has no authority at all, mirroring
/// how `src/proxy.rs`'s HTTP/1.1 path has exactly one source (`Host`) to
/// trust. Preferring `:authority` also means an attacker-supplied ordinary
/// `host` header sent alongside a legitimate `:authority` can never win.
fn downstream_host(req: &http::Request<()>) -> Option<String> {
    req.uri()
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}

/// Builds the header list used for both WAF inspection and upstream
/// forwarding: every regular header the client sent, with `host` always
/// forced to the trusted `downstream_host` value (removed entirely if there
/// is none) -- never a client-suppliable value. This is what closes C1 (WAF
/// rules matching on `host` previously never saw an HTTP/3 request's
/// authority at all) and half of C2 (a spoofed `host` regular header can
/// never reach the upstream, since it is unconditionally replaced here
/// rather than merely filled in when absent).
fn build_request_headers(
    req: &http::Request<()>,
    downstream_host: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    if let Some(host) = downstream_host {
        headers.push(("host".to_owned(), host.to_owned()));
    }
    headers
}

/// Replaces every existing occurrence of `name` (case-insensitively) with a
/// single entry holding `value`.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value));
}

fn strip_hop_by_hop_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !HOP_BY_HOP_HEADERS
            .iter()
            .any(|hop| name.eq_ignore_ascii_case(hop))
    });
}

/// Reimplementation of `observability::append_forwarded_for`'s logic
/// against the plain `Vec<(String, String)>` header representation this
/// module uses (that function operates on a Pingora `RequestHeader`, which
/// is not reusable here). Appends the *real* QUIC peer address -- never a
/// client-suppliable value -- to whatever `X-Forwarded-For` chain the
/// client already presented, closing the other half of C2 (a spoofed
/// `X-Forwarded-For` can extend the chain it's already in, but can never
/// impersonate the final, real hop).
fn append_forwarded_for(headers: &mut Vec<(String, String)>, client_addr: SocketAddr) {
    let client_ip = client_addr.ip().to_string();
    let existing = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, value)| value.clone());
    let value = match existing {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip,
    };
    set_header(headers, "x-forwarded-for", value);
    // This listener never negotiates anything but HTTP/3 over TLS (see
    // `build_rustls_server_config`'s ALPN restriction), so unlike
    // `observability::append_forwarded_for` (which hardcodes "http" for a
    // listener that may or may not be TLS-terminated), "https" is always
    // correct here.
    set_header(headers, "x-forwarded-proto", "https".to_owned());
}

async fn handle_request<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, bytes::Bytes>,
    state: Arc<HandlerState>,
    remote_addr: SocketAddr,
) where
    S: h3::quic::BidiStream<bytes::Bytes>,
{
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or_default().to_owned();
    let downstream_host = downstream_host(&req);
    let headers = build_request_headers(&req, downstream_host.as_deref());
    let request_id = validated_request_id(
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
            .map(|(_, value)| value.as_bytes()),
    );

    // Single-phase evaluation (buffer the whole body up to
    // MAX_INSPECTION_BODY_BYTES, then evaluate once): this task
    // deliberately does not replicate src/proxy.rs's two-phase
    // header-then-body optimization -- see this plan's Global Constraints.
    //
    // Bodies larger than the cap are rejected outright (413) rather than
    // silently truncated: forwarding a truncated buffer upstream while the
    // client's original (larger) `content-length` header traveled along
    // unmodified would corrupt the request framing at the upstream. This
    // loop stops reading as soon as it can prove there is more data than
    // fits in the cap, so an oversized body is never buffered in full.
    let mut body = Vec::new();
    let mut oversized = false;
    'read: while let Ok(Some(mut chunk)) = stream.recv_data().await {
        while chunk.has_remaining() {
            if body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES {
                oversized = true;
                break 'read;
            }
            let take = chunk
                .remaining()
                .min(crate::waf::MAX_INSPECTION_BODY_BYTES - body.len());
            body.extend_from_slice(&chunk.chunk()[..take]);
            chunk.advance(take);
        }
    }
    if oversized {
        let resp = http::Response::builder()
            .status(http::StatusCode::PAYLOAD_TOO_LARGE)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream
            .send_data(bytes::Bytes::from_static(b"Payload Too Large"))
            .await;
        let _ = stream.finish().await;
        record_analytics_event(
            &state.analytics,
            downstream_host.as_deref(),
            413,
            start,
            false,
            false,
        );
        return;
    }

    if let Some(waf) = &state.waf {
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
            record_analytics_event(
                &state.analytics,
                downstream_host.as_deref(),
                403,
                start,
                true,
                false,
            );
            return;
        }
    }

    // Not blocked (or WAF not configured): route and forward.
    let authority = downstream_host.as_deref().unwrap_or_default();
    let snapshot = state.store.load();
    let Some((route, pool)) = snapshot.route(authority, &path) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        record_analytics_event(
            &state.analytics,
            downstream_host.as_deref(),
            404,
            start,
            false,
            false,
        );
        return;
    };

    // Rate limiting, mirroring src/proxy.rs's placement: after the WAF has
    // already passed and a route has resolved, before backend selection.
    // `client_ip` and `route_key` are reused directly from src/proxy.rs and
    // src/rate_limit_store.rs -- neither takes a Pingora type (`client_ip`
    // already expects the same `http::HeaderMap` type `req.headers()` is
    // here).
    if let Some(rate_limit) = &state.rate_limit {
        let ip = client_ip(remote_addr.ip(), req.headers(), &rate_limit.trusted_proxies);
        let host_id = crate::proxy::route_key(route);
        let policy = rate_limit.limiter.host_policy(host_id);
        let decision = rate_limit.limiter.evaluate(
            RateLimitKey {
                proxy_host_id: host_id,
                client_ip: ip,
            },
            &policy,
            Instant::now(),
        );
        if let RateLimitDecision::Limited { .. } = decision {
            crate::proxy::emit_rate_limit_telemetry(&request_id, &decision, policy.action);
            if policy.action == RateLimitAction::Block {
                let retry_after = match decision {
                    RateLimitDecision::Limited { retry_after, .. } => {
                        retry_after.as_secs().clamp(1, 3_600)
                    }
                    RateLimitDecision::Allowed { .. } => 1,
                };
                let resp = http::Response::builder()
                    .status(http::StatusCode::TOO_MANY_REQUESTS)
                    .header("retry-after", retry_after.to_string())
                    .header("cache-control", "no-store")
                    .body(())
                    .expect("static response head is always valid");
                let _ = stream.send_response(resp).await;
                let _ = stream
                    .send_data(bytes::Bytes::from_static(b"Rate limit exceeded"))
                    .await;
                let _ = stream.finish().await;
                record_analytics_event(
                    &state.analytics,
                    Some(route.host.as_str()),
                    429,
                    start,
                    false,
                    true,
                );
                return;
            }
        }
    }

    let Some(lease) = pool.select(None) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        record_analytics_event(
            &state.analytics,
            Some(route.host.as_str()),
            502,
            start,
            false,
            false,
        );
        return;
    };

    let target = format!(
        "http://{}{}",
        lease.address(),
        req.uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or(&path)
    );

    // Never forward client headers verbatim: strip hop-by-hop headers (I4),
    // drop the client's own `content-length` (its buffered body is what
    // will actually be sent -- `reqwest` computes the correct length itself
    // from the body it is given, so an unmodified, possibly-mismatched
    // client value must not travel along), rebuild `X-Forwarded-For` from
    // the real peer address (C2), and stamp a validated `X-Request-Id`.
    // `host` was already forced to the trusted value by
    // `build_request_headers` above.
    let mut outgoing_headers = headers.clone();
    strip_hop_by_hop_headers(&mut outgoing_headers);
    outgoing_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
    append_forwarded_for(&mut outgoing_headers, remote_addr);
    set_header(&mut outgoing_headers, "x-request-id", request_id);

    let mut builder = state.client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &target,
    );
    for (name, value) in &outgoing_headers {
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
            record_analytics_event(
                &state.analytics,
                Some(route.host.as_str()),
                status.as_u16(),
                start,
                false,
                false,
            );
        }
        Err(_) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            record_analytics_event(
                &state.analytics,
                Some(route.host.as_str()),
                502,
                start,
                false,
                false,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// C1 regression test: a well-formed HTTP/3 request carries its
    /// authority in `:authority` (surfaced via `req.uri().authority()`),
    /// never as a `host` regular header. Confirms `downstream_host` reads
    /// it, and that `build_request_headers` -- the function that feeds both
    /// `build_inspection_context` and upstream forwarding -- actually
    /// inserts it as `host`, so a WAF rule matching on `host` sees the same
    /// value it would for an equivalent HTTP/1.1 request's real `Host`
    /// header.
    #[test]
    fn build_request_headers_derives_host_from_authority_when_no_host_header_is_present() {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .body(())
            .unwrap();

        assert_eq!(downstream_host(&req).as_deref(), Some("example.com"));

        let headers = build_request_headers(&req, downstream_host(&req).as_deref());
        assert_eq!(headers, vec![("host".to_owned(), "example.com".to_owned())]);
    }

    /// A request with no authority at all falls back to an explicit `host`
    /// regular header, if the client sent one.
    #[test]
    fn build_request_headers_falls_back_to_an_explicit_host_header_without_authority() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/path")
            .header("host", "fallback.example")
            .body(())
            .unwrap();

        assert_eq!(downstream_host(&req).as_deref(), Some("fallback.example"));
        let headers = build_request_headers(&req, downstream_host(&req).as_deref());
        assert_eq!(
            headers,
            vec![("host".to_owned(), "fallback.example".to_owned())]
        );
    }

    /// C1/C2 spoofing regression: a client that sends both a legitimate
    /// `:authority` *and* an attacker-controlled `host` regular header must
    /// never have the regular header win -- `:authority` is the
    /// protocol-level source of truth and always wins.
    #[test]
    fn build_request_headers_prefers_authority_over_a_spoofed_host_header() {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://real.example/path")
            .header("host", "attacker.example")
            .body(())
            .unwrap();

        let host = downstream_host(&req);
        assert_eq!(host.as_deref(), Some("real.example"));
        let headers = build_request_headers(&req, host.as_deref());
        assert_eq!(
            headers,
            vec![("host".to_owned(), "real.example".to_owned())]
        );
    }

    #[test]
    fn build_request_headers_removes_host_entirely_when_there_is_none() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/path")
            .body(())
            .unwrap();
        assert_eq!(downstream_host(&req), None);
        let headers = build_request_headers(&req, None);
        assert!(headers.is_empty());
    }

    /// C2 regression: `append_forwarded_for` appends the real peer address
    /// to an existing (client-suppliable) chain rather than replacing it,
    /// matching `observability::append_forwarded_for`'s semantics, and sets
    /// `x-forwarded-proto` unconditionally to `https`.
    #[test]
    fn append_forwarded_for_appends_the_real_peer_address_to_an_existing_chain() {
        let mut headers = vec![("x-forwarded-for".to_owned(), "203.0.113.9".to_owned())];
        append_forwarded_for(&mut headers, "198.51.100.7:12345".parse().unwrap());
        assert_eq!(
            headers
                .iter()
                .find(|(n, _)| n == "x-forwarded-for")
                .unwrap()
                .1,
            "203.0.113.9, 198.51.100.7"
        );
        assert_eq!(
            headers
                .iter()
                .find(|(n, _)| n == "x-forwarded-proto")
                .unwrap()
                .1,
            "https"
        );
    }

    /// C2 regression: a spoofed `X-Forwarded-For` sent by the client cannot
    /// impersonate the real peer address -- it can only be a prefix in the
    /// chain, with the real address always appended last.
    #[test]
    fn append_forwarded_for_defeats_a_spoofed_forwarded_for_header() {
        let mut headers = vec![(
            "x-forwarded-for".to_owned(),
            "10.0.0.1".to_owned(), // attacker-supplied, claims to be internal
        )];
        let real_client: SocketAddr = "203.0.113.55:9999".parse().unwrap();
        append_forwarded_for(&mut headers, real_client);
        let value = headers
            .iter()
            .find(|(n, _)| n == "x-forwarded-for")
            .unwrap()
            .1
            .clone();
        // The attacker's claimed value is preserved as a prior hop (as any
        // XFF chain would preserve upstream proxies), but the real,
        // untrusted-by-the-client address is always the last, authoritative
        // entry -- downstream IP-based logic that reads the last hop is not
        // fooled.
        assert_eq!(value, "10.0.0.1, 203.0.113.55");
        assert_ne!(value, "10.0.0.1");
    }

    #[test]
    fn strip_hop_by_hop_headers_removes_every_documented_hop_by_hop_header() {
        let mut headers = vec![
            ("connection".to_owned(), "keep-alive".to_owned()),
            ("keep-alive".to_owned(), "timeout=5".to_owned()),
            ("transfer-encoding".to_owned(), "chunked".to_owned()),
            ("upgrade".to_owned(), "websocket".to_owned()),
            ("proxy-authenticate".to_owned(), "Basic".to_owned()),
            ("proxy-authorization".to_owned(), "Basic abc".to_owned()),
            ("te".to_owned(), "trailers".to_owned()),
            ("trailers".to_owned(), "x-checksum".to_owned()),
            ("x-kept".to_owned(), "yes".to_owned()),
        ];
        strip_hop_by_hop_headers(&mut headers);
        assert_eq!(headers, vec![("x-kept".to_owned(), "yes".to_owned())]);
    }

    /// I7(c) / C1 parity test: builds two logically-equivalent requests --
    /// one the way `src/proxy.rs`'s real HTTP/1.1/HTTP/2
    /// `request_filter` builds its `InspectionContext` (from a
    /// `pingora_http::RequestHeader`, whose `Host` is an ordinary header --
    /// see `src/proxy.rs` around line 1048), the other via this module's
    /// `downstream_host` + `build_request_headers` +
    /// `build_inspection_context` (from an `http::Request` whose authority
    /// lives in `:authority`, not a `host` header) -- and asserts the
    /// resulting `InspectionContext`s agree on method, path, query, and
    /// (crucially) the `host` header a WAF rule would match against. This
    /// is the specific test category that would have caught C1: without
    /// the authority-to-host derivation, the HTTP/3-built context would
    /// have no `host` header at all while the HTTP/1.1-built one does.
    #[test]
    fn h1_and_h3_inspection_contexts_agree_on_host_method_path_and_query_for_equivalent_requests() {
        // HTTP/1.1/HTTP/2 path: mirrors src/proxy.rs's request_filter
        // InspectionContext construction (method/path/query/headers filter,
        // empty body) field-for-field, from a pingora_http::RequestHeader
        // carrying an ordinary `Host` header -- the only source of
        // authority HTTP/1.1 has.
        let mut header = pingora_http::RequestHeader::build("GET", b"/hello?x=1", None).unwrap();
        header.insert_header("host", "example.com").unwrap();
        header.insert_header("x-test", "1").unwrap();
        let h1_context = crate::waf::InspectionContext {
            method: header.method.as_str().to_owned(),
            path: header.uri.path().to_owned(),
            query: header.uri.query().unwrap_or_default().to_owned(),
            headers: header
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
            body: Vec::new(),
        };

        // HTTP/3 path: an equivalent request whose authority lives in
        // `:authority` (no `host` regular header at all -- the normal shape
        // for a real H3 client), run through this module's own
        // construction path.
        let h3_req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/hello?x=1")
            .header("x-test", "1")
            .body(())
            .unwrap();
        let h3_headers = build_request_headers(&h3_req, downstream_host(&h3_req).as_deref());
        let h3_context = build_inspection_context(
            h3_req.method().as_str(),
            h3_req.uri().path(),
            h3_req.uri().query().unwrap_or_default(),
            &h3_headers,
            Vec::new(),
        );

        assert_eq!(h1_context.method, h3_context.method);
        assert_eq!(h1_context.path, h3_context.path);
        assert_eq!(h1_context.query, h3_context.query);
        let h1_host = h1_context
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone());
        let h3_host = h3_context
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone());
        assert_eq!(h1_host, Some("example.com".to_owned()));
        assert_eq!(
            h1_host, h3_host,
            "a WAF rule matching on `host` must see the same value regardless of protocol"
        );
    }
}
