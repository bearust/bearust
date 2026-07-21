use crate::{
    acme::{lookup_http01_for_host, Http01Store},
    balancer::{BackendId, BackendLease},
    observability::{append_forwarded_for, classify_error, log_request, validated_request_id},
    router::{normalize_host, ResolvedRoute},
    runtime::{RuntimeSnapshot, RuntimeStore},
    waf::{evaluate, Evaluation, InspectionContext, WafDecision},
    waf_store::WafStore,
};
use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{upstreams::peer::HttpPeer, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::{sync::Arc, time::Instant};

pub struct RequestContext {
    pub snapshot: Option<Arc<RuntimeSnapshot>>,
    pub route: Option<ResolvedRoute>,
    pub lease: Option<BackendLease>,
    pub request_id: String,
    pub start: Instant,
    pub upstream_started: bool,
    pub failover_attempted: bool,
    pub excluded_backend: Option<BackendId>,
    pub completion_logged: bool,
    pub waf_body: Vec<u8>,
    pub waf_blocked: bool,
    /// The most recent bounded WAF result.  Keeping the result in the request
    /// context lets the body callback enrich the initial header-only check
    /// without re-reading or retaining the request payload.
    pub waf_evaluation: Option<Evaluation>,
    pub waf_telemetry_emitted: bool,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            snapshot: None,
            route: None,
            lease: None,
            request_id: validated_request_id(None),
            start: Instant::now(),
            upstream_started: false,
            failover_attempted: false,
            excluded_backend: None,
            completion_logged: false,
            waf_body: Vec::new(),
            waf_blocked: false,
            waf_evaluation: None,
            waf_telemetry_emitted: false,
        }
    }
}

pub struct BeaRustProxy {
    pub runtime: Arc<RuntimeStore>,
    pub challenges: Http01Store,
    pub waf: Option<Arc<WafStore>>,
}

impl BeaRustProxy {
    pub fn new(runtime: Arc<RuntimeStore>) -> Self {
        Self {
            runtime,
            challenges: Http01Store::default(),
            waf: None,
        }
    }
    pub fn with_challenge_store(mut self, challenges: Http01Store) -> Self {
        self.challenges = challenges;
        self
    }
    pub fn with_waf_store(mut self, waf: Arc<WafStore>) -> Self {
        self.waf = Some(waf);
        self
    }
}

pub fn http_service(
    proxy: BeaRustProxy,
    conf: &Arc<pingora_core::server::configuration::ServerConf>,
) -> pingora_core::services::listening::Service<pingora_proxy::HttpProxy<BeaRustProxy, ()>> {
    pingora_proxy::http_proxy_service(conf, proxy)
}

/// Emit only bounded, redacted WAF metadata.  In particular, do not use the
/// evaluator diagnostic here: it is intentionally useful for local debugging
/// but is not an audit payload contract.  Categories are normalized into
/// identifiers and capped so custom rule names cannot become an unbounded log
/// injection vector.
fn emit_waf_telemetry(request_id: &str, evaluation: &Evaluation) {
    if evaluation.semantic_score == 0 && evaluation.matched_rule_ids.is_empty() {
        return;
    }
    let details = crate::waf::redacted_telemetry(evaluation);
    tracing::info!(
        event = "waf_detection",
        request_id,
        category = %details.category,
        score = details.score,
        severity = %details.severity,
        reason_ids = %details.reason_ids,
        decision = ?evaluation.decision,
    );
}

#[async_trait]
impl ProxyHttp for BeaRustProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let snapshot = self.runtime.load();
        let host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path = session.req_header().uri.path().to_owned();
        ctx.request_id = validated_request_id(
            session
                .req_header()
                .headers
                .get("x-request-id")
                .map(|v| v.as_bytes()),
        );
        let challenge_host = normalize_host(host).unwrap_or_default();
        let method = session.req_header().method.as_str();
        if let Some(waf) = &self.waf {
            let context = InspectionContext {
                method: method.to_owned(),
                path: path.clone(),
                query: session.req_header().uri.query().unwrap_or_default().to_owned(),
                headers: session.req_header().headers.iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect(),
                body: Vec::new(),
            };
            let evaluation = evaluate(&waf.snapshot(), &context);
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
            ctx.waf_evaluation = Some(evaluation.clone());
            if !ctx.waf_telemetry_emitted {
                emit_waf_telemetry(&ctx.request_id, &evaluation);
                ctx.waf_telemetry_emitted = evaluation.semantic_score > 0
                    || !evaluation.matched_rule_ids.is_empty();
            }
            if evaluation.decision == WafDecision::Block {
                session.respond_error_with_body(403, Bytes::from_static(b"Request blocked")).await?;
                ctx.completion_logged = true;
                return Ok(true);
            }
        }
        if matches!(method, "GET" | "HEAD") {
            if let Some(value) = lookup_http01_for_host(&path, &challenge_host, &self.challenges) {
                session
                    .respond_error_with_body(200, Bytes::from(value))
                    .await?;
                ctx.completion_logged = true;
                return Ok(true);
            }
        }
        let Some((route, _)) = snapshot.route(host, &path) else {
            session.respond_error(404).await?;
            log_request(
                &ctx.request_id,
                session.req_header().method.as_str(),
                &path,
                "",
                "",
                404,
                ctx.start.elapsed().as_millis() as u64,
                "routing",
            );
            ctx.completion_logged = true;
            return Ok(true);
        };
        ctx.route = Some(route.clone());
        ctx.snapshot = Some(snapshot);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let snapshot = ctx.snapshot.as_ref().expect("request_filter must run");
        let route = ctx.route.as_ref().expect("route must be set");
        let Some(pool) = snapshot.pool(&route.upstream_pool) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "upstream pool unavailable",
            ));
        };
        let Some(lease) = pool.select(ctx.excluded_backend) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "no healthy upstream",
            ));
        };
        let address = lease.address();
        ctx.lease = Some(lease);
        let mut peer = HttpPeer::new(address, false, String::new());
        peer.options.connection_timeout = Some(pool.connect_timeout());
        peer.options.read_timeout = Some(pool.request_timeout());
        peer.options.write_timeout = Some(pool.request_timeout());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.waf_blocked {
            return Err(pingora_core::Error::explain(ErrorType::HTTPStatus(403), "request blocked by waf"));
        }
        if let Some(host) = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
        {
            let _ = request.insert_header("Host", host);
        }
        append_forwarded_for(
            request,
            session.client_addr().map(ToString::to_string).as_deref(),
        );
        let _ = request.insert_header("X-Request-Id", ctx.request_id.clone());
        ctx.upstream_started = true;
        Ok(())
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if self.waf.is_none() { return Ok(()); }
        if let Some(chunk) = body.as_ref() {
            let remaining = crate::waf::MAX_INSPECTION_BODY_BYTES.saturating_sub(ctx.waf_body.len());
            ctx.waf_body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        if end_of_stream {
            if let Some(waf) = &self.waf {
                let header_values = session.req_header().headers.iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect();
                let context = InspectionContext { method: session.req_header().method.as_str().to_owned(), path: session.req_header().uri.path().to_owned(), query: session.req_header().uri.query().unwrap_or_default().to_owned(), headers: header_values, body: ctx.waf_body.clone() };
                let evaluation = evaluate(&waf.snapshot(), &context);
                ctx.waf_blocked = evaluation.decision == WafDecision::Block;
                ctx.waf_evaluation = Some(evaluation.clone());
                if !ctx.waf_telemetry_emitted {
                    emit_waf_telemetry(&ctx.request_id, &evaluation);
                    ctx.waf_telemetry_emitted = evaluation.semantic_score > 0
                        || !evaluation.matched_rule_ids.is_empty();
                }
            }
        }
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        if ctx.completion_logged {
            ctx.lease.take();
            return;
        }
        let status = session
            .response_written()
            .map(|response| response.status.as_u16())
            .or_else(|| error.map(error_status))
            .unwrap_or(0);
        let route = ctx.route.as_ref().map_or("", |route| route.name.as_str());
        let upstream = ctx
            .lease
            .as_ref()
            .map_or_else(String::new, |lease| lease.address().to_string());
        log_request(
            &ctx.request_id,
            session.req_header().method.as_str(),
            session.req_header().uri.path(),
            route,
            &upstream,
            status,
            ctx.start.elapsed().as_millis() as u64,
            error.map(classify_error).unwrap_or(""),
        );
        ctx.completion_logged = true;
        ctx.lease.take();
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora_core::Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = error_status(error);
        if code > 0 && session.response_written().is_none() {
            let _ = session.respond_error(code).await;
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        if !ctx.failover_attempted {
            ctx.failover_attempted = true;
            if let Some(lease) = ctx.lease.take() {
                ctx.excluded_backend = Some(lease.id());
            }
            e.set_retry(true);
        } else {
            e.set_retry(false);
        }
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        _session: &mut Session,
        mut e: Box<pingora_core::Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<pingora_core::Error> {
        if ctx.upstream_started || ctx.failover_attempted {
            e.set_retry(false);
        } else {
            ctx.failover_attempted = true;
            if let Some(lease) = ctx.lease.take() {
                ctx.excluded_backend = Some(lease.id());
            }
            e.set_retry(true);
        }
        e.more_context(format!("Peer: {peer}"))
    }
}

fn error_status(error: &pingora_core::Error) -> u16 {
    match error.etype() {
        ErrorType::HTTPStatus(code) => *code,
        _ => 502,
    }
}

#[cfg(test)]
mod tests {
    use super::error_status;
    use pingora_core::{Error, ErrorType};

    #[test]
    fn preserves_explicit_http_error_status() {
        let error = Error::explain(ErrorType::HTTPStatus(503), "no healthy upstream");
        assert_eq!(error_status(&error), 503);
    }
}
