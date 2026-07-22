use crate::{
    acme::{lookup_http01_for_host, Http01Store},
    balancer::{BackendId, BackendLease},
    observability::{append_forwarded_for, classify_error, log_request, validated_request_id},
    router::{normalize_host, ResolvedRoute},
    runtime::{RuntimeSnapshot, RuntimeStore},
    waf::{evaluate, Evaluation, InspectionContext, WafDecision, WafSnapshot},
    waf_store::WafStore,
    bot_protection::{evaluate as evaluate_bot, BotAction, BotEvaluation, BotInspectionContext},
    bot_store::BotStore,
    bot_challenge::{ChallengeService, unix_now},
};
use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{upstreams::peer::HttpPeer, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
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
    pub waf_buffering: bool,
    pub waf_pending_suffix: Vec<u8>,
    pub waf_large_chunk: bool,
    pub waf_large_chunk_includes_prefix: bool,
    pub waf_blocked: bool,
    /// The most recent bounded WAF result.  Keeping the result in the request
    /// context lets the body callback enrich the initial header-only check
    /// without re-reading or retaining the request payload.
    pub waf_evaluation: Option<Evaluation>,
    pub waf_telemetry_emitted: bool,
    pub waf_snapshot: Option<Arc<WafSnapshot>>,
    pub waf_body_expected: bool,
    pub bot_evaluation: Option<BotEvaluation>,
    pub bot_blocked: bool,
    pub bot_challenge: bool,
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
            waf_buffering: true,
            waf_pending_suffix: Vec::new(),
            waf_large_chunk: false,
            waf_large_chunk_includes_prefix: false,
            waf_blocked: false,
            waf_evaluation: None,
            waf_telemetry_emitted: false,
            waf_snapshot: None,
            waf_body_expected: false,
            bot_evaluation: None,
            bot_blocked: false,
            bot_challenge: false,
        }
    }
}

pub struct BeaRustProxy {
    pub runtime: Arc<RuntimeStore>,
    pub http01: Http01Store,
    pub waf: Option<Arc<WafStore>>,
    pub bot: Option<Arc<BotStore>>,
    pub challenges: Option<Arc<ChallengeService>>,
}

impl BeaRustProxy {
    pub fn new(runtime: Arc<RuntimeStore>) -> Self {
        Self {
            runtime,
            http01: Http01Store::default(),
            waf: None,
            bot: None,
            challenges: None,
        }
    }
    pub fn with_challenge_store(mut self, challenges: Http01Store) -> Self {
        self.http01 = challenges;
        self
    }
    pub fn with_waf_store(mut self, waf: Arc<WafStore>) -> Self {
        self.waf = Some(waf);
        self
    }
    pub fn with_bot_store(mut self, bot: Arc<BotStore>, challenges: Arc<ChallengeService>) -> Self {
        self.bot = Some(bot);
        self.challenges = Some(challenges);
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
fn emit_waf_telemetry(request_id: &str, waf: &WafStore, evaluation: &Evaluation) {
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
    waf.record_detection(evaluation);
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
        if let Some(bot) = &self.bot {
            let headers = session.req_header().headers.iter().filter_map(|(name, value)| {
                let name = name.as_str().to_ascii_lowercase();
                if !matches!(name.as_str(), "user-agent" | "accept" | "accept-language" | "sec-ch-ua" | "x-forwarded-for" | "host") { return None; }
                value.to_str().ok().map(|value| (name, value.to_owned()))
            }).collect::<Vec<_>>();
            let inspection = BotInspectionContext::new(method, &path, headers);
            let snapshot = bot.snapshot();
            let mut evaluation = evaluate_bot(&snapshot, &inspection);
            let valid_clearance = session.req_header().headers.get("cookie").and_then(|v| v.to_str().ok()).and_then(cookie_value).and_then(|token| self.challenges.as_ref().and_then(|service| service.verify_clearance(token, &evaluation.fingerprint, unix_now()).ok())).is_some();
            if valid_clearance && evaluation.action == BotAction::Challenge { evaluation.action = BotAction::Allow; }
            ctx.bot_evaluation = Some(evaluation.clone());
            if evaluation.action != BotAction::Allow { bot.record_detection(&evaluation); tracing::info!(event="bot_detection", request_id=%ctx.request_id, action=?evaluation.action, score=evaluation.score, trusted=evaluation.trusted, categories=?evaluation.categories, fingerprint_prefix=%evaluation.fingerprint.chars().take(16).collect::<String>()); }
            ctx.bot_blocked = evaluation.action == BotAction::Block;
            ctx.bot_challenge = evaluation.action == BotAction::Challenge;
        }
        if let Some(waf) = &self.waf {
            let waf_snapshot = waf.snapshot();
            ctx.waf_snapshot = Some(waf_snapshot.clone());
            ctx.waf_body_expected = session
                .req_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > 0)
                || session.req_header().headers.get("transfer-encoding").is_some();
            let context = InspectionContext {
                method: method.to_owned(),
                path: path.clone(),
                query: session.req_header().uri.query().unwrap_or_default().to_owned(),
                headers: session.req_header().headers.iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect(),
                body: Vec::new(),
            };
            let evaluation = evaluate(&waf_snapshot, &context);
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
            ctx.waf_evaluation = Some(evaluation.clone());
            if !ctx.waf_body_expected && !ctx.waf_telemetry_emitted {
                emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
                ctx.waf_telemetry_emitted = evaluation.semantic_score > 0
                    || !evaluation.matched_rule_ids.is_empty();
            }
            if evaluation.decision == WafDecision::Block {
                session.respond_error_with_body(403, Bytes::from_static(b"Request blocked")).await?;
                ctx.completion_logged = true;
                return Ok(true);
            }
        }
        if ctx.bot_blocked {
            session.respond_error_with_body(403, Bytes::from_static(b"Request blocked")).await?;
            ctx.completion_logged = true;
            return Ok(true);
        }
        if ctx.bot_challenge {
            let body = if let (Some(service), Some(evaluation)) = (&self.challenges, &ctx.bot_evaluation) { service.issue_challenge(&evaluation.fingerprint, unix_now()).await.ok().and_then(|value| serde_json::to_vec(&value).ok()) } else { None }.unwrap_or_else(|| b"Challenge required".to_vec());
            let mut response = ResponseHeader::build(403, Some(3)).map_err(|e| pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string()))?;
            response.insert_header("Cache-Control", "no-store").map_err(|e| pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string()))?;
            response.insert_header("Content-Type", "application/json").map_err(|e| pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string()))?;
            session.as_downstream_mut().write_error_response(response, Bytes::from(body)).await?;
            ctx.completion_logged = true;
            return Ok(true);
        }
        if matches!(method, "GET" | "HEAD") {
            if let Some(value) = lookup_http01_for_host(&path, &challenge_host, &self.http01) {
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
        if ctx.waf_buffering {
            if let Some(chunk) = body.as_ref() {
                let remaining = crate::waf::MAX_INSPECTION_BODY_BYTES.saturating_sub(ctx.waf_body.len());
                let take = chunk.len().min(remaining);
                ctx.waf_body.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    // Keep the original chunk untouched while the retained
                    // prefix is evaluated below. If allowed, it can stream
                    // immediately without retaining an unbounded suffix.
                    ctx.waf_large_chunk = true;
                    ctx.waf_large_chunk_includes_prefix = take > 0;
                    ctx.waf_buffering = false;
                } else {
                    *body = Some(Bytes::new());
                }
            }
        }
        if let Some(waf) = &self.waf {
                let header_values = session.req_header().headers.iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect();
                let context = InspectionContext { method: session.req_header().method.as_str().to_owned(), path: session.req_header().uri.path().to_owned(), query: session.req_header().uri.query().unwrap_or_default().to_owned(), headers: header_values, body: ctx.waf_body.clone() };
                let evaluation = ctx
                    .waf_snapshot
                    .as_ref()
                    .map(|snapshot| evaluate(snapshot, &context))
                    .unwrap_or_else(|| evaluate(&waf.snapshot(), &context));
                ctx.waf_blocked = evaluation.decision == WafDecision::Block;
                ctx.waf_evaluation = Some(evaluation.clone());
                // Evaluate every bounded chunk before forwarding it. This
                // catches body-only attacks without requiring replay/buffering.
                if ctx.waf_blocked {
                    emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
                    *body = None;
                    ctx.completion_logged = true;
                    session
                        .respond_error_with_body(403, Bytes::from_static(b"Request blocked"))
                        .await?;
                    // Returning an error is required here: `Ok(())` would let
                    // Pingora continue its upstream body pipeline after the
                    // downstream response was written.
                    return Err(pingora_core::Error::explain(
                        ErrorType::HTTPStatus(403),
                        "request blocked by waf",
                    ));
                }
                if ctx.waf_large_chunk {
                    if !ctx.waf_large_chunk_includes_prefix && !ctx.waf_body.is_empty() {
                        let mut forwarded = Vec::with_capacity(ctx.waf_body.len() + body.as_ref().map_or(0, |bytes| bytes.len()));
                        forwarded.extend_from_slice(&ctx.waf_body);
                        if let Some(chunk) = body.as_ref() {
                            forwarded.extend_from_slice(chunk);
                        }
                        *body = Some(Bytes::from(forwarded));
                    }
                    ctx.waf_body.clear();
                    ctx.waf_pending_suffix.clear();
                    ctx.waf_large_chunk = false;
                    ctx.waf_large_chunk_includes_prefix = false;
                }
                if end_of_stream && (evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty()) {
                    emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
                }
                let should_flush_buffer = !ctx.waf_blocked
                    && ctx.waf_buffering
                    && (end_of_stream
                        || ctx.waf_body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES);
                if should_flush_buffer {
                    let mut forwarded = Vec::with_capacity(ctx.waf_body.len() + ctx.waf_pending_suffix.len());
                    forwarded.extend_from_slice(&ctx.waf_body);
                    forwarded.extend_from_slice(&ctx.waf_pending_suffix);
                    *body = Some(Bytes::from(forwarded));
                    ctx.waf_body.clear();
                    ctx.waf_pending_suffix.clear();
                    ctx.waf_buffering = false;
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

fn cookie_value(header: &str) -> Option<&str> { header.split(';').map(str::trim).find_map(|part| part.strip_prefix("bearust_bot_clear=")) }

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
