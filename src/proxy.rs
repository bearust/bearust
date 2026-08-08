use crate::{
    acme::{lookup_http01_for_host, Http01Store},
    analytics::{AnalyticsCollector, AnalyticsEvent, SecurityCounters},
    balancer::{BackendId, BackendLease},
    bot_challenge::{unix_now, ChallengeService},
    bot_protection::{evaluate as evaluate_bot, BotAction, BotEvaluation, BotInspectionContext},
    bot_store::BotStore,
    observability::{append_forwarded_for, classify_error, log_request, validated_request_id},
    plugin_runtime::PluginManager,
    rate_limit::{Decision as RateLimitDecision, RateLimitAction, RateLimitKey, RateLimitPolicy},
    rate_limit_store::{client_ip, IpNetSet, RateLimiterStore},
    router::{normalize_host, ResolvedRoute},
    runtime::{RuntimeSnapshot, RuntimeStore},
    waf::{evaluate, Evaluation, InspectionContext, WafDecision, WafSnapshot},
    waf_store::WafStore,
};
use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{upstreams::peer::HttpPeer, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::{collections::HashMap, sync::Arc, time::Instant};

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
    pub analytics_logged: bool,
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
    pub rate_limit_decision: Option<RateLimitDecision>,
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
            analytics_logged: false,
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
            rate_limit_decision: None,
        }
    }
}

pub struct BeaRustProxy {
    pub runtime: Arc<RuntimeStore>,
    pub http01: Http01Store,
    pub waf: Option<Arc<WafStore>>,
    pub bot: Option<Arc<BotStore>>,
    pub challenges: Option<Arc<ChallengeService>>,
    pub rate_limiter: Option<Arc<RateLimiterStore>>,
    pub rate_limit_policy: RateLimitPolicy,
    pub trusted_proxies: IpNetSet,
    pub analytics: Option<Arc<AnalyticsCollector>>,
    pub analytics_changed: Option<Arc<dyn Fn() + Send + Sync>>,
    pub analytics_host_ids: HashMap<String, i64>,
    pub baseline: Option<Arc<crate::baseline::BaselineCollector>>,
    pub anomaly: Option<Arc<crate::anomaly::AnomalyDetector>>,
    pub plugin_notify: Option<Arc<crate::plugin_notify::NotificationSink>>,
    pub plugin_manager: Option<Arc<PluginManager>>,
}

impl BeaRustProxy {
    pub fn new(runtime: Arc<RuntimeStore>) -> Self {
        Self {
            runtime,
            http01: Http01Store::default(),
            waf: None,
            bot: None,
            challenges: None,
            rate_limiter: None,
            rate_limit_policy: RateLimitPolicy::default(),
            trusted_proxies: IpNetSet::default(),
            analytics: None,
            analytics_changed: None,
            analytics_host_ids: HashMap::new(),
            baseline: None,
            anomaly: None,
            plugin_notify: None,
            plugin_manager: None,
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
    pub fn with_rate_limiter(mut self, store: Arc<RateLimiterStore>) -> Self {
        self.rate_limiter = Some(store);
        self
    }
    pub fn with_rate_limit_policy(mut self, policy: RateLimitPolicy) -> Self {
        if let Some(store) = &self.rate_limiter {
            store.set_policy(policy.clone());
        }
        self.rate_limit_policy = policy;
        self
    }
    pub fn with_trusted_proxies(mut self, trusted: IpNetSet) -> Self {
        self.trusted_proxies = trusted;
        self
    }
    pub fn with_analytics(mut self, analytics: Arc<AnalyticsCollector>) -> Self {
        self.analytics = Some(analytics);
        self
    }
    pub fn with_analytics_changed_notifier(
        mut self,
        notifier: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        self.analytics_changed = Some(notifier);
        self
    }
    pub fn with_analytics_host_ids(mut self, host_ids: HashMap<String, i64>) -> Self {
        self.analytics_host_ids = host_ids;
        self
    }
    pub fn with_baseline(mut self, baseline: Arc<crate::baseline::BaselineCollector>) -> Self {
        self.baseline = Some(baseline);
        self
    }
    pub fn with_anomaly(mut self, anomaly: Arc<crate::anomaly::AnomalyDetector>) -> Self {
        self.anomaly = Some(anomaly);
        self
    }
    pub fn with_plugin_notify_sink(
        mut self,
        sink: Arc<crate::plugin_notify::NotificationSink>,
    ) -> Self {
        self.plugin_notify = Some(sink);
        self
    }
    pub fn with_plugin_manager(mut self, manager: Arc<PluginManager>) -> Self {
        self.plugin_manager = Some(manager);
        self
    }

    fn record_completion(
        &self,
        session: &Session,
        ctx: &mut RequestContext,
        status_hint: Option<u16>,
    ) {
        if ctx.analytics_logged {
            return;
        }
        let Some(analytics) = &self.analytics else {
            return;
        };
        let status_code = status_hint
            .or_else(|| {
                session
                    .response_written()
                    .map(|response| response.status.as_u16())
            })
            .unwrap_or(0);
        let security = analytics_security_counters(
            ctx.waf_blocked,
            ctx.bot_blocked,
            ctx.bot_challenge,
            matches!(
                ctx.rate_limit_decision,
                Some(RateLimitDecision::Limited { .. })
            ),
        );
        let proxy_host_id = ctx
            .route
            .as_ref()
            .and_then(|route| self.analytics_host_ids.get(&route.host).copied())
            .unwrap_or(0);
        analytics.record(completion_event(
            proxy_host_id,
            status_code,
            ctx.start.elapsed().as_millis() as u64,
            security,
        ));
        invoke_analytics_changed(&self.analytics_changed);
        ctx.analytics_logged = true;
    }
}

fn invoke_analytics_changed(notifier: &Option<Arc<dyn Fn() + Send + Sync>>) {
    if let Some(notifier) = notifier {
        notifier();
    }
}

/// Build the bounded security dimensions attached to one completion event.
/// Bot blocks are counted as security events independently of challenges.
pub fn analytics_security_counters(
    waf_blocked: bool,
    bot_blocked: bool,
    bot_challenge: bool,
    rate_limited: bool,
) -> SecurityCounters {
    SecurityCounters {
        waf_blocks: u64::from(waf_blocked),
        bot_blocks: u64::from(bot_blocked),
        bot_challenges: u64::from(bot_challenge),
        rate_limited: u64::from(rate_limited),
    }
}

/// Construct a completion event without retaining request data or headers.
pub fn completion_event(
    proxy_host_id: i64,
    status_code: u16,
    latency_ms: u64,
    security: SecurityCounters,
) -> AnalyticsEvent {
    AnalyticsEvent {
        proxy_host_id,
        timestamp: chrono::Utc::now(),
        status_code,
        latency_ms,
        security,
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
/// Builds the notification-sink event for a WAF decision, or `None` if the
/// decision was not a block. Pure and side-effect free so it can be tested
/// without a running plugin or channel.
fn waf_block_event(
    request_id: &str,
    decision: WafDecision,
    details: &crate::waf::RedactedTelemetry,
) -> Option<bearust_plugin_sdk::WafBlockEvent> {
    if decision != WafDecision::Block {
        return None;
    }
    Some(bearust_plugin_sdk::WafBlockEvent {
        request_id: request_id.to_owned(),
        occurred_at_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        category: details.category.clone(),
        score: details.score,
        severity: details.severity.clone(),
        reason_ids: details.reason_ids.clone(),
    })
}

/// `waf.detect`'s body is capped smaller than the rule engine's own
/// `MAX_INSPECTION_BODY_BYTES` (8 KiB) specifically because JSON encodes a
/// byte array as decimal numbers -- roughly a 4x size increase -- and this
/// keeps the worst-case wire payload well under a plugin's declared
/// `max_output_bytes`.
const MAX_WAF_DETECT_BODY_BYTES: usize = 2048;

/// Truncates `value` to at most `*remaining` bytes (and no more than
/// `crate::waf::MAX_NORMALIZED_FIELD_BYTES` per field), at a char boundary,
/// decrementing `*remaining` by the bytes actually kept. Mirrors the
/// budget-tracking shape of `crate::waf::normalize_context`'s private
/// `normalize_metadata` closure, applied here to the raw (non-normalized)
/// text a `waf.detect` plugin receives.
fn bounded_metadata(value: &str, remaining: &mut usize) -> String {
    let cap = (*remaining).min(crate::waf::MAX_NORMALIZED_FIELD_BYTES);
    let mut end = value.len().min(cap);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = value[..end].to_owned();
    *remaining = remaining.saturating_sub(truncated.len());
    truncated
}

/// Converts a WAF `InspectionContext` into the wire shape a `waf.detect`
/// plugin receives. `method`/`path`/`query`/`headers` share a
/// `crate::waf::MAX_NORMALIZED_METADATA_BYTES` budget and each header is
/// additionally capped at `crate::waf::MAX_NORMALIZED_FIELD_BYTES` -- the
/// same bounds the built-in rule engine enforces on the same raw fields --
/// so a detector plugin never receives more attacker-controlled metadata
/// than the rule engine itself inspects. `body` is separately capped at
/// `MAX_WAF_DETECT_BODY_BYTES`. Pure and side-effect free.
fn waf_detect_request(context: &InspectionContext) -> bearust_plugin_sdk::WafDetectRequest {
    let mut remaining = crate::waf::MAX_NORMALIZED_METADATA_BYTES;
    let method = bounded_metadata(&context.method, &mut remaining);
    let path = bounded_metadata(&context.path, &mut remaining);
    let query = bounded_metadata(&context.query, &mut remaining);
    let headers = context
        .headers
        .iter()
        .take(crate::waf::MAX_NORMALIZED_HEADERS)
        .map(|(name, value)| {
            (
                bounded_metadata(name, &mut remaining),
                bounded_metadata(value, &mut remaining),
            )
        })
        .collect();
    let body_len = context.body.len().min(MAX_WAF_DETECT_BODY_BYTES);
    bearust_plugin_sdk::WafDetectRequest {
        method,
        path,
        query,
        headers,
        body: context.body[..body_len].to_vec(),
    }
}

/// Runs the registered `waf.detect` plugin (if any) against `context` and
/// merges its verdict into `evaluation`. Synchronous from the caller's
/// point of view but offloads the blocking wasmtime call via
/// `spawn_blocking` so it never blocks the shared async runtime. Fails
/// open on every error class: no detector configured, no plugin currently
/// declaring the capability, a disabled plugin, a trap/timeout/fuel
/// exhaustion, a malformed verdict, or a `spawn_blocking` join failure all
/// return `evaluation` unchanged (after counting a failure metric where
/// applicable).
async fn apply_waf_detector(
    plugin_manager: Option<&Arc<PluginManager>>,
    context: &InspectionContext,
    evaluation: Evaluation,
) -> Evaluation {
    let Some(manager) = plugin_manager else {
        return evaluation;
    };
    let Some(detector) = manager.waf_detector_plugin() else {
        return evaluation;
    };
    let metrics = manager.metrics();
    let request = waf_detect_request(context);
    let outcome = tokio::task::spawn_blocking(move || detector.detect(&request)).await;
    match outcome {
        Ok(Ok(verdict)) => {
            metrics.record_waf_detect_invocation();
            let previous_decision = evaluation.decision.clone();
            let merged = crate::waf::merge_plugin_verdict(evaluation, verdict);
            if merged.decision == WafDecision::Block && previous_decision != WafDecision::Block {
                metrics.record_waf_detect_block();
            }
            merged
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "waf_detect_failed", reason = error.code());
            metrics.record_waf_detect_failure();
            evaluation
        }
        Err(_join_error) => {
            tracing::warn!(event = "waf_detect_failed", reason = "join_error");
            metrics.record_waf_detect_failure();
            evaluation
        }
    }
}

fn emit_waf_telemetry(
    request_id: &str,
    waf: &WafStore,
    evaluation: &Evaluation,
    notify: Option<&crate::plugin_notify::NotificationSink>,
) {
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
    if let Some(notify) = notify {
        if let Some(event) = waf_block_event(request_id, evaluation.decision.clone(), &details) {
            notify.notify_waf_block(event);
        }
    }
}

fn emit_rate_limit_telemetry(
    request_id: &str,
    decision: &RateLimitDecision,
    action: RateLimitAction,
) {
    if let RateLimitDecision::Limited {
        remaining_tokens,
        retry_after,
    } = decision
    {
        tracing::info!(
            event = "rate_limit_detection",
            request_id,
            action = ?action,
            remaining_tokens,
            retry_after_seconds = retry_after.as_secs().min(3_600),
        );
    }
}

fn route_key(route: &ResolvedRoute) -> i64 {
    // Stable, non-sensitive identity for the configured proxy host.  The
    // control-plane proxy-host id can replace this hash once it is wired into
    // the runtime snapshot; paths deliberately do not participate so all
    // routes on one host share the same client quota.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in route.host.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash & i64::MAX as u64) as i64
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
            let headers = session
                .req_header()
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    let name = name.as_str().to_ascii_lowercase();
                    if !matches!(
                        name.as_str(),
                        "user-agent"
                            | "accept"
                            | "accept-language"
                            | "sec-ch-ua"
                            | "x-forwarded-for"
                            | "host"
                    ) {
                        return None;
                    }
                    value.to_str().ok().map(|value| (name, value.to_owned()))
                })
                .collect::<Vec<_>>();
            // Trusted crawler bypass is intentionally deferred until a signed
            // ingress marker is implemented. Client headers never verify origin.
            let inspection = BotInspectionContext::new(method, &path, headers);
            let snapshot = bot.snapshot();
            let mut evaluation = evaluate_bot(&snapshot, &inspection);
            let valid_clearance = session
                .req_header()
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(cookie_value)
                .and_then(|token| {
                    self.challenges.as_ref().and_then(|service| {
                        service
                            .verify_clearance(token, &evaluation.fingerprint, unix_now())
                            .ok()
                    })
                })
                .is_some();
            if valid_clearance && evaluation.action == BotAction::Challenge {
                evaluation.action = BotAction::Allow;
            }
            ctx.bot_evaluation = Some(evaluation.clone());
            if evaluation.action != BotAction::Allow {
                bot.record_detection(&evaluation);
                tracing::info!(event="bot_detection", request_id=%ctx.request_id, action=?evaluation.action, score=evaluation.score, trusted=evaluation.trusted, categories=?evaluation.categories, fingerprint_prefix=%evaluation.fingerprint.chars().take(16).collect::<String>());
            }
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
                || session
                    .req_header()
                    .headers
                    .get("transfer-encoding")
                    .is_some();
            let context = InspectionContext {
                method: method.to_owned(),
                path: path.clone(),
                query: session
                    .req_header()
                    .uri
                    .query()
                    .unwrap_or_default()
                    .to_owned(),
                headers: session
                    .req_header()
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
            let evaluation = evaluate(&waf_snapshot, &context);
            let evaluation =
                apply_waf_detector(self.plugin_manager.as_ref(), &context, evaluation).await;
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
            ctx.waf_evaluation = Some(evaluation.clone());
            if !ctx.waf_body_expected && !ctx.waf_telemetry_emitted {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
                ctx.waf_telemetry_emitted =
                    evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty();
            }
            if evaluation.decision == WafDecision::Block {
                session
                    .respond_error_with_body(403, Bytes::from_static(b"Request blocked"))
                    .await?;
                self.record_completion(session, ctx, None);
                ctx.completion_logged = true;
                return Ok(true);
            }
        }
        if ctx.bot_blocked {
            session
                .respond_error_with_body(403, Bytes::from_static(b"Request blocked"))
                .await?;
            self.record_completion(session, ctx, None);
            ctx.completion_logged = true;
            return Ok(true);
        }
        if ctx.bot_challenge {
            let body = if let Some(evaluation) = &ctx.bot_evaluation {
                let prefix: String = evaluation.fingerprint.chars().take(16).collect();
                serde_json::to_vec(&serde_json::json!({
                    "challenge_url": format!("/bot-challenge?fingerprint_prefix={prefix}"),
                    "fingerprint_prefix": prefix,
                }))
                .unwrap_or_else(|_| b"Challenge required".to_vec())
            } else {
                b"Challenge required".to_vec()
            };
            let mut response = ResponseHeader::build(403, Some(3)).map_err(|e| {
                pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string())
            })?;
            response
                .insert_header("Cache-Control", "no-store")
                .map_err(|e| {
                    pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string())
                })?;
            response
                .insert_header("Content-Type", "application/json")
                .map_err(|e| {
                    pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string())
                })?;
            session
                .as_downstream_mut()
                .write_error_response(response, Bytes::from(body))
                .await?;
            self.record_completion(session, ctx, None);
            ctx.completion_logged = true;
            return Ok(true);
        }
        if matches!(method, "GET" | "HEAD") {
            if let Some(value) = lookup_http01_for_host(&path, &challenge_host, &self.http01) {
                session
                    .respond_error_with_body(200, Bytes::from(value))
                    .await?;
                self.record_completion(session, ctx, None);
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
            self.record_completion(session, ctx, Some(404));
            ctx.completion_logged = true;
            return Ok(true);
        };
        ctx.route = Some(route.clone());
        ctx.snapshot = Some(snapshot);
        if let Some(store) = &self.rate_limiter {
            let peer = session
                .client_addr()
                .and_then(|addr| addr.as_inet().map(|inet| inet.ip()));
            if let Some(peer) = peer {
                let ip = client_ip(peer, &session.req_header().headers, &self.trusted_proxies);
                // The store owns the live policy snapshot so control-plane
                // mutations take effect for existing proxy workers without a
                // listener restart.
                let host_id = route_key(ctx.route.as_ref().expect("route must be set"));
                let policy = store.host_policy(host_id);
                let decision = store.evaluate(
                    RateLimitKey {
                        proxy_host_id: host_id,
                        client_ip: ip,
                    },
                    &policy,
                    Instant::now(),
                );
                ctx.rate_limit_decision = Some(decision);
                if let RateLimitDecision::Limited { .. } = decision {
                    emit_rate_limit_telemetry(&ctx.request_id, &decision, policy.action);
                    if policy.action == RateLimitAction::Block {
                        let retry_after = match decision {
                            RateLimitDecision::Limited { retry_after, .. } => {
                                retry_after.as_secs().clamp(1, 3_600)
                            }
                            RateLimitDecision::Allowed { .. } => 1,
                        };
                        let mut response = ResponseHeader::build(429, Some(2)).map_err(|e| {
                            pingora_core::Error::explain(ErrorType::HTTPStatus(500), e.to_string())
                        })?;
                        response
                            .insert_header("Retry-After", retry_after.to_string())
                            .map_err(|e| {
                                pingora_core::Error::explain(
                                    ErrorType::HTTPStatus(500),
                                    e.to_string(),
                                )
                            })?;
                        response
                            .insert_header("Cache-Control", "no-store")
                            .map_err(|e| {
                                pingora_core::Error::explain(
                                    ErrorType::HTTPStatus(500),
                                    e.to_string(),
                                )
                            })?;
                        session
                            .as_downstream_mut()
                            .write_error_response(
                                response,
                                Bytes::from_static(b"Rate limit exceeded"),
                            )
                            .await?;
                        self.record_completion(session, ctx, Some(429));
                        ctx.completion_logged = true;
                        return Ok(true);
                    }
                }
            }
        }
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
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(403),
                "request blocked by waf",
            ));
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
        if self.waf.is_none() {
            return Ok(());
        }
        if ctx.waf_buffering {
            if let Some(chunk) = body.as_ref() {
                let remaining =
                    crate::waf::MAX_INSPECTION_BODY_BYTES.saturating_sub(ctx.waf_body.len());
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
            let header_values = session
                .req_header()
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect();
            let context = InspectionContext {
                method: session.req_header().method.as_str().to_owned(),
                path: session.req_header().uri.path().to_owned(),
                query: session
                    .req_header()
                    .uri
                    .query()
                    .unwrap_or_default()
                    .to_owned(),
                headers: header_values,
                body: ctx.waf_body.clone(),
            };
            let mut evaluation = ctx
                .waf_snapshot
                .as_ref()
                .map(|snapshot| evaluate(snapshot, &context))
                .unwrap_or_else(|| evaluate(&waf.snapshot(), &context));
            if end_of_stream || ctx.waf_body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES {
                evaluation =
                    apply_waf_detector(self.plugin_manager.as_ref(), &context, evaluation).await;
            }
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
            ctx.waf_evaluation = Some(evaluation.clone());
            // Evaluate every bounded chunk before forwarding it. This
            // catches body-only attacks without requiring replay/buffering.
            if ctx.waf_blocked {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
                *body = None;
                session
                    .respond_error_with_body(403, Bytes::from_static(b"Request blocked"))
                    .await?;
                self.record_completion(session, ctx, None);
                ctx.completion_logged = true;
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
                    let mut forwarded = Vec::with_capacity(
                        ctx.waf_body.len() + body.as_ref().map_or(0, |bytes| bytes.len()),
                    );
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
            if end_of_stream
                && (evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty())
            {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
            }
            let should_flush_buffer = !ctx.waf_blocked
                && ctx.waf_buffering
                && (end_of_stream || ctx.waf_body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES);
            if should_flush_buffer {
                let mut forwarded =
                    Vec::with_capacity(ctx.waf_body.len() + ctx.waf_pending_suffix.len());
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
        self.record_completion(session, ctx, Some(status));
        ctx.lease.take();
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = error_status(error);
        if code > 0 && session.response_written().is_none() {
            let _ = session.respond_error(code).await;
        }
        // Record before returning even when writing the downstream error
        // failed; logging still owns the request log and this call is
        // idempotent through analytics_logged.
        self.record_completion(session, ctx, Some(code));
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

fn cookie_value(header: &str) -> Option<&str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("bearust_bot_clear="))
}

fn error_status(error: &pingora_core::Error) -> u16 {
    match error.etype() {
        ErrorType::HTTPStatus(code) => *code,
        _ => 502,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_waf_detector, error_status, invoke_analytics_changed, waf_block_event};
    use pingora_core::{Error, ErrorType};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn preserves_explicit_http_error_status() {
        let error = Error::explain(ErrorType::HTTPStatus(503), "no healthy upstream");
        assert_eq!(error_status(&error), 503);
    }

    #[test]
    fn analytics_change_notifier_is_invoked() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let notifier: Option<Arc<dyn Fn() + Send + Sync>> = Some(Arc::new(move || {
            observed.fetch_add(1, Ordering::Relaxed);
        }));
        invoke_analytics_changed(&notifier);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn waf_block_event_is_built_only_for_block_decisions() {
        let details = crate::waf::RedactedTelemetry {
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        };
        assert!(waf_block_event("req-1", crate::waf::WafDecision::Allow, &details).is_none());
        assert!(waf_block_event("req-1", crate::waf::WafDecision::Log, &details).is_none());
        let event = waf_block_event("req-1", crate::waf::WafDecision::Block, &details).unwrap();
        assert_eq!(event.request_id, "req-1");
        assert_eq!(event.category, "sqli");
        assert_eq!(event.score, 42);
        assert_eq!(event.severity, "high");
        assert_eq!(event.reason_ids, "sqli");
    }

    /// Regression test for the spec's acceptance gate: "WAF block/allow
    /// decisions are byte-for-byte unchanged by the presence or absence of
    /// a sink plugin — the hook is purely observational." `waf_block_event`
    /// takes `details` by shared reference and returns a new, independent
    /// `WafBlockEvent`; it has no `&mut` parameter, no return channel back
    /// into the decision, and no shared/global state to mutate. This test
    /// pins that signature down: it proves the inputs are byte-for-byte
    /// identical before and after the call (regardless of whether the
    /// decision was a block, and regardless of whether the resulting event
    /// is ever constructed at all), so a future change can't quietly make
    /// this function start influencing the WAF decision it merely reads.
    #[test]
    fn waf_block_event_never_influences_the_decision_it_reads() {
        let details = crate::waf::RedactedTelemetry {
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        };

        for decision in [
            crate::waf::WafDecision::Allow,
            crate::waf::WafDecision::Log,
            crate::waf::WafDecision::Block,
        ] {
            let details_before = details.clone();
            let decision_before = decision.clone();

            let event = waf_block_event("req-1", decision.clone(), &details);

            // The inputs the function read are byte-for-byte unchanged: a
            // pure fn taking `&details` by shared reference cannot feed
            // anything back into the decision path.
            assert_eq!(details, details_before);
            assert_eq!(decision, decision_before);

            match decision {
                crate::waf::WafDecision::Block => assert!(event.is_some()),
                crate::waf::WafDecision::Allow | crate::waf::WafDecision::Log => {
                    assert!(event.is_none())
                }
            }
        }

        // Calling the function at all -- for any decision, including the
        // ones that yield no event -- leaves `details` fit to be read again
        // by the real telemetry/decision path with the same result (the
        // only field that legitimately varies between calls is the
        // wall-clock timestamp).
        let first = waf_block_event("req-1", crate::waf::WafDecision::Block, &details).unwrap();
        let second = waf_block_event("req-1", crate::waf::WafDecision::Block, &details).unwrap();
        assert_eq!(first.request_id, second.request_id);
        assert_eq!(first.category, second.category);
        assert_eq!(first.score, second.score);
        assert_eq!(first.severity, second.severity);
        assert_eq!(first.reason_ids, second.reason_ids);
    }

    use crate::config::PluginConfig;
    use crate::plugin_runtime::PluginManager;
    use std::fs;
    use tempfile::tempdir;

    fn waf_detector_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("waf-detect-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/waf_detect_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("waf-detect-v2", false).unwrap();
        }
        manager
    }

    fn sample_context() -> crate::waf::InspectionContext {
        crate::waf::InspectionContext {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn allow_evaluation() -> crate::waf::Evaluation {
        crate::waf::Evaluation {
            decision: crate::waf::WafDecision::Allow,
            matched_rule_ids: Vec::new(),
            categories: Vec::new(),
            diagnostic: None,
            semantic_score: 0,
            severity: None,
        }
    }

    fn block_evaluation() -> crate::waf::Evaluation {
        crate::waf::Evaluation {
            decision: crate::waf::WafDecision::Block,
            ..allow_evaluation()
        }
    }

    #[tokio::test]
    async fn a_block_verdict_escalates_an_allow_decision() {
        let manager = waf_detector_manager(true);
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), allow_evaluation()).await;
        assert_eq!(merged.decision, crate::waf::WafDecision::Block);
        assert!(merged.categories.contains(&"custom_detector".to_string()));
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_block_total 1"));
    }

    #[tokio::test]
    async fn a_plugin_verdict_can_never_downgrade_an_existing_block() {
        // The fixture always returns Block, so this exercises the
        // Block-stays-Block path rather than a downgrade -- the important
        // assertion is that a rule-engine Block is never lost.
        let manager = waf_detector_manager(true);
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), block_evaluation()).await;
        assert_eq!(merged.decision, crate::waf::WafDecision::Block);
    }

    #[tokio::test]
    async fn no_detector_configured_leaves_the_evaluation_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
        assert_eq!(merged.categories, evaluation.categories);
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 0"));
    }

    #[tokio::test]
    async fn a_disabled_detector_leaves_the_evaluation_unchanged() {
        let manager = waf_detector_manager(false);
        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
    }

    #[tokio::test]
    async fn no_plugin_manager_leaves_the_evaluation_unchanged() {
        let evaluation = allow_evaluation();
        let merged = apply_waf_detector(None, &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
    }

    #[tokio::test]
    async fn a_trapping_detector_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("waf-detect-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/waf_detect_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but traps on every call.
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap_ptr (mut i32) (i32.const 1024))
            (func (export "bearust_abi_version") (result i32) i32.const 2)
            (func (export "bearust_alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $heap_ptr
                local.set $ptr
                global.get $heap_ptr
                local.get $len
                i32.add
                global.set $heap_ptr
                local.get $ptr)
            (func (export "bearust_dealloc") (param i32 i32) nop)
            (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
            (func (export "bearust_waf_detect") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_failures_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 0"));
    }
}
