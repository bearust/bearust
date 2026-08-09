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
use base64::Engine as _;
use bytes::Bytes;
use pingora_core::{upstreams::peer::HttpPeer, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

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
    pub transform_response_buffering: bool,
    pub transform_response_buffer: Vec<u8>,
    pub transform_response_status: u16,
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
            transform_response_buffering: false,
            transform_response_buffer: Vec::new(),
            transform_response_status: 0,
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

/// Converts the outbound `RequestHeader` into the wire shape a
/// `transform.request` plugin receives. `method`/`path`/`query`/`headers`
/// share a `crate::waf::MAX_NORMALIZED_METADATA_BYTES` budget and each
/// header is additionally capped at `crate::waf::MAX_NORMALIZED_FIELD_BYTES`
/// -- the same bounds `waf_detect_request` enforces on the same kind of raw
/// fields -- so a transform plugin never receives more request metadata
/// than a detector plugin already does. There is no body: this hook only
/// ever sees headers. Pure and side-effect free.
fn transform_request(header: &RequestHeader) -> bearust_plugin_sdk::TransformRequest {
    let mut remaining = crate::waf::MAX_NORMALIZED_METADATA_BYTES;
    let method = bounded_metadata(header.method.as_str(), &mut remaining);
    let path = bounded_metadata(header.uri.path(), &mut remaining);
    let query = bounded_metadata(header.uri.query().unwrap_or(""), &mut remaining);
    let headers = header
        .headers
        .iter()
        .take(crate::waf::MAX_NORMALIZED_HEADERS)
        .map(|(name, value)| {
            (
                bounded_metadata(name.as_str(), &mut remaining),
                bounded_metadata(&String::from_utf8_lossy(value.as_bytes()), &mut remaining),
            )
        })
        .collect();
    bearust_plugin_sdk::TransformRequest {
        method,
        path,
        query,
        headers,
    }
}

/// Framing/hop-by-hop headers a `transform.request` plugin is never allowed
/// to set: unlike `Host`/`X-Forwarded-For`/`X-Request-Id` (reasserted by
/// `upstream_request_filter` after this hook runs), nothing downstream of
/// this function protects these, and pingora's H1 client trusts them
/// literally when framing the upstream request. Letting a plugin control
/// them either silently drops the request body (no `Content-Length` or
/// `Transfer-Encoding` survives the wholesale replace, so pingora frames a
/// zero-length body) or opens a request-smuggling vector (a plugin-supplied
/// `Content-Length` that disagrees with the real body, or a `Connection`/
/// `Upgrade` override that breaks a WebSocket upgrade).
const PROTECTED_FRAMING_HEADERS: [&str; 4] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
];

/// A plugin's returned header list is applied only if it stays within the
/// same bounds `transform_request` enforces on the input side: no more than
/// `MAX_NORMALIZED_HEADERS` entries, and no single name or value longer
/// than `MAX_NORMALIZED_FIELD_BYTES`. Every name/value pair must also be
/// syntactically valid as an HTTP header -- a plugin returning something
/// `http::HeaderName`/`http::HeaderValue` reject would otherwise fail
/// `apply_header` silently, leaving some of the plugin's intended headers
/// applied and others dropped. A plugin that violates any of this has
/// produced malformed output as far as the host is concerned -- the whole
/// transform is rejected (see `apply_transform_plugin`), not partially
/// truncated, so a plugin can't silently have some of its intended headers
/// dropped without warning.
fn is_valid_transform_headers(headers: &[(String, String)]) -> bool {
    headers.len() <= crate::waf::MAX_NORMALIZED_HEADERS
        && headers.iter().all(|(name, value)| {
            name.len() <= crate::waf::MAX_NORMALIZED_FIELD_BYTES
                && value.len() <= crate::waf::MAX_NORMALIZED_FIELD_BYTES
                && http::HeaderName::try_from(name.as_str()).is_ok()
                && http::HeaderValue::try_from(value.as_str()).is_ok()
        })
}

/// Replaces every existing header on `request` with `response`'s headers.
/// The framing headers in `PROTECTED_FRAMING_HEADERS` are exempt: their
/// pre-transform values (if any) are captured before the wipe, any
/// plugin-supplied values for those same names are ignored, and the
/// captured originals are reasserted afterward -- a transform plugin can
/// rewrite every other header but can never touch request framing. The
/// caller has already validated the response's size/count/syntax bounds
/// via `is_valid_transform_headers` before calling this.
fn apply_transform_response(
    request: &mut RequestHeader,
    response: bearust_plugin_sdk::TransformResponse,
) {
    let protected: Vec<(&'static str, Option<http::HeaderValue>)> = PROTECTED_FRAMING_HEADERS
        .iter()
        .map(|&name| (name, request.headers.get(name).cloned()))
        .collect();
    let existing_names: Vec<_> = request.headers.keys().cloned().collect();
    for name in existing_names {
        request.remove_header(&name);
    }
    for (name, value) in response.headers {
        if PROTECTED_FRAMING_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        let _ = request.append_header(name, value);
    }
    for (name, value) in protected {
        if let Some(value) = value {
            let _ = request.insert_header(name, value);
        }
    }
}

/// Runs the registered `transform.request` plugin (if any) against
/// `request`'s current headers and, on success, wholesale-replaces them
/// with the plugin's response. Synchronous from the caller's point of view
/// but offloads the blocking wasmtime call via `spawn_blocking` so it never
/// blocks the shared async runtime. Fails open on every error class: no
/// transformer configured, no plugin currently declaring the capability, a
/// disabled plugin, a trap/timeout/fuel exhaustion, output exceeding the
/// header count/size bounds, a malformed response, or a `spawn_blocking`
/// join failure all leave `request`'s headers untouched (after counting a
/// failure metric where applicable). The caller (`upstream_request_filter`)
/// unconditionally reasserts `Host`/`X-Forwarded-For`/`X-Request-Id` right
/// after this call returns, whether or not a transform was applied, so this
/// function never needs to protect those three headers itself.
async fn apply_transform_plugin(
    plugin_manager: Option<&Arc<PluginManager>>,
    request: &mut RequestHeader,
) {
    let Some(manager) = plugin_manager else {
        return;
    };
    let Some(transformer) = manager.transform_plugin() else {
        return;
    };
    let metrics = manager.metrics();
    metrics.record_transform_invocation();
    let input = transform_request(request);
    let outcome = tokio::task::spawn_blocking(move || transformer.transform(&input)).await;
    match outcome {
        Ok(Ok(response)) if is_valid_transform_headers(&response.headers) => {
            apply_transform_response(request, response);
            metrics.record_transform_applied();
        }
        Ok(Ok(_)) => {
            tracing::warn!(
                event = "transform_request_failed",
                reason = "output_bounds_exceeded"
            );
            metrics.record_transform_failure();
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "transform_request_failed", reason = error.code());
            metrics.record_transform_failure();
        }
        Err(_join_error) => {
            tracing::warn!(event = "transform_request_failed", reason = "join_error");
            metrics.record_transform_failure();
        }
    }
}

/// Response bodies larger than this are never handed to a
/// `transform.response` plugin -- fail open to unmodified passthrough
/// instead. Bounds per-request proxy memory from a single large upstream
/// response; matches the design spec's chosen cap for BeaRust's typical
/// API/JSON/HTML traffic.
const RESPONSE_BODY_TRANSFORM_CAP_BYTES: usize = 1024 * 1024;

/// Whether `response`'s body should be buffered for a `transform.response`
/// plugin. Every one of the following must hold; the check is pure and
/// side-effect free:
///
/// - a plugin is enabled and currently declaring `transform.response`;
/// - `Content-Encoding` is absent, empty, or `identity` -- a plugin would
///   otherwise receive opaque compressed bytes it cannot meaningfully
///   transform, and could be misused to launder a compressed payload past
///   any future response inspection;
/// - the status is not informational (`1xx`, which includes `101 Switching
///   Protocols`): an upgraded connection's frames arrive through this same
///   body filter as `HttpTask::UpgradedBody`, and buffering them would
///   swallow WebSocket traffic instead of streaming it;
/// - the status is neither `204 No Content` nor `304 Not Modified`, which
///   carry no body at all -- stripping their framing headers is pointless;
/// - the downstream request method is not `HEAD`, whose response describes
///   what a `GET` would return but carries no body, so its `Content-Length`
///   is meaningful to size-probing clients and must be left intact;
/// - `Content-Type` is not `text/event-stream` (case-insensitive): a
///   long-lived stream's events would be withheld until the 1 MiB buffer
///   cap or the connection's end, defeating the point of streaming.
fn should_buffer_response_for_transform(
    plugin_manager: Option<&Arc<PluginManager>>,
    method: &http::Method,
    response: &ResponseHeader,
) -> bool {
    let Some(manager) = plugin_manager else {
        return false;
    };
    if manager.transform_response_plugin().is_none() {
        return false;
    }
    if method == http::Method::HEAD {
        return false;
    }
    let status = response.status;
    if status.is_informational()
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
    {
        return false;
    }
    if response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
    {
        return false;
    }
    match response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
    {
        None => true,
        Some(value) => value.is_empty() || value.eq_ignore_ascii_case("identity"),
    }
}

/// Accumulates `chunk` into `ctx`'s response body buffer, bounded by
/// `RESPONSE_BODY_TRANSFORM_CAP_BYTES`. Returns `Some(overflow_bytes)` if
/// the cap was exceeded -- the combined prefix-so-far plus this chunk,
/// ready to be emitted as-is -- with `ctx.transform_response_buffering`
/// left `false` (buffering aborted, no further chunks are accumulated).
/// Returns `None` if the chunk fit within the cap (buffering continues,
/// nothing should be emitted yet).
fn accumulate_response_chunk(ctx: &mut RequestContext, chunk: &[u8]) -> Option<Vec<u8>> {
    let remaining =
        RESPONSE_BODY_TRANSFORM_CAP_BYTES.saturating_sub(ctx.transform_response_buffer.len());
    if chunk.len() > remaining {
        ctx.transform_response_buffer.extend_from_slice(chunk);
        ctx.transform_response_buffering = false;
        return Some(std::mem::take(&mut ctx.transform_response_buffer));
    }
    ctx.transform_response_buffer.extend_from_slice(chunk);
    None
}

/// Runs the registered `transform.response` plugin (if any) against the
/// fully buffered response `body` and returns its replacement on success,
/// or `body` unchanged on any failure. Synchronous from the caller's point
/// of view -- `response_body_filter` is not an `async fn`, unlike the
/// request-side hooks -- but offloads the blocking wasmtime call via
/// `tokio::task::block_in_place` so it never stalls the calling worker
/// thread's other queued tasks the way a bare synchronous call would.
/// Fails open on every error class: no plugin manager, no plugin currently
/// declaring the capability, a disabled plugin, a trap/timeout/fuel
/// exhaustion, a malformed or oversized output body, a base64 decode
/// failure, or a `block_in_place` panic all return `body` unchanged (after
/// counting a failure metric where applicable).
///
/// Load-bearing runtime assumption: `block_in_place` is only valid on a
/// real multi-thread tokio runtime. BeaRust's pingora `Server` is created
/// in `src/cli.rs` with no config override for `work_stealing`, which
/// defaults to enabled and backs the server with a multi-thread runtime.
/// If that default ever changes to a `NoSteal`/current-thread flavor,
/// `block_in_place` would panic on every call -- caught by the
/// `catch_unwind` below, so it degrades to fail-open plus a failure
/// counter rather than crashing, but the capability would be effectively
/// disabled and would need a `spawn_blocking`-style offload instead.
fn apply_transform_response_plugin(
    plugin_manager: Option<&Arc<PluginManager>>,
    status: u16,
    body: Vec<u8>,
) -> Vec<u8> {
    let Some(manager) = plugin_manager else {
        return body;
    };
    let Some(transformer) = manager.transform_response_plugin() else {
        return body;
    };
    let metrics = manager.metrics();
    metrics.record_transform_response_invocation();
    let request = bearust_plugin_sdk::TransformResponseRequest {
        status,
        body: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::task::block_in_place(|| transformer.transform_response(&request))
    }));
    match outcome {
        Ok(Ok(response)) => {
            match base64::engine::general_purpose::STANDARD.decode(&response.body) {
                Ok(decoded) if decoded.len() <= RESPONSE_BODY_TRANSFORM_CAP_BYTES => {
                    metrics.record_transform_response_applied();
                    decoded
                }
                Ok(_) => {
                    tracing::warn!(
                        event = "transform_response_failed",
                        reason = "output_bounds_exceeded"
                    );
                    metrics.record_transform_response_failure();
                    body
                }
                Err(_) => {
                    tracing::warn!(
                        event = "transform_response_failed",
                        reason = "invalid_base64"
                    );
                    metrics.record_transform_response_failure();
                    body
                }
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "transform_response_failed", reason = error.code());
            metrics.record_transform_response_failure();
            body
        }
        Err(_panic) => {
            tracing::warn!(event = "transform_response_failed", reason = "panic");
            metrics.record_transform_response_failure();
            body
        }
    }
}

/// Reasserts the three headers `upstream_request_filter` guarantees a
/// `transform.request` plugin can never drop, blank, or spoof: `Host`
/// (the downstream's own value, or removed entirely if the downstream sent
/// none -- never a plugin-supplied value), `X-Forwarded-For` (rebuilt from
/// `pre_transform_forwarded_for` -- the downstream's value captured before
/// the transform ran -- plus the real client address, never the plugin's
/// post-transform value), and `X-Request-Id`. Takes plain values rather
/// than a `Session` so it can be unit-tested against an adversarial
/// `request` header without constructing a full pingora `Session`.
fn reassert_protected_request_headers(
    request: &mut RequestHeader,
    pre_transform_forwarded_for: Option<&str>,
    downstream_host: Option<&str>,
    client_addr: Option<&str>,
    request_id: &str,
) {
    match downstream_host {
        Some(host) => {
            let _ = request.insert_header("Host", host);
        }
        None => {
            request.remove_header("host");
        }
    }
    match pre_transform_forwarded_for {
        Some(value) => {
            let _ = request.insert_header("X-Forwarded-For", value);
        }
        None => {
            request.remove_header("x-forwarded-for");
        }
    }
    append_forwarded_for(request, client_addr);
    let _ = request.insert_header("X-Request-Id", request_id.to_owned());
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
        // Captured before the transform runs so a plugin can never make its
        // own spoofed X-Forwarded-For survive: whatever the plugin returns
        // for that name is discarded in `reassert_protected_request_headers`
        // below, regardless of whether the downstream request had one.
        let pre_transform_forwarded_for = request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        apply_transform_plugin(self.plugin_manager.as_ref(), request).await;
        let downstream_host = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        reassert_protected_request_headers(
            request,
            pre_transform_forwarded_for.as_deref(),
            downstream_host.as_deref(),
            session.client_addr().map(ToString::to_string).as_deref(),
            &ctx.request_id,
        );
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

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let method = session.req_header().method.clone();
        if should_buffer_response_for_transform(
            self.plugin_manager.as_ref(),
            &method,
            upstream_response,
        ) {
            // The transformed body's length is not known until
            // `end_of_stream`, so the response must be chunk-framed. Set
            // that framing explicitly rather than relying on pingora's
            // auto-chunk step: that check runs earlier in the H1 pipeline,
            // *before* this hook, and sees the upstream `Content-Length`
            // still present, so it declines to add `Transfer-Encoding`.
            // Removing `Content-Length` on its own would leave the response
            // with neither header -- close-delimited framing, which kills
            // downstream keep-alive. On an HTTP/2 downstream this is
            // harmless: h2 strips `Transfer-Encoding` before writing
            // headers regardless.
            upstream_response.set_version(http::Version::HTTP_11);
            upstream_response.remove_header("content-length");
            let _ = upstream_response.insert_header("transfer-encoding", "chunked");
            ctx.transform_response_buffering = true;
            ctx.transform_response_status = upstream_response.status.as_u16();
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if !ctx.transform_response_buffering {
            return Ok(None);
        }
        if let Some(chunk) = body.take() {
            if let Some(overflow) = accumulate_response_chunk(ctx, &chunk) {
                *body = Some(Bytes::from(overflow));
                return Ok(None);
            }
        }
        if end_of_stream {
            let buffer = std::mem::take(&mut ctx.transform_response_buffer);
            ctx.transform_response_buffering = false;
            // An empty body has nothing to transform; skip the wasm
            // instantiation entirely (redirects, empty 200s, ...).
            *body = Some(if buffer.is_empty() {
                Bytes::new()
            } else {
                Bytes::from(apply_transform_response_plugin(
                    self.plugin_manager.as_ref(),
                    ctx.transform_response_status,
                    buffer,
                ))
            });
        }
        Ok(None)
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
    use super::{
        accumulate_response_chunk, apply_transform_plugin, apply_transform_response_plugin,
        apply_waf_detector, error_status, invoke_analytics_changed, is_valid_transform_headers,
        reassert_protected_request_headers, should_buffer_response_for_transform, waf_block_event,
        RequestContext, RESPONSE_BODY_TRANSFORM_CAP_BYTES,
    };
    use pingora_core::{Error, ErrorType};
    use pingora_http::{RequestHeader, ResponseHeader};
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

    fn transform_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-request-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_request_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/transform_request_v2/transform_request_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("transform-request-v2", false).unwrap();
        }
        manager
    }

    fn sample_request_header() -> RequestHeader {
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        header.insert_header("Host", "example.com").unwrap();
        header
    }

    #[tokio::test]
    async fn a_successful_transform_replaces_the_header_list() {
        let manager = transform_manager(true);
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("x-transformed").unwrap(), "yes");
        // The plugin's fixed response does not include Host -- it is only
        // reasserted by upstream_request_filter's own code, which this unit
        // test does not call, so it is correctly absent here.
        assert!(header.headers.get("host").is_none());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_invocations_total 1"));
        assert!(output.contains("bearust_plugins_transform_applied_total 1"));
    }

    #[tokio::test]
    async fn no_transformer_configured_leaves_headers_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_invocations_total 0"));
    }

    #[tokio::test]
    async fn a_disabled_transformer_leaves_headers_unchanged() {
        let manager = transform_manager(false);
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
    }

    #[tokio::test]
    async fn no_plugin_manager_leaves_headers_unchanged() {
        let mut header = sample_request_header();
        apply_transform_plugin(None, &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
    }

    #[tokio::test]
    async fn a_trapping_transformer_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-request-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_request_v2/plugin.toml"),
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
            (func (export "bearust_transform_request") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_failures_total 1"));
        assert!(output.contains("bearust_plugins_transform_applied_total 0"));
    }

    #[test]
    fn oversized_header_count_is_rejected_as_invalid() {
        let headers: Vec<(String, String)> = (0..(crate::waf::MAX_NORMALIZED_HEADERS + 1))
            .map(|i| (format!("x-h{i}"), "v".to_string()))
            .collect();
        assert!(!is_valid_transform_headers(&headers));
    }

    #[test]
    fn header_field_exceeding_the_per_field_bound_is_rejected_as_invalid() {
        let headers = vec![(
            "x-big".to_string(),
            "a".repeat(crate::waf::MAX_NORMALIZED_FIELD_BYTES + 1),
        )];
        assert!(!is_valid_transform_headers(&headers));
    }

    #[test]
    fn ordinary_headers_are_valid() {
        let headers = vec![("host".to_string(), "example.com".to_string())];
        assert!(is_valid_transform_headers(&headers));
    }

    #[test]
    fn a_header_with_invalid_http_syntax_is_rejected_as_invalid() {
        let headers = vec![("x-bad\nname".to_string(), "value".to_string())];
        assert!(!is_valid_transform_headers(&headers));
        let headers = vec![("x-bad".to_string(), "va\nlue".to_string())];
        assert!(!is_valid_transform_headers(&headers));
    }

    fn spoofing_transform_manager() -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-request-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_request_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but returns a payload that
        // tries to spoof Host/X-Forwarded-For/X-Request-Id and hijack
        // request framing (Content-Length/Transfer-Encoding/Connection).
        // WAT string literals use `\22` for an embedded `"` -- this is the
        // JSON `{"headers":[["x-transformed","yes"],["host","evil.internal"],
        // ["x-forwarded-for","10.0.0.1"],["x-request-id","spoofed"],
        // ["content-length","5"],["transfer-encoding","chunked"],
        // ["connection","close"]]}` (198 bytes unescaped).
        let json = concat!(
            "{\\22headers\\22:[[\\22x-transformed\\22,\\22yes\\22],",
            "[\\22host\\22,\\22evil.internal\\22],",
            "[\\22x-forwarded-for\\22,\\2210.0.0.1\\22],",
            "[\\22x-request-id\\22,\\22spoofed\\22],",
            "[\\22content-length\\22,\\225\\22],",
            "[\\22transfer-encoding\\22,\\22chunked\\22],",
            "[\\22connection\\22,\\22close\\22]]}"
        );
        let wat = format!(
            r#"(module
            (memory (export "memory") 1)
            (global $heap_ptr (mut i32) (i32.const 1024))
            (data (i32.const 0) "{json}")
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
            (func (export "bearust_transform_request") (param i32 i32) (result i64)
                (i64.or
                    (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                    (i64.extend_i32_u (i32.const 198)))))"#
        );
        let module = wat::parse_str(&wat).unwrap();
        fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        manager
    }

    /// Regression test for the design's acceptance gate: Host,
    /// X-Forwarded-For, X-Request-Id, and request framing headers are
    /// always present and correct after the transform hook runs, even when
    /// a fixture plugin deliberately tries to drop or spoof them.
    #[tokio::test]
    async fn reassert_protected_request_headers_defeats_a_spoofing_transform() {
        let manager = spoofing_transform_manager();
        let mut header = sample_request_header();
        header
            .insert_header("x-forwarded-for", "203.0.113.9")
            .unwrap();
        header.insert_header("content-length", "42").unwrap();

        let pre_transform_forwarded_for = header
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        apply_transform_plugin(Some(&manager), &mut header).await;
        // `apply_transform_response` itself already protects framing
        // headers: the plugin's spoofed content-length/transfer-encoding/
        // connection never make it into `header` at all, restored to their
        // pre-transform values (or absent, if they were absent before) --
        // this is defense-in-depth, independent of the caller's
        // reassertion pass below. Host/X-Forwarded-For/X-Request-Id are
        // *not* protected at this layer, so the plugin's spoofed values are
        // visible here until `reassert_protected_request_headers` runs.
        assert_eq!(header.headers.get("host").unwrap(), "evil.internal");
        assert_eq!(header.headers.get("content-length").unwrap(), "42");
        assert!(header.headers.get("transfer-encoding").is_none());
        assert!(header.headers.get("connection").is_none());

        reassert_protected_request_headers(
            &mut header,
            pre_transform_forwarded_for.as_deref(),
            Some("example.com"),
            Some("198.51.100.7"),
            "req-123",
        );

        assert_eq!(header.headers.get("host").unwrap(), "example.com");
        assert_eq!(
            header.headers.get("x-forwarded-for").unwrap(),
            "203.0.113.9, 198.51.100.7"
        );
        assert_eq!(header.headers.get("x-request-id").unwrap(), "req-123");
        // Framing headers are still exactly the pre-transform original --
        // untouched by the reassertion pass, which only handles the other
        // three names.
        assert_eq!(header.headers.get("content-length").unwrap(), "42");
        assert!(header.headers.get("transfer-encoding").is_none());
        assert!(header.headers.get("connection").is_none());
        // Untouched, ordinary headers the plugin legitimately returned are
        // still applied.
        assert_eq!(header.headers.get("x-transformed").unwrap(), "yes");
    }

    #[test]
    fn reassert_protected_request_headers_removes_host_and_xff_when_downstream_had_none() {
        let mut header = sample_request_header();
        header.insert_header("host", "attacker-controlled").unwrap();
        header
            .insert_header("x-forwarded-for", "attacker-controlled")
            .unwrap();
        reassert_protected_request_headers(&mut header, None, None, None, "req-456");
        assert!(header.headers.get("host").is_none());
        assert!(header.headers.get("x-forwarded-for").is_none());
        assert_eq!(header.headers.get("x-request-id").unwrap(), "req-456");
    }

    fn transform_response_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-response-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_response_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/transform_response_v2/transform_response_v2.wat"
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
        if !enabled {
            manager.set_enabled("transform-response-v2", false).unwrap();
        }
        manager
    }

    fn sample_response_header(status: u16) -> ResponseHeader {
        ResponseHeader::build(status, None).unwrap()
    }

    #[test]
    fn eligible_when_a_transformer_is_enabled_and_no_content_encoding() {
        let manager = transform_response_manager(true);
        let response = sample_response_header(200);
        assert!(should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn eligible_when_content_encoding_is_identity() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response
            .insert_header("content-encoding", "identity")
            .unwrap();
        assert!(should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn eligible_for_an_ordinary_json_content_type() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response
            .insert_header("content-type", "application/json; charset=utf-8")
            .unwrap();
        assert!(should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_without_a_plugin_manager() {
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(
            None,
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_when_no_transformer_is_configured() {
        let manager = PluginManager::new(PluginConfig::default());
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_when_the_transformer_is_disabled() {
        let manager = transform_response_manager(false);
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_when_the_response_is_compressed() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response.insert_header("content-encoding", "gzip").unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_when_the_response_is_a_websocket_upgrade() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(101);
        response.insert_header("upgrade", "websocket").unwrap();
        response.insert_header("connection", "Upgrade").unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_for_other_informational_responses() {
        let manager = transform_response_manager(true);
        let response = sample_response_header(100);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_for_a_no_content_response() {
        let manager = transform_response_manager(true);
        let response = sample_response_header(204);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_for_a_not_modified_response() {
        let manager = transform_response_manager(true);
        let response = sample_response_header(304);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_for_a_head_request() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response.insert_header("content-length", "512").unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::HEAD,
            &response
        ));
    }

    #[test]
    fn ineligible_for_a_server_sent_event_stream() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response
            .insert_header("content-type", "text/event-stream")
            .unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn ineligible_for_a_server_sent_event_stream_with_mixed_case_and_parameters() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response
            .insert_header("content-type", "Text/Event-Stream; charset=utf-8")
            .unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &http::Method::GET,
            &response
        ));
    }

    #[test]
    fn accumulate_response_chunk_appends_within_cap() {
        let mut ctx = RequestContext {
            transform_response_buffering: true,
            ..RequestContext::default()
        };
        let overflow = accumulate_response_chunk(&mut ctx, b"hello");
        assert!(overflow.is_none());
        assert_eq!(ctx.transform_response_buffer, b"hello");
        assert!(ctx.transform_response_buffering);
    }

    #[test]
    fn accumulate_response_chunk_aborts_buffering_past_the_cap() {
        let mut ctx = RequestContext {
            transform_response_buffering: true,
            transform_response_buffer: vec![0u8; RESPONSE_BODY_TRANSFORM_CAP_BYTES - 2],
            ..RequestContext::default()
        };
        let overflow = accumulate_response_chunk(&mut ctx, b"abcd").expect("chunk exceeds the cap");
        assert_eq!(overflow.len(), RESPONSE_BODY_TRANSFORM_CAP_BYTES - 2 + 4);
        assert!(!ctx.transform_response_buffering);
        assert!(ctx.transform_response_buffer.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_successful_response_transform_replaces_the_body() {
        let manager = transform_response_manager(true);
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"hello");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_invocations_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 1"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_response_transformer_configured_leaves_body_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_invocations_total 0"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_response_transformer_leaves_body_unchanged() {
        let manager = transform_response_manager(false);
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
    }

    #[test]
    fn no_plugin_manager_leaves_response_body_unchanged() {
        let body = apply_transform_response_plugin(None, 200, b"original".to_vec());
        assert_eq!(body, b"original");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_trapping_response_transformer_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-response-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_response_v2/plugin.toml"),
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
            (func (export "bearust_transform_response") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            max_output_bytes: 2 * 1024 * 1024,
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_failures_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 0"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invalid_base64_response_body_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-response-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_response_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but its fixed JSON literal
        // `{"body":"!!!not-valid-base64!!!"}` (33 bytes) carries a body
        // field that is well-formed JSON yet not decodable base64.
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap_ptr (mut i32) (i32.const 1024))
            (data (i32.const 0) "{\22body\22:\22!!!not-valid-base64!!!\22}")
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
            (func (export "bearust_transform_response") (param i32 i32) (result i64)
                (i64.or
                    (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                    (i64.extend_i32_u (i32.const 33)))))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            max_output_bytes: 2 * 1024 * 1024,
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_failures_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 0"));
    }
}
