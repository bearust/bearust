use pingora_http::RequestHeader;
use std::sync::atomic::{AtomicU64, Ordering};

pub type InitError = Box<dyn std::error::Error + Send + Sync>;

/// Bounded, provider-agnostic AI advisor counters for operational dashboards.
/// Labels are fixed enum values; request text, user IDs, model names, and
/// provider responses are intentionally never accepted here.
#[derive(Debug, Default)]
pub struct AdvisorMetrics {
    queued: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    breaker_open: AtomicU64,
    approved: AtomicU64,
    rejected: AtomicU64,
}

/// Fixed-cardinality metrics for plugin lifecycle operations. Plugin IDs and
/// runtime details are intentionally not represented as labels.
#[derive(Debug, Default)]
pub struct PluginMetrics {
    reload_success: AtomicU64,
    reload_failure: AtomicU64,
    enable_success: AtomicU64,
    enable_failure: AtomicU64,
    disable_success: AtomicU64,
    disable_failure: AtomicU64,
    unload_success: AtomicU64,
    unload_failure: AtomicU64,
    health_check_success: AtomicU64,
    health_check_failure: AtomicU64,
    loaded: AtomicU64,
    notify_invocations: AtomicU64,
    notify_failures: AtomicU64,
    notify_dropped: AtomicU64,
    waf_detect_invocations: AtomicU64,
    waf_detect_block: AtomicU64,
    waf_detect_failures: AtomicU64,
}

impl PluginMetrics {
    pub fn record_operation(&self, operation: &str, outcome: &str) {
        let counter = match (operation, outcome) {
            ("reload", "success") => &self.reload_success,
            ("reload", "failure") => &self.reload_failure,
            ("enable", "success") => &self.enable_success,
            ("enable", "failure") => &self.enable_failure,
            ("disable", "success") => &self.disable_success,
            ("disable", "failure") => &self.disable_failure,
            ("unload", "success") => &self.unload_success,
            ("unload", "failure") => &self.unload_failure,
            ("health_check", "success") => &self.health_check_success,
            ("health_check", "failure") => &self.health_check_failure,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_loaded(&self, loaded: usize) {
        self.loaded.store(loaded as u64, Ordering::Relaxed);
    }

    /// The registered `notify.waf_block` sink returned status `0`.
    pub fn record_notify_invocation(&self) {
        self.notify_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// The registered sink returned a nonzero status, trapped, timed out,
    /// exhausted its fuel, or had a malformed export — any outcome other
    /// than a clean `0` return.
    pub fn record_notify_failure(&self) {
        self.notify_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A WAF-block event was dropped because the notification queue was
    /// full.
    pub fn record_notify_dropped(&self) {
        self.notify_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// A `waf.detect` plugin call completed successfully (any decision,
    /// including `Allow`).
    pub fn record_waf_detect_invocation(&self) {
        self.waf_detect_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// A `waf.detect` plugin verdict actually changed the merged
    /// `Evaluation`'s decision (an escalation occurred).
    pub fn record_waf_detect_block(&self) {
        self.waf_detect_block.fetch_add(1, Ordering::Relaxed);
    }

    /// A `waf.detect` plugin call failed: trap, timeout, fuel exhaustion,
    /// malformed export/output, or a `spawn_blocking` join failure.
    pub fn record_waf_detect_failure(&self) {
        self.waf_detect_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let samples = [
            ("reload", "success", &self.reload_success),
            ("reload", "failure", &self.reload_failure),
            ("enable", "success", &self.enable_success),
            ("enable", "failure", &self.enable_failure),
            ("disable", "success", &self.disable_success),
            ("disable", "failure", &self.disable_failure),
            ("unload", "success", &self.unload_success),
            ("unload", "failure", &self.unload_failure),
            ("health_check", "success", &self.health_check_success),
            ("health_check", "failure", &self.health_check_failure),
        ];
        let mut output = String::from("# TYPE bearust_plugins_operations_total counter\n");
        for (operation, outcome, value) in samples {
            output.push_str(&format!(
                "bearust_plugins_operations_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {}\n",
                value.load(Ordering::Relaxed)
            ));
        }
        output.push_str("# TYPE bearust_plugins_loaded gauge\n");
        output.push_str(&format!(
            "bearust_plugins_loaded {}\n",
            self.loaded.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_notify_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_invocations_total {}\n",
            self.notify_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_notify_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_failures_total {}\n",
            self.notify_failures.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_notify_dropped_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_dropped_total {}\n",
            self.notify_dropped.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_waf_detect_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_invocations_total {}\n",
            self.waf_detect_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_waf_detect_block_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_block_total {}\n",
            self.waf_detect_block.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_waf_detect_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_failures_total {}\n",
            self.waf_detect_failures.load(Ordering::Relaxed)
        ));
        output
    }
}

impl AdvisorMetrics {
    pub fn record_job(&self, status: &str) {
        match status {
            "queued" => self.queued.fetch_add(1, Ordering::Relaxed),
            "completed" => self.completed.fetch_add(1, Ordering::Relaxed),
            "failed" => self.failed.fetch_add(1, Ordering::Relaxed),
            "breaker_open" => self.breaker_open.fetch_add(1, Ordering::Relaxed),
            "approved" => self.approved.fetch_add(1, Ordering::Relaxed),
            "rejected" => self.rejected.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# TYPE bearust_ai_advisor_jobs_total counter\n\
bearust_ai_advisor_jobs_total{{status=\"queued\"}} {}\n\
bearust_ai_advisor_jobs_total{{status=\"completed\"}} {}\n\
bearust_ai_advisor_jobs_total{{status=\"failed\"}} {}\n\
bearust_ai_advisor_jobs_total{{status=\"breaker_open\"}} {}\n\
# TYPE bearust_ai_advisor_approval_total counter\n\
bearust_ai_advisor_approval_total{{decision=\"approved\"}} {}\n\
bearust_ai_advisor_approval_total{{decision=\"rejected\"}} {}\n",
            self.queued.load(Ordering::Relaxed),
            self.completed.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.breaker_open.load(Ordering::Relaxed),
            self.approved.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
        )
    }
}

pub fn init(json: bool, filter: &str) -> Result<(), InitError> {
    let filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    }
}

pub fn classify_error(error: &pingora_core::Error) -> &'static str {
    use pingora_core::{ErrorSource, ErrorType};

    // Preserve the explicit routing failure emitted when a pool has no
    // eligible backends.  This is more actionable than a generic upstream
    // category and must not depend on the error context string.
    if matches!(error.etype(), ErrorType::HTTPStatus(503)) {
        return "no_healthy_upstream";
    }

    // Pingora has distinct timeout variants for each phase.  Treat all of
    // them uniformly, regardless of the source attached by the callback.
    if matches!(
        error.etype(),
        ErrorType::ConnectTimedout
            | ErrorType::TLSHandshakeTimedout
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
    ) {
        return "timeout";
    }

    // ErrorSource is the authoritative attribution for errors created by
    // Pingora's proxy pipeline.  It avoids leaking or parsing free-form
    // error context and keeps the log contract stable across releases.
    match &error.esource {
        ErrorSource::Downstream => return "client",
        ErrorSource::Upstream => return "upstream",
        ErrorSource::Internal => return "internal",
        ErrorSource::Unset => {}
    }

    // For errors without an explicit source, use only the typed variant as a
    // conservative fallback.  Connection failures retain their dedicated
    // category; HTTP/read/write failures are upstream-facing; everything
    // else is internal.
    match error.etype() {
        ErrorType::ConnectRefused
        | ErrorType::ConnectNoRoute
        | ErrorType::ConnectError
        | ErrorType::ConnectProxyFailure => "connect",
        ErrorType::HTTPStatus(_)
        | ErrorType::ReadError
        | ErrorType::WriteError
        | ErrorType::ConnectionClosed => "upstream",
        _ => "internal",
    }
}

pub fn validated_request_id(value: Option<&[u8]>) -> String {
    let valid = value
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-:_.".contains(&b))
        });
    valid.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned)
}

pub fn append_forwarded_for(request: &mut RequestHeader, client: Option<&str>) {
    if let Some(client) = client {
        let client = client
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| client.trim_matches(['[', ']']).to_owned());
        let value = request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!("{v}, {client}"))
            .unwrap_or(client);
        let _ = request.insert_header("X-Forwarded-For", value);
    }
    let _ = request.insert_header("X-Forwarded-Proto", "http");
}

#[allow(clippy::too_many_arguments)]
pub fn log_request(
    request_id: &str,
    method: &str,
    path: &str,
    route: &str,
    upstream: &str,
    status: u16,
    duration_ms: u64,
    error_category: &str,
) {
    tracing::info!(
        event = "request_complete",
        request_id,
        method,
        path,
        route,
        upstream,
        status,
        latency_ms = duration_ms,
        error_category,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::{Error, ErrorType};
    #[test]
    fn accepts_only_bounded_safe_request_ids() {
        assert_eq!(validated_request_id(Some(b"abc-123:_.")), "abc-123:_.");
        assert_ne!(validated_request_id(Some(b"has space")), "has space");
        assert_ne!(validated_request_id(Some(&[b'a'; 129])), "a".repeat(129));
    }

    #[test]
    fn appends_ip_without_port_and_preserves_chain() {
        let mut request = RequestHeader::build("GET", b"/", Some(2)).unwrap();
        request
            .insert_header("X-Forwarded-For", "10.0.0.1")
            .unwrap();
        append_forwarded_for(&mut request, Some("[2001:db8::1]:8443"));
        assert_eq!(
            request.headers.get("x-forwarded-for").unwrap(),
            "10.0.0.1, 2001:db8::1"
        );
        assert_eq!(request.headers.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn classifies_pingora_errors_into_stable_categories() {
        let error = Error::explain(ErrorType::ConnectError, "dial failed");
        assert_eq!(classify_error(&error), "connect");
        let error = Error::explain(ErrorType::HTTPStatus(503), "no healthy upstream");
        assert_eq!(classify_error(&error), "no_healthy_upstream");
    }

    #[test]
    fn advisor_metrics_use_only_fixed_labels() {
        let metrics = AdvisorMetrics::default();
        metrics.record_job("queued");
        metrics.record_job("approved");
        metrics.record_job("user-controlled-value");
        let output = metrics.render_prometheus();
        assert!(output.contains("status=\"queued\""));
        assert!(output.contains("decision=\"approved\""));
        assert!(!output.contains("user-controlled-value"));
    }

    #[test]
    fn notify_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_notify_invocation();
        metrics.record_notify_invocation();
        metrics.record_notify_failure();
        metrics.record_notify_dropped();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 2"));
        assert!(output.contains("bearust_plugins_notify_failures_total 1"));
        assert!(output.contains("bearust_plugins_notify_dropped_total 1"));
    }

    #[test]
    fn waf_detect_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_waf_detect_invocation();
        metrics.record_waf_detect_invocation();
        metrics.record_waf_detect_block();
        metrics.record_waf_detect_failure();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 2"));
        assert!(output.contains("bearust_plugins_waf_detect_block_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_failures_total 1"));
    }
}
