use bearust::{
    analytics::{AnalyticsCollector, AnalyticsEvent, SecurityCounters},
    analytics_prometheus::{render, PrometheusConfig},
};
use chrono::Utc;

#[test]
fn prometheus_is_disabled_by_default_and_has_stable_names() {
    let cfg = PrometheusConfig::default();
    assert!(!cfg.enabled);
    let c = AnalyticsCollector::default();
    c.record(AnalyticsEvent {
        proxy_host_id: 7,
        timestamp: Utc::now(),
        status_code: 503,
        latency_ms: 42,
        security: SecurityCounters {
            rate_limited: 1,
            ..Default::default()
        },
    });
    let out = render(&c.snapshot(), &cfg).unwrap();
    assert!(out.contains("bearust_requests_total"));
    assert!(out.contains("bearust_request_duration_ms"));
    assert!(out.contains("bearust_security_events_total"));
    assert!(out.contains("bearust_rate_limit_events_total"));
}

#[test]
fn prometheus_escapes_labels_and_caps_output() {
    let c = AnalyticsCollector::default();
    let cfg = PrometheusConfig {
        enabled: true,
        max_output_bytes: 128,
        ..Default::default()
    };
    let out = render(&c.snapshot(), &cfg).unwrap();
    assert!(out.len() <= 128);
}

#[test]
fn prometheus_internal_mode_requires_loopback_bind() {
    let cfg = PrometheusConfig {
        enabled: true,
        bind: "0.0.0.0:9090".parse().unwrap(),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}
