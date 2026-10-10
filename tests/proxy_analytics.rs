use bearust::{
    analytics::{AnalyticsCollector, AnalyticsFilter},
    config::{Config, ServerConfig},
    proxy::{analytics_security_counters, completion_event, BearustProxy},
    runtime::{RuntimeSnapshot, RuntimeStore},
};
use std::sync::Arc;

#[test]
fn proxy_builder_accepts_analytics_collector() {
    let snapshot = RuntimeSnapshot::build(
        Config {
            server: ServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                control_bind: "127.0.0.1:0".parse().unwrap(),
                control_database: "target/test.sqlite".into(),
                certificate_store: "target/test-certs".into(),
                graceful_shutdown_seconds: 1,
                pid_file: "target/test.pid".into(),
                tls: None,
                http3: Default::default(),
                trusted_proxy_cidrs: Vec::new(),
                geoip_database: None,
                https_bind: None,
                https_public_port: None,
            },
            health: Default::default(),
            upstream_pools: Vec::new(),
            routes: Vec::new(),
            rate_limit: Default::default(),
            prometheus: Default::default(),
            cluster: Default::default(),
            plugins: Default::default(),
        },
        None,
    )
    .unwrap();
    let collector = Arc::new(AnalyticsCollector::default());
    let _proxy = BearustProxy::new(Arc::new(RuntimeStore::new(snapshot)))
        .with_analytics(Arc::clone(&collector));
    assert_eq!(collector.summary(AnalyticsFilter::default()).requests, 0);
}

#[test]
fn completion_records_status_latency_and_bot_block() {
    let collector = Arc::new(AnalyticsCollector::default());
    let security = analytics_security_counters(false, true, false, false);
    collector.record(completion_event(42, 403, 137, security));

    let summary = collector.summary(AnalyticsFilter {
        proxy_host_id: Some(42),
        ..Default::default()
    });
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.status_4xx, 1);
    assert_eq!(summary.bot_blocks, 1);
    assert_eq!(summary.bot_challenges, 0);
    assert_eq!(summary.p50_ms, Some(250));
}

#[test]
fn analytics_event_path_is_fail_open_without_collector() {
    // Proxy requests are allowed to proceed when analytics is not configured;
    // the builder must remain usable and no collector is required on the hot path.
    let snapshot = RuntimeSnapshot::build(
        Config {
            server: ServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                control_bind: "127.0.0.1:0".parse().unwrap(),
                control_database: "target/test.sqlite".into(),
                certificate_store: "target/test-certs".into(),
                graceful_shutdown_seconds: 1,
                pid_file: "target/test.pid".into(),
                tls: None,
                http3: Default::default(),
                trusted_proxy_cidrs: Vec::new(),
                geoip_database: None,
                https_bind: None,
                https_public_port: None,
            },
            health: Default::default(),
            upstream_pools: Vec::new(),
            routes: Vec::new(),
            rate_limit: Default::default(),
            prometheus: Default::default(),
            cluster: Default::default(),
            plugins: Default::default(),
        },
        None,
    )
    .unwrap();
    let _proxy = BearustProxy::new(Arc::new(RuntimeStore::new(snapshot)));
}
