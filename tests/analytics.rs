use bearust::analytics::{
    AnalyticsCollector, AnalyticsDimensionEvent, AnalyticsEvent, AnalyticsFilter, SecurityCounters,
};
use chrono::{TimeZone, Utc};

fn event(host: i64, minute: i64, status: u16, latency: u64) -> AnalyticsEvent {
    AnalyticsEvent {
        proxy_host_id: host,
        timestamp: Utc.timestamp_opt(minute * 60, 0).unwrap(),
        status_code: status,
        latency_ms: latency,
        security: SecurityCounters::default(),
    }
}

#[test]
fn dimensions_roll_up_bandwidth_and_top_lists() {
    let c = AnalyticsCollector::new(2);
    c.record_with_dimensions(
        event(1, 10, 200, 12),
        AnalyticsDimensionEvent {
            endpoint: Some("/api/orders".into()),
            upstream: Some("10.0.0.1:8080".into()),
            attacker_ip: Some("203.0.113.7".into()),
            bytes: 512,
            attack_type: Some("waf".into()),
        },
    );
    c.record_with_dimensions(
        event(1, 10, 403, 20),
        AnalyticsDimensionEvent {
            endpoint: Some("/api/orders".into()),
            upstream: Some("10.0.0.1:8080".into()),
            attacker_ip: Some("203.0.113.7".into()),
            bytes: 256,
            attack_type: Some("waf".into()),
        },
    );

    let dimensions = c.dimensions(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(dimensions.bandwidth_bytes, 768);
    assert_eq!(dimensions.top_endpoints[0].key, "/api/orders");
    assert_eq!(dimensions.top_endpoints[0].count, 2);
    assert_eq!(dimensions.top_attacker_ips[0].key, "203.0.113.7");
    assert_eq!(dimensions.attack_types[0].key, "waf");
}

#[test]
fn empty_snapshot_has_zeroes() {
    let c = AnalyticsCollector::new(4);
    let s = c.summary(AnalyticsFilter::default());
    assert_eq!(s.requests, 0);
    assert_eq!(s.p50_ms, None);
}

#[test]
fn records_minute_buckets_and_percentiles() {
    let c = AnalyticsCollector::new(4);
    c.record(event(1, 10, 200, 10));
    c.record(event(1, 10, 500, 100));
    c.record(event(1, 11, 200, 50));
    let ts = c.timeseries(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(ts.len(), 2);
    assert_eq!(ts[0].requests, 2);
    let s = c.summary(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(s.requests, 3);
    assert_eq!(s.status_2xx, 2);
    assert_eq!(s.status_5xx, 1);
    assert!(s.p50_ms.unwrap() >= 10);
}

#[test]
fn evicts_old_buckets_and_limits_hosts() {
    let c = AnalyticsCollector::with_limits(2, 2);
    c.record(event(1, 0, 200, 1));
    c.record(event(1, 1440, 200, 1));
    assert_eq!(
        c.timeseries(AnalyticsFilter {
            proxy_host_id: Some(1),
            ..Default::default()
        })
        .len(),
        1
    );
    c.record(event(2, 1440, 200, 1));
    c.record(event(3, 1440, 200, 1));
    assert!(c.host_count() <= 2);
}

#[test]
fn out_of_order_stale_events_do_not_displace_recent_buckets() {
    let c = AnalyticsCollector::with_limits(1, 2);
    c.record(event(1, 100, 200, 1));
    c.record(event(1, 101, 200, 1));
    c.record(event(1, 90, 200, 1));

    let ts = c.timeseries(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(ts.len(), 2);
    assert_eq!(ts[0].timestamp, Utc.timestamp_opt(100 * 60, 0).unwrap());
    assert_eq!(ts[1].timestamp, Utc.timestamp_opt(101 * 60, 0).unwrap());
}

#[test]
fn persisted_buckets_restore_counters_histograms_and_dimensions() {
    let source = AnalyticsCollector::with_limits(2, 120);
    source.record_with_dimensions(
        event(1, 100, 403, 250),
        AnalyticsDimensionEvent {
            endpoint: Some("/login".into()),
            upstream: Some("10.0.0.2:8080".into()),
            attacker_ip: Some("203.0.113.8".into()),
            bytes: 128,
            attack_type: Some("waf".into()),
        },
    );
    let restored = AnalyticsCollector::with_limits(2, 120);
    restored.restore_persistence(source.persistence_snapshot());

    let summary = restored.summary(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.status_4xx, 1);
    assert_eq!(summary.p95_ms, Some(250));
    let dimensions = restored.dimensions(AnalyticsFilter {
        proxy_host_id: Some(1),
        ..Default::default()
    });
    assert_eq!(dimensions.bandwidth_bytes, 128);
    assert_eq!(dimensions.top_endpoints[0].key, "/login");
    assert_eq!(dimensions.attack_types[0].key, "waf");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_recording_is_safe() {
    let c = std::sync::Arc::new(AnalyticsCollector::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..100 {
                c.record(event(1, i, 200, i as u64));
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(c.summary(AnalyticsFilter::default()).requests, 800);
}
