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
fn interval_rollups_preserve_hosts_counters_histograms_and_apply_limit_last() {
    use bearust::analytics::AnalyticsInterval;
    let collector = AnalyticsCollector::with_limits(4, 10080);
    for minute in [61, 62] {
        let mut request = event(
            1,
            minute,
            if minute == 61 { 200 } else { 403 },
            if minute == 61 { 10 } else { 1000 },
        );
        request.security = SecurityCounters {
            waf_blocks: 1,
            bot_blocks: 2,
            bot_challenges: 3,
            rate_limited: 4,
        };
        collector.record_with_dimensions(
            request,
            AnalyticsDimensionEvent {
                bytes: 100,
                ..Default::default()
            },
        );
    }
    collector.record(event(2, 62, 500, 50));
    collector.record(event(1, 120, 500, 50));
    let rows = collector.timeseries(AnalyticsFilter {
        interval: AnalyticsInterval::Hour,
        ..Default::default()
    });
    assert_eq!(
        rows.iter()
            .map(|row| (row.timestamp.timestamp(), row.proxy_host_id, row.requests))
            .collect::<Vec<_>>(),
        vec![(3600, 1, 2), (3600, 2, 1), (7200, 1, 1)]
    );
    assert_eq!(
        (rows[0].status_2xx, rows[0].status_4xx, rows[0].status_5xx),
        (1, 1, 0)
    );
    assert_eq!(
        (
            rows[0].waf_blocks,
            rows[0].bot_blocks,
            rows[0].bot_challenges,
            rows[0].rate_limited
        ),
        (2, 4, 6, 8)
    );
    assert_eq!(rows[0].bandwidth_bytes, 200);
    assert_eq!(
        (rows[0].p50_ms, rows[0].p95_ms, rows[0].p99_ms),
        (Some(10), Some(1000), Some(1000))
    );
    let filtered = collector.timeseries(AnalyticsFilter {
        proxy_host_id: Some(1),
        from: Some(Utc.timestamp_opt(3600, 0).unwrap()),
        to: Some(Utc.timestamp_opt(7199, 0).unwrap()),
        interval: AnalyticsInterval::Hour,
        limit: 1,
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].requests, 2);
}

#[test]
fn daily_rollups_use_utc_boundaries_and_filter_source_minutes_before_grouping() {
    use bearust::analytics::AnalyticsInterval;
    let collector = AnalyticsCollector::with_limits(2, 10080);
    for minute in [-1, 0, 1, 1439, 1440] {
        collector.record(event(1, minute, 200, 10));
    }
    let rows = collector.timeseries(AnalyticsFilter {
        interval: AnalyticsInterval::Day,
        ..Default::default()
    });
    assert_eq!(
        rows.iter()
            .map(|row| (row.timestamp.timestamp(), row.requests))
            .collect::<Vec<_>>(),
        vec![(-86400, 1), (0, 3), (86400, 1)]
    );
    let rows = collector.timeseries(AnalyticsFilter {
        interval: AnalyticsInterval::Day,
        from: Some(Utc.timestamp_opt(60, 0).unwrap()),
        to: Some(Utc.timestamp_opt(120, 0).unwrap()),
        ..Default::default()
    });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].timestamp.timestamp(), 0);
    assert_eq!(rows[0].requests, 1);
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
