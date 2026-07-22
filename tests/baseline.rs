use bearust::analytics::{AnalyticsBucket, AnalyticsSnapshot, AnalyticsSummary};
use bearust::baseline::{BaselineCollector, BaselineStatus, BaselineWindow};
use chrono::{Duration, Utc};

fn create_sample_bucket(
    proxy_host_id: i64,
    timestamp: chrono::DateTime<Utc>,
    reqs: u64,
) -> AnalyticsBucket {
    AnalyticsBucket {
        timestamp,
        proxy_host_id,
        requests: reqs,
        status_2xx: reqs,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
        waf_blocks: 0,
        bot_blocks: 0,
        bot_challenges: 0,
        rate_limited: 0,
        p50_ms: Some(10),
        p95_ms: Some(25),
        p99_ms: Some(50),
    }
}

#[test]
fn test_warming_up_and_ready_status() {
    let collector = BaselineCollector::default();
    let now = Utc::now();

    // Empty snapshot is warming_up
    let snap = collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(snap.status, BaselineStatus::WarmingUp);
    assert_eq!(snap.sample_count, 0);

    // Add 2 buckets (less than 5)
    let analytics = AnalyticsSnapshot {
        summary: AnalyticsSummary::default(),
        timeseries: vec![
            create_sample_bucket(1, now - Duration::minutes(2), 60),
            create_sample_bucket(1, now - Duration::minutes(1), 60),
        ],
    };
    collector.record(&analytics, now);

    let snap = collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(snap.status, BaselineStatus::WarmingUp);
    assert_eq!(snap.sample_count, 2);

    // Add 3 more buckets (total 5)
    let analytics2 = AnalyticsSnapshot {
        summary: AnalyticsSummary::default(),
        timeseries: vec![
            create_sample_bucket(1, now - Duration::minutes(5), 60),
            create_sample_bucket(1, now - Duration::minutes(4), 60),
            create_sample_bucket(1, now - Duration::minutes(3), 60),
        ],
    };
    collector.record(&analytics2, now);

    let snap = collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(snap.status, BaselineStatus::Ready);
    assert_eq!(snap.sample_count, 5);
}

#[test]
fn test_rolling_windows_metrics() {
    let collector = BaselineCollector::default();
    let now = Utc::now();

    let mut timeseries = Vec::new();
    for i in 0..10 {
        timeseries.push(create_sample_bucket(1, now - Duration::minutes(10 - i), 60));
    }
    collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries,
        },
        now,
    );

    let snap_5m = collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(snap_5m.sample_count, 5);
    assert!((snap_5m.metrics.req_per_sec - 1.0).abs() < 1e-3); // 60 req / 60 sec = 1.0 req/s

    let snap_1h = collector.snapshot(
        Some(1),
        BaselineWindow::OneHour,
        now - Duration::hours(1),
        now,
    );
    assert_eq!(snap_1h.sample_count, 10);
}

#[test]
fn test_out_of_order_timestamps() {
    let collector = BaselineCollector::default();
    let now = Utc::now();

    let timeseries = vec![
        create_sample_bucket(1, now - Duration::minutes(1), 60),
        create_sample_bucket(1, now - Duration::minutes(3), 60),
        create_sample_bucket(1, now - Duration::minutes(2), 60),
    ];
    collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries,
        },
        now,
    );

    let snap = collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(snap.sample_count, 3);
}

#[test]
fn test_bounded_host_eviction() {
    let collector = BaselineCollector::with_limits(2, 60);
    let now = Utc::now();

    collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: vec![create_sample_bucket(101, now - Duration::minutes(1), 10)],
        },
        now,
    );

    collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: vec![create_sample_bucket(102, now - Duration::minutes(1), 10)],
        },
        now,
    );

    // Host count is at limit 2
    assert_eq!(collector.host_count(), 2);

    // Record host 103 -> should evict one of the existing hosts
    collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: vec![create_sample_bucket(103, now - Duration::minutes(1), 10)],
        },
        now,
    );

    assert_eq!(collector.host_count(), 2);
}
