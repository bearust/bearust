use bearust::analytics::{AnalyticsBucket, AnalyticsSnapshot, AnalyticsSummary};
use bearust::anomaly::{AnomalyDetector, AnomalyRule, AnomalySeverity};
use bearust::baseline::{BaselineCollector, BaselineStatus, BaselineWindow};
use chrono::{Duration, Utc};

fn create_sample_bucket(
    proxy_host_id: i64,
    timestamp: chrono::DateTime<Utc>,
    reqs: u64,
    errors: u64,
    sec: u64,
) -> AnalyticsBucket {
    AnalyticsBucket {
        timestamp,
        proxy_host_id,
        requests: reqs,
        status_2xx: reqs.saturating_sub(errors),
        status_3xx: 0,
        status_4xx: errors,
        status_5xx: 0,
        waf_blocks: sec,
        bot_blocks: 0,
        bot_challenges: 0,
        rate_limited: 0,
        bandwidth_bytes: 0,
        p50_ms: Some(10),
        p95_ms: Some(25),
        p99_ms: Some(50),
    }
}

#[test]
fn test_request_rate_spike_detection() {
    let detector = AnomalyDetector::default();
    let now = Utc::now();

    // Baseline with steady 1.0 req/s (5 samples = ready)
    let baseline_collector = BaselineCollector::default();
    let baseline_timeseries: Vec<_> = (0..5)
        .map(|i| create_sample_bucket(1, now - Duration::minutes(5 - i), 60, 0, 0))
        .collect();
    baseline_collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: baseline_timeseries,
        },
        now,
    );
    let baseline = baseline_collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(baseline.status, BaselineStatus::Ready);

    // Observed snapshot with huge spike: 600 req in 1 min (10 req/s, 10x baseline)
    let observed = AnalyticsSnapshot {
        summary: AnalyticsSummary::default(),
        timeseries: vec![create_sample_bucket(1, now, 600, 0, 0)],
    };

    let anomalies = detector.evaluate(&baseline, &observed, now);
    assert!(!anomalies.is_empty());
    assert_eq!(anomalies[0].host_id, 1);
    assert_eq!(anomalies[0].rule, AnomalyRule::RequestRate);
    assert_eq!(anomalies[0].severity, AnomalySeverity::Critical);
}

#[test]
fn test_warming_up_never_produces_critical_anomaly() {
    let detector = AnomalyDetector::default();
    let now = Utc::now();

    // Baseline with only 2 samples = warming_up
    let baseline_collector = BaselineCollector::default();
    let baseline_timeseries: Vec<_> = (0..2)
        .map(|i| create_sample_bucket(1, now - Duration::minutes(2 - i), 60, 0, 0))
        .collect();
    baseline_collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: baseline_timeseries,
        },
        now,
    );
    let baseline = baseline_collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );
    assert_eq!(baseline.status, BaselineStatus::WarmingUp);

    // Observed spike
    let observed = AnalyticsSnapshot {
        summary: AnalyticsSummary::default(),
        timeseries: vec![create_sample_bucket(1, now, 1000, 500, 100)],
    };

    let anomalies = detector.evaluate(&baseline, &observed, now);
    for a in anomalies {
        assert_ne!(
            a.severity,
            AnomalySeverity::Critical,
            "WarmingUp status must not produce critical anomalies"
        );
    }
}

#[test]
fn test_cooldown_and_acknowledgement() {
    let detector = AnomalyDetector::default();
    let now = Utc::now();

    let baseline_collector = BaselineCollector::default();
    let baseline_timeseries: Vec<_> = (0..5)
        .map(|i| create_sample_bucket(1, now - Duration::minutes(5 - i), 60, 0, 0))
        .collect();
    baseline_collector.record(
        &AnalyticsSnapshot {
            summary: AnalyticsSummary::default(),
            timeseries: baseline_timeseries,
        },
        now,
    );
    let baseline = baseline_collector.snapshot(
        Some(1),
        BaselineWindow::FiveMinutes,
        now - Duration::minutes(5),
        now,
    );

    let observed = AnalyticsSnapshot {
        summary: AnalyticsSummary::default(),
        timeseries: vec![create_sample_bucket(1, now, 600, 0, 0)],
    };

    let anomalies = detector.evaluate(&baseline, &observed, now);
    assert_eq!(anomalies.len(), 1);
    let record_id = anomalies[0].id;

    // Immediately evaluating again within cooldown should not produce duplicate record
    let anomalies2 = detector.evaluate(&baseline, &observed, now + Duration::seconds(10));
    assert!(anomalies2.is_empty());

    // Acknowledge the anomaly record
    let acked = detector.acknowledge(record_id);
    assert!(acked.is_some());
    assert!(acked.unwrap().acknowledged);
}
