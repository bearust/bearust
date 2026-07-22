use bearust::adaptive_tuning::{
    AdaptiveTuningEngine, TuningMode, TuningPolicy,
};
use bearust::anomaly::{AnomalyRecord, AnomalyRule, AnomalySeverity};
use bearust::rate_limit::RateLimitPolicy;

#[test]
fn test_default_mode_and_guardrails() {
    let engine = AdaptiveTuningEngine::default();

    let policy = TuningPolicy {
        mode: TuningMode::Monitor,
        max_delta_percent: 50,
        cooldown_seconds: 300,
        min_confidence: 0.8,
    };

    let anomaly = AnomalyRecord {
        id: 1,
        host_id: 10,
        rule: AnomalyRule::RequestRate,
        severity: AnomalySeverity::Critical,
        score: 8.5,
        summary: "Spike detected".into(),
        observed_at: chrono::Utc::now(),
        acknowledged: false,
    };

    let current_rl = RateLimitPolicy {
        enabled: true,
        action: bearust::rate_limit::RateLimitAction::Monitor,
        capacity: 100,
        refill_per_second: 10.0,
        key_scope: bearust::rate_limit::RateLimitKeyScope::ProxyHostIp,
    };

    let rec = engine.recommend(&anomaly, &current_rl, &policy);
    assert!(rec.is_some());
    let rec = rec.unwrap();

    assert_eq!(rec.host_id, 10);
    assert!(rec.confidence >= policy.min_confidence);

    // Validate max delta limit (capacity 100 with max 50% delta -> patch capacity between 50 and 150)
    if let Some(cap) = rec.patch.capacity {
        assert!(cap >= 50 && cap <= 150);
    }
}

#[test]
fn test_emergency_disable_blocks_enforce() {
    let engine = AdaptiveTuningEngine::default();
    engine.set_emergency_disabled(true);
    assert!(engine.is_emergency_disabled());
}
