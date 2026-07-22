use bearust::rate_limit::{Decision, RateLimitAction, RateLimitKey, RateLimitPolicy};
use bearust::rate_limit_store::RateLimiterStore;
use std::{net::IpAddr, sync::Arc, time::{Duration, Instant}};

fn key() -> RateLimitKey {
    RateLimitKey { proxy_host_id: 42, client_ip: "198.51.100.10".parse::<IpAddr>().unwrap() }
}

#[test]
fn monitor_mode_records_limit_without_changing_decision_math() {
    let store = Arc::new(RateLimiterStore::new(16, Duration::from_secs(60)));
    let policy = RateLimitPolicy { enabled: true, action: RateLimitAction::Monitor, capacity: 1, refill_per_second: 0.001, ..RateLimitPolicy::default() };
    let now = Instant::now();
    assert!(matches!(store.evaluate(key(), &policy, now), Decision::Allowed { .. }));
    assert!(matches!(store.evaluate(key(), &policy, now), Decision::Limited { .. }));
}

#[test]
fn block_mode_exposes_retry_after_for_429_response() {
    let store = RateLimiterStore::new(16, Duration::from_secs(60));
    let policy = RateLimitPolicy { enabled: true, action: RateLimitAction::Block, capacity: 1, refill_per_second: 0.001, ..RateLimitPolicy::default() };
    let now = Instant::now();
    let _ = store.evaluate(key(), &policy, now);
    let decision = store.evaluate(key(), &policy, now);
    match decision {
        Decision::Limited { retry_after, .. } => assert!(retry_after >= Duration::from_secs(1)),
        Decision::Allowed { .. } => panic!("second request must be limited"),
    }
}

#[test]
fn buckets_are_isolated_by_proxy_host_and_client_ip() {
    let store = RateLimiterStore::new(16, Duration::from_secs(60));
    let policy = RateLimitPolicy { enabled: true, capacity: 1, refill_per_second: 0.001, ..RateLimitPolicy::default() };
    let now = Instant::now();
    let _ = store.evaluate(key(), &policy, now);
    assert!(matches!(store.evaluate(RateLimitKey { proxy_host_id: 43, ..key() }, &policy, now), Decision::Allowed { .. }));
}
