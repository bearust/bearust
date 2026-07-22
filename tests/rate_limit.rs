use bearust::rate_limit::{
    Decision, RateLimitAction, RateLimitKeyScope, RateLimitPolicy, TokenBucket, MAX_CAPACITY,
    MAX_REFILL_PER_SECOND, MAX_RETRY_AFTER,
};
use std::time::{Duration, Instant};

#[test]
fn default_policy_is_disabled_monitor_only() {
    let policy = RateLimitPolicy::default();
    assert!(!policy.enabled);
    assert_eq!(policy.action, RateLimitAction::Monitor);
    assert_eq!(policy.key_scope, RateLimitKeyScope::ProxyHostIp);
    assert!(policy.validate().is_ok());
}

#[test]
fn policy_rejects_out_of_bounds_values() {
    let mut policy = RateLimitPolicy {
        capacity: 0,
        ..Default::default()
    };
    assert!(policy.validate().is_err());
    policy.capacity = MAX_CAPACITY + 1;
    assert!(policy.validate().is_err());
    policy.capacity = 10;
    policy.refill_per_second = 0.0;
    assert!(policy.validate().is_err());
    policy.refill_per_second = MAX_REFILL_PER_SECOND + 1.0;
    assert!(policy.validate().is_err());
}

#[test]
fn burst_consumes_capacity_then_limits() {
    let start = Instant::now();
    let mut bucket = TokenBucket::new(2, 1.0).unwrap();
    assert!(matches!(
        bucket.try_consume(start, 1),
        Decision::Allowed {
            remaining_tokens: 1,
            ..
        }
    ));
    assert!(matches!(
        bucket.try_consume(start, 1),
        Decision::Allowed {
            remaining_tokens: 0,
            ..
        }
    ));
    assert!(
        matches!(bucket.try_consume(start, 1), Decision::Limited { retry_after, .. } if retry_after == Duration::from_secs(1))
    );
}

#[test]
fn tokens_refill_monotonically() {
    let start = Instant::now();
    let mut bucket = TokenBucket::new(2, 2.0).unwrap();
    let _ = bucket.try_consume(start, 2);
    assert!(matches!(
        bucket.try_consume(start + Duration::from_millis(500), 1),
        Decision::Allowed {
            remaining_tokens: 0,
            ..
        }
    ));
}

#[test]
fn zero_and_backward_clock_deltas_do_not_create_tokens() {
    let start = Instant::now();
    let mut bucket = TokenBucket::new(1, 1.0).unwrap();
    let _ = bucket.try_consume(start, 1);
    assert!(matches!(
        bucket.try_consume(start, 1),
        Decision::Limited { .. }
    ));
    assert!(matches!(
        bucket.try_consume(start - Duration::from_secs(1), 1),
        Decision::Limited { .. }
    ));
}

#[test]
fn retry_after_is_bounded() {
    let start = Instant::now();
    let mut bucket = TokenBucket::new(4, 0.001).unwrap();
    let _ = bucket.try_consume(start, 4);
    let decision = bucket.try_consume(start, 4);
    let Decision::Limited { retry_after, .. } = decision else {
        panic!("expected limited")
    };
    assert_eq!(retry_after, MAX_RETRY_AFTER);
}

#[test]
fn cost_above_capacity_is_bounded_and_never_admitted() {
    let start = Instant::now();
    let mut bucket = TokenBucket::new(2, 1.0).unwrap();
    let decision = bucket.try_consume(start, 3);
    assert!(matches!(
        decision,
        Decision::Limited {
            retry_after: MAX_RETRY_AFTER,
            ..
        }
    ));
    assert!(matches!(
        bucket.try_consume(start + Duration::from_secs(60), 3),
        Decision::Limited {
            retry_after: MAX_RETRY_AFTER,
            ..
        }
    ));
}
