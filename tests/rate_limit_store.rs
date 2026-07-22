use bearust::{
    rate_limit::{Decision, RateLimitKey, RateLimitPolicy},
    rate_limit_store::{client_ip, IpNetSet, RateLimiterStore},
};
use http::{HeaderMap, HeaderValue};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}
fn key(n: i64, value: &str) -> RateLimitKey {
    RateLimitKey {
        proxy_host_id: n,
        client_ip: ip(value),
    }
}

#[test]
fn untrusted_forwarding_headers_are_ignored() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
    assert_eq!(
        client_ip(ip("198.51.100.2"), &headers, &IpNetSet::new(["10.0.0.0/8"])),
        ip("198.51.100.2")
    );
}

#[test]
fn trusted_peer_uses_validated_forwarded_address() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        HeaderValue::from_static("for=203.0.113.9;proto=https"),
    );
    assert_eq!(
        client_ip(ip("10.2.3.4"), &headers, &IpNetSet::new(["10.0.0.0/8"])),
        ip("203.0.113.9")
    );
}

#[test]
fn ttl_and_capacity_evict_entries_deterministically() {
    let store = RateLimiterStore::new(2, Duration::from_secs(5));
    let policy = RateLimitPolicy {
        enabled: true,
        capacity: 2,
        refill_per_second: 0.0,
        ..RateLimitPolicy::default()
    };
    let start = Instant::now();
    let _ = store.evaluate(key(1, "192.0.2.1"), &policy, start);
    let _ = store.evaluate(key(1, "192.0.2.2"), &policy, start + Duration::from_secs(1));
    let _ = store.evaluate(key(1, "192.0.2.3"), &policy, start + Duration::from_secs(2));
    assert_eq!(store.len(), 2);
    let _ = store.evaluate(
        key(1, "192.0.2.2"),
        &policy,
        start + Duration::from_secs(10),
    );
    assert_eq!(store.len(), 1);
}

#[test]
fn concurrent_calls_remain_bounded() {
    let store = Arc::new(RateLimiterStore::new(8, Duration::from_secs(60)));
    let policy = RateLimitPolicy {
        enabled: true,
        capacity: 10,
        refill_per_second: 1.0,
        ..RateLimitPolicy::default()
    };
    let start = Instant::now();
    std::thread::scope(|scope| {
        for thread in 0..16 {
            let store = Arc::clone(&store);
            let policy = policy.clone();
            scope.spawn(move || {
                for n in 0..100 {
                    let _ = store.evaluate(
                        key(thread, &format!("192.0.2.{}", n % 4 + 1)),
                        &policy,
                        start,
                    );
                }
            });
        }
    });
    assert!(store.len() <= 8);
}

#[test]
fn disabled_policy_is_monitor_only() {
    let store = RateLimiterStore::new(1, Duration::from_secs(1));
    let decision = store.evaluate(
        key(1, "192.0.2.1"),
        &RateLimitPolicy::default(),
        Instant::now(),
    );
    assert!(matches!(decision, Decision::Allowed { .. }));
}
