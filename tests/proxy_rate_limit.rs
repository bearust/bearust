use bearust::rate_limit::{Decision, RateLimitAction, RateLimitKey, RateLimitPolicy};
use bearust::rate_limit_store::{client_ip, IpNetSet, RateLimiterStore};
use http::HeaderMap;
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

#[test]
fn client_ip_preserves_ipv4_and_ipv6_peer_addresses() {
    let headers = HeaderMap::new();
    let trusted = IpNetSet::default();
    let ipv4: IpAddr = "192.0.2.10".parse().unwrap();
    let ipv6: IpAddr = "2001:db8::10".parse().unwrap();
    assert_eq!(client_ip(ipv4, &headers, &trusted), ipv4);
    assert_eq!(client_ip(ipv6, &headers, &trusted), ipv6);
}

#[test]
fn trusted_forwarded_client_ip_supports_bracketed_ipv6() {
    let mut headers = HeaderMap::new();
    headers.insert("forwarded", "for=\"[2001:db8::20]\"".parse().unwrap());
    let trusted = IpNetSet::new(["192.0.2.1/32"]);
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let expected: IpAddr = "2001:db8::20".parse().unwrap();
    assert_eq!(client_ip(peer, &headers, &trusted), expected);
}

#[test]
fn one_host_quota_is_shared_across_paths() {
    let store = RateLimiterStore::new(16, Duration::from_secs(60));
    let policy = RateLimitPolicy { enabled: true, capacity: 1, refill_per_second: 0.001, ..RateLimitPolicy::default() };
    let now = Instant::now();
    let host = 42;
    let ip: IpAddr = "198.51.100.10".parse().unwrap();
    let _ = store.evaluate(RateLimitKey { proxy_host_id: host, client_ip: ip }, &policy, now);
    // Paths are intentionally absent from RateLimitKey; / and /api consume
    // the same proxy-host/client bucket.
    assert!(matches!(store.evaluate(RateLimitKey { proxy_host_id: host, client_ip: ip }, &policy, now), Decision::Limited { .. }));
}
