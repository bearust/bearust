use std::sync::Arc;

use bearust::{
    balancer::PoolState,
    config::{Algorithm, Config},
};

fn pool(algorithm: &str) -> Arc<PoolState> {
    let text = include_str!("fixtures/valid.toml").replace(
        "algorithm = \"least_connections\"",
        &format!("algorithm = \"{algorithm}\""),
    );
    let mut config = Config::parse(&text).unwrap();
    let duplicate = config.upstream_pools[0].backends[0].clone();
    config.upstream_pools[0].backends.push(duplicate);
    config.upstream_pools[0].backends[1].address = "127.0.0.1:19002".parse().unwrap();
    if matches!(algorithm, "weighted" | "adaptive_weight") {
        config.upstream_pools[0].backends[0].weight = 3;
        config.upstream_pools[0].backends[1].weight = 1;
    }
    let pool = Arc::new(PoolState::new(&config.upstream_pools[0]));
    pool.set_healthy(0.into(), true);
    pool.set_healthy(1.into(), true);
    pool
}

#[test]
fn round_robin_rotates_healthy_backends() {
    let pool = pool("round_robin");
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select(None).unwrap().address())
        .collect();
    assert_eq!(selected[0], selected[2]);
    assert_eq!(selected[1], selected[3]);
    assert_ne!(selected[0], selected[1]);
}

#[test]
fn least_connections_prefers_lower_inflight_and_drop_releases_count() {
    let pool = pool("least_connections");
    let held = pool.select(None).unwrap();
    let other = pool.select(None).unwrap();
    assert_ne!(held.id(), other.id());
    drop(held);
    drop(other);
    assert_eq!(pool.total_inflight(), 0);
}

#[test]
fn exclusion_prevents_immediate_failover_to_same_backend() {
    let pool = pool("round_robin");
    let first = pool.select(None).unwrap();
    let second = pool.select(Some(first.id())).unwrap();
    assert_ne!(first.id(), second.id());
}

#[test]
fn concurrent_selections_release_all_leases() {
    let pool = pool("least_connections");
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let pool = Arc::clone(&pool);
            scope.spawn(move || {
                for _ in 0..625 {
                    let lease = pool.select(None).unwrap();
                    std::hint::black_box(lease.id());
                }
            });
        }
    });
    assert_eq!(pool.total_inflight(), 0);
}

#[test]
fn plugin_algorithm_falls_back_to_round_robin_selection() {
    let pool = pool("plugin");
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select(None).unwrap().address())
        .collect();
    assert_eq!(selected[0], selected[2]);
    assert_eq!(selected[1], selected[3]);
    assert_ne!(selected[0], selected[1]);
}

#[test]
fn weighted_selection_honors_backend_weights() {
    let pool = pool("weighted");
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select(None).unwrap().id().index())
        .collect();
    assert_eq!(selected, vec![0, 0, 0, 1]);
}

#[test]
fn ip_hash_keeps_a_client_on_the_same_backend() {
    let pool = pool("ip_hash");
    let first = pool
        .select_with_key(None, Some(b"198.51.100.20"))
        .unwrap()
        .id();
    let second = pool
        .select_with_key(None, Some(b"198.51.100.20"))
        .unwrap()
        .id();
    assert_eq!(first, second);
}

#[test]
fn passive_health_ejects_after_three_failures_and_active_health_restores() {
    let text = include_str!("fixtures/valid.toml").replace(
        "algorithm = \"least_connections\"",
        "algorithm = \"round_robin\"\npassive_health = true",
    );
    let config = Config::parse(&text).unwrap();
    let pool = std::sync::Arc::new(PoolState::new(&config.upstream_pools[0]));
    pool.set_healthy(0.into(), true);
    pool.record_result(0.into(), 500, 20);
    pool.record_result(0.into(), 500, 20);
    pool.record_result(0.into(), 500, 20);
    assert!(!pool.is_healthy(0.into()));
    assert!(pool.select(None).is_none());
    pool.set_healthy(0.into(), true);
    assert!(pool.select(None).is_some());
}

#[test]
fn algorithm_accessor_reports_the_configured_algorithm() {
    let plugin_pool = pool("plugin");
    assert_eq!(plugin_pool.algorithm(), Algorithm::Plugin);
    let round_robin_pool = pool("round_robin");
    assert_eq!(round_robin_pool.algorithm(), Algorithm::RoundRobin);
}

#[test]
fn candidates_reflects_live_health_and_inflight_state() {
    let pool = pool("round_robin");
    pool.set_healthy(1.into(), false);
    let held = pool.select(Some(1.into())).unwrap();
    let candidates = pool.candidates();
    assert_eq!(candidates.len(), 2);
    let zero = candidates.iter().find(|c| c.id == 0.into()).unwrap();
    assert!(zero.healthy);
    assert_eq!(zero.inflight, 1);
    let one = candidates.iter().find(|c| c.id == 1.into()).unwrap();
    assert!(!one.healthy);
    assert_eq!(one.inflight, 0);
    drop(held);
}

#[test]
fn select_specific_rejects_an_unhealthy_backend() {
    let pool = pool("round_robin");
    pool.set_healthy(0.into(), false);
    assert!(pool.select_specific(0.into(), None).is_none());
}

#[test]
fn select_specific_rejects_the_excluded_backend() {
    let pool = pool("round_robin");
    assert!(pool.select_specific(0.into(), Some(0.into())).is_none());
}

#[test]
fn select_specific_rejects_a_nonexistent_backend() {
    let pool = pool("round_robin");
    assert!(pool.select_specific(99.into(), None).is_none());
}

#[test]
fn select_specific_accepts_a_valid_pick_and_increments_inflight() {
    let pool = pool("round_robin");
    let lease = pool.select_specific(0.into(), None).unwrap();
    assert_eq!(lease.id(), 0.into());
    assert_eq!(pool.total_inflight(), 1);
    drop(lease);
    assert_eq!(pool.total_inflight(), 0);
}
