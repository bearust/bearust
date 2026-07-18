use std::sync::Arc;

use bearust::{balancer::PoolState, config::Config};

fn pool(algorithm: &str) -> Arc<PoolState> {
    let text = include_str!("fixtures/valid.toml").replace(
        "algorithm = \"least_connections\"",
        &format!("algorithm = \"{algorithm}\""),
    );
    let mut config = Config::parse(&text).unwrap();
    let duplicate = config.upstream_pools[0].backends[0].clone();
    config.upstream_pools[0].backends.push(duplicate);
    config.upstream_pools[0].backends[1].address = "127.0.0.1:19002".parse().unwrap();
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
