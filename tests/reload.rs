use std::sync::Arc;

use bearust::{config, runtime::RuntimeStore};

#[tokio::test]
async fn invalid_reload_keeps_current_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let store = RuntimeStore::new(
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap(),
    );
    let before = store.load();

    std::fs::write(&path, "[server]\nbind = \"broken\"").unwrap();
    assert!(store.reload(&path).await.is_err());
    assert_eq!(store.load().generation(), before.generation());
    assert!(Arc::ptr_eq(&store.load(), &before));
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn successful_reload_increments_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);

    let outcome = store.reload(&path).await.unwrap();
    assert_eq!(outcome.old_generation, 1);
    assert_eq!(outcome.new_generation, 2);
    assert_eq!(store.load().generation(), 2);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn old_snapshot_remains_usable_after_reload() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);
    let old = store.load();

    let changed = include_str!("fixtures/valid.toml").replace("18080", "18081");
    std::fs::write(&path, changed).unwrap();
    store.reload(&path).await.unwrap();

    assert_eq!(old.generation(), 1);
    assert!(old.route("api.example.com", "/health").is_some());
    assert!(!Arc::ptr_eq(&old, &store.load()));
    assert_eq!(store.load().generation(), 2);
    store.shutdown().await.unwrap();
}

#[test]
fn unchanged_backend_identity_preserves_health_eligibility() {
    let config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let before = bearust::runtime::RuntimeSnapshot::build(config.clone(), None).unwrap();
    let old_pool = before.pools().next().unwrap();
    old_pool.set_healthy(0.into(), true);

    let after = bearust::runtime::RuntimeSnapshot::build(config, Some(&before)).unwrap();
    assert!(after.pools().next().unwrap().is_healthy(0.into()));
}

#[test]
fn changed_backend_definition_resets_health_eligibility() {
    let mut config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let before = bearust::runtime::RuntimeSnapshot::build(config.clone(), None).unwrap();
    before.pools().next().unwrap().set_healthy(0.into(), true);

    config.upstream_pools[0].backends[0].address = "127.0.0.1:19002".parse().unwrap();
    let after = bearust::runtime::RuntimeSnapshot::build(config, Some(&before)).unwrap();
    assert!(!after.pools().next().unwrap().is_healthy(0.into()));
}

#[test]
fn snapshot_routes_to_pool() {
    let config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let snapshot = bearust::runtime::RuntimeSnapshot::build(config, None).unwrap();
    let (route, pool) = snapshot.route("api.example.com", "/").unwrap();
    assert_eq!(route.upstream_pool, pool.name());
}
