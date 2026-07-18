use std::sync::Arc;

use bearust::{config, runtime::RuntimeStore};

#[tokio::test]
async fn invalid_reload_keeps_current_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let store = RuntimeStore::from_path(&path).await.unwrap();
    let before = store.load();

    std::fs::write(&path, "[server]\nbind = \"broken\"").unwrap();
    assert!(store.reload(&path).await.is_err());
    assert_eq!(store.load().generation(), before.generation());
    assert!(Arc::ptr_eq(&store.load(), &before));
}

#[test]
fn snapshot_routes_to_pool() {
    let config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let snapshot = bearust::runtime::RuntimeSnapshot::build(config, None).unwrap();
    let (route, pool) = snapshot.route("api.example.com", "/").unwrap();
    assert_eq!(route.upstream_pool, pool.name());
}
