use bearust::{bot_protection::{BotConfig, BotMode, BotRule}, control_plane::repository};

async fn db() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn defaults_and_rule_crud_are_bounded() {
    let pool = db().await;
    let config = repository::get_bot_config(&pool).await.unwrap();
    assert_eq!(config.mode, BotMode::Monitor);
    let id = repository::insert_bot_rule(&pool, &BotRule::trusted_crawler("ExampleBot", "Example.COM")).await.unwrap();
    assert_eq!(repository::list_bot_rules(&pool).await.unwrap()[0].trusted_domain.as_deref(), Some("example.com"));
    assert_eq!(repository::delete_bot_rule(&pool, id).await.unwrap(), 1);
}

#[tokio::test]
async fn invalid_config_is_rejected_without_write() {
    let pool = db().await;
    let mut config = repository::get_bot_config(&pool).await.unwrap();
    config.threshold = 0;
    assert!(repository::update_bot_config(&pool, &config).await.is_err());
    let good = repository::get_bot_config(&pool).await.unwrap();
    assert_eq!(good.threshold, 60);
    let _ = BotConfig { mode: BotMode::Monitor, threshold: 60, ttl_seconds: 900, fingerprint_key: vec![1] };
}

#[tokio::test]
async fn migration_is_idempotent_and_failed_reload_keeps_snapshot() {
    let pool = db().await;
    repository::migrate(&pool).await.unwrap();
    let before = repository::get_bot_config(&pool).await.unwrap();
    let store = bearust::bot_store::BotStore::load(&pool).await.unwrap();
    sqlx::query("UPDATE bot_config SET mode='invalid' WHERE id=1").execute(&pool).await.unwrap();
    assert!(store.reload(&pool).await.is_err());
    assert_eq!(store.snapshot().mode, before.mode);
}
