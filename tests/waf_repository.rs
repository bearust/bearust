use bearust::control_plane::{models::{WafAction, WafMode, WafRule}, repository};

async fn db() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn fresh_database_defaults_to_monitor_only_and_seeds_builtin_rules() {
    let pool = db().await;
    let config = repository::get_waf_config(&pool).await.unwrap();
    assert_eq!(config.mode, WafMode::MonitorOnly);
    let rules = repository::list_waf_rules(&pool).await.unwrap();
    assert_eq!(rules.iter().filter(|rule| rule.source == "builtin").count(), 4);
    assert!(rules.iter().any(|rule| rule.category == "sqli"));
    assert!(rules.iter().any(|rule| rule.category == "xss"));
    assert!(rules.iter().any(|rule| rule.category == "path_traversal"));
    assert!(rules.iter().any(|rule| rule.category == "command_injection"));
}

#[tokio::test]
async fn builtin_seeding_is_idempotent() {
    let pool = db().await;
    let before = repository::list_waf_rules(&pool).await.unwrap().len();
    repository::seed_builtin_waf_rules(&pool).await.unwrap();
    repository::seed_builtin_waf_rules(&pool).await.unwrap();
    assert_eq!(repository::list_waf_rules(&pool).await.unwrap().len(), before);
}

#[tokio::test]
async fn custom_rule_crud_round_trips_matcher_and_timestamps() {
    let pool = db().await;
    let rule = WafRule {
        id: 0,
        name: "custom test".into(),
        source: "custom".into(),
        category: "custom".into(),
        severity: "medium".into(),
        enabled: true,
        action: WafAction::Block,
        matcher_json: r#"{"field":"query","pattern":"evil"}"#.into(),
        created_at: String::new(),
        updated_at: String::new(),
    };
    let id = repository::insert_waf_rule(&pool, &rule).await.unwrap();
    let stored = repository::list_waf_rules(&pool).await.unwrap().into_iter().find(|item| item.id == id).unwrap();
    assert_eq!(stored.matcher_json, rule.matcher_json);
    assert!(!stored.created_at.is_empty());
    let mut updated = stored.clone();
    updated.enabled = false;
    updated.action = WafAction::Log;
    repository::update_waf_rule(&pool, id, &updated).await.unwrap();
    let updated_stored = repository::list_waf_rules(&pool).await.unwrap().into_iter().find(|item| item.id == id).unwrap();
    assert!(!updated_stored.enabled);
    assert_eq!(updated_stored.action, WafAction::Log);
    repository::delete_waf_rule(&pool, id).await.unwrap();
    assert!(repository::list_waf_rules(&pool).await.unwrap().into_iter().all(|item| item.id != id));
}

#[tokio::test]
async fn mode_updates_round_trip() {
    let pool = db().await;
    repository::update_waf_mode(&pool, WafMode::Block).await.unwrap();
    assert_eq!(repository::get_waf_config(&pool).await.unwrap().mode, WafMode::Block);
}
