use bearust::{control_plane::{models::{WafAction, WafMode, WafRule}, repository}, waf::{evaluate, redacted_telemetry, InspectionContext, WafDecision}, waf_store::WafStore};

#[tokio::test]
async fn waf_store_loads_monitor_mode_and_reload_publishes_block_snapshot() {
    let db = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&db).await.unwrap();
    let store = WafStore::load(&db).await.unwrap();
    let context = InspectionContext { method: "GET".into(), path: "/search".into(), query: "q=' OR 1=1".into(), headers: Vec::new(), body: Vec::new() };
    assert_eq!(evaluate(&store.snapshot(), &context).decision, WafDecision::Log);
    repository::update_waf_mode(&db, WafMode::Block).await.unwrap();
    store.reload(&db).await.unwrap();
    assert_eq!(evaluate(&store.snapshot(), &context).decision, WafDecision::Block);
}

#[tokio::test]
async fn invalid_custom_rule_does_not_replace_last_valid_snapshot() {
    let db = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&db).await.unwrap();
    let store = WafStore::load(&db).await.unwrap();
    let before = store.snapshot();
    let bad = WafRule { id: 0, name: "bad".into(), source: "custom".into(), category: "custom".into(), severity: "low".into(), enabled: true, action: WafAction::Block, matcher_json: r#"{"field":"query","pattern":"("}"#.into(), created_at: String::new(), updated_at: String::new() };
    repository::insert_waf_rule(&db, &bad).await.unwrap();
    assert!(store.reload(&db).await.is_err());
    assert_eq!(store.snapshot().rules.len(), before.rules.len());
}

#[test]
fn waf_telemetry_contains_only_bounded_redacted_identifiers() {
    let snapshot = bearust::waf::compile_snapshot(
        bearust::control_plane::models::WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let body = "union select password from users; credential=super-secret-body";
    let evaluation = evaluate(
        &snapshot,
        &InspectionContext {
            method: "POST".into(),
            path: "/login".into(),
            query: "".into(),
            headers: vec![("authorization".into(), "Bearer top-secret-token".into())],
            body: body.as_bytes().to_vec(),
        },
    );
    let details = redacted_telemetry(&evaluation);
    assert_eq!(details.category, "sqli");
    assert_eq!(details.reason_ids, "sqli");
    assert_eq!(details.score, 6);
    assert_eq!(details.severity, "medium");
    let serialized = format!("{}:{}:{}:{}", details.category, details.score, details.severity, details.reason_ids);
    assert!(!serialized.contains("super-secret-body"));
    assert!(!serialized.contains("top-secret-token"));
    assert!(!serialized.contains("authorization"));
}
