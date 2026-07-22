use bearust::adaptive_tuning::{PolicyPatch, PolicyRecommendation, TuningMode, TuningPolicy};
use bearust::control_plane::auth::{hash_password, token_hash};
use bearust::control_plane::{build_state, repository, router};
use axum::{body::Body, http::{Request, StatusCode}};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn adaptive_tuning_policy_endpoint_and_validation() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123").await.unwrap();

    let admin = repository::insert_initial_admin(&state.db, "admin@example.com", &hash_password("admin12345678").unwrap()).await.unwrap().unwrap();
    repository::create_session(&state.db, admin.id, &token_hash("admin-token"), "2099-01-01T00:00:00Z").await.unwrap();

    let app = router(state.clone());

    // GET policy for host 1 (defaults to monitor)
    let req = Request::builder()
        .uri("/api/adaptive-tuning/policy/1")
        .method("GET")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Invalid policy input (max_delta_percent = 0) rejected with 400
    let invalid_json = serde_json::to_string(&TuningPolicy {
        mode: TuningMode::Recommend,
        max_delta_percent: 0,
        cooldown_seconds: 300,
        min_confidence: 0.8,
    }).unwrap();

    let req = Request::builder()
        .uri("/api/adaptive-tuning/policy/1")
        .method("PUT")
        .header("Cookie", "bearust_session=admin-token")
        .header("Content-Type", "application/json")
        .body(Body::from(invalid_json))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Valid PUT policy update for host 1
    let policy_json = serde_json::to_string(&TuningPolicy {
        mode: TuningMode::Recommend,
        max_delta_percent: 30,
        cooldown_seconds: 600,
        min_confidence: 0.85,
    }).unwrap();

    let req = Request::builder()
        .uri("/api/adaptive-tuning/policy/1")
        .method("PUT")
        .header("Cookie", "bearust_session=admin-token")
        .header("Content-Type", "application/json")
        .body(Body::from(policy_json))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn adaptive_tuning_apply_rollback_and_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    std::fs::File::create(&db_path).unwrap();
    let db_url = format!("sqlite://{}", db_path.display());

    let state = build_state(&db_url, dir.path(), "setup-token-123").await.unwrap();
    let admin = repository::insert_initial_admin(&state.db, "admin@example.com", &hash_password("admin12345678").unwrap()).await.unwrap().unwrap();
    repository::create_session(&state.db, admin.id, &token_hash("admin-token"), "2099-01-01T00:00:00Z").await.unwrap();

    let app = router(state.clone());

    // Invalid recommendation ID (999) returns 404
    let req = Request::builder()
        .uri("/api/adaptive-tuning/recommendations/999/apply")
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Set host 1 policy mode to Recommend
    repository::update_tuning_policy(&state.db, 1, &TuningPolicy {
        mode: TuningMode::Recommend,
        max_delta_percent: 50,
        cooldown_seconds: 300,
        min_confidence: 0.8,
    }).await.unwrap();

    // Insert dummy recommendation into DB
    let rec = PolicyRecommendation {
        id: 0,
        host_id: 1,
        patch: PolicyPatch {
            capacity: Some(50),
            refill_per_second: Some(5.0),
            waf_mode: None,
        },
        confidence: 0.9,
        reason: "Test spike recommendation".into(),
        created_at: chrono::Utc::now(),
        applied: false,
        applied_at: None,
        previous_config_json: None,
    };
    let rec_id = repository::insert_tuning_recommendation(&state.db, &rec).await.unwrap();

    // Initial rate limit capacity in DB for host 1 is 100
    let rl_before = repository::get_host_rate_limit_config(&state.db, 1).await.unwrap();
    assert_eq!(rl_before.capacity, 100);

    // Apply recommendation
    let req = Request::builder()
        .uri(format!("/api/adaptive-tuning/recommendations/{rec_id}/apply"))
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify rate limit capacity for host 1 updated to 50
    let rl_after = repository::get_host_rate_limit_config(&state.db, 1).await.unwrap();
    assert_eq!(rl_after.capacity, 50);

    // Re-applying already applied recommendation returns 400
    let req = Request::builder()
        .uri(format!("/api/adaptive-tuning/recommendations/{rec_id}/apply"))
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Rollback recommendation
    let req = Request::builder()
        .uri(format!("/api/adaptive-tuning/recommendations/{rec_id}/rollback"))
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify rate limit capacity for host 1 restored to 100
    let rl_restored = repository::get_host_rate_limit_config(&state.db, 1).await.unwrap();
    assert_eq!(rl_restored.capacity, 100);

    // Toggle emergency disable
    let req = Request::builder()
        .uri("/api/adaptive-tuning/emergency-disable")
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-build state from persistent SQLite database and verify emergency_disabled persists
    let state_restarted = build_state(&db_url, dir.path(), "setup-token-123").await.unwrap();
    assert!(state_restarted.adaptive_tuning.is_emergency_disabled());
}

#[tokio::test]
async fn adaptive_tuning_monitor_mode_rejection_and_deduplication() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123").await.unwrap();

    let admin = repository::insert_initial_admin(&state.db, "admin@example.com", &hash_password("admin12345678").unwrap()).await.unwrap().unwrap();
    repository::create_session(&state.db, admin.id, &token_hash("admin-token"), "2099-01-01T00:00:00Z").await.unwrap();

    let app = router(state.clone());

    // Host 2 defaults to Monitor mode
    let rec = PolicyRecommendation {
        id: 0,
        host_id: 2,
        patch: PolicyPatch {
            capacity: Some(30),
            refill_per_second: Some(3.0),
            waf_mode: None,
        },
        confidence: 0.95,
        reason: "Spike on host 2".into(),
        created_at: chrono::Utc::now(),
        applied: false,
        applied_at: None,
        previous_config_json: None,
    };

    // Deduplication test: inserting same recommendation twice returns None on second call
    let id1 = repository::insert_tuning_recommendation_dedup(&state.db, &rec, 300).await.unwrap();
    assert!(id1.is_some());
    let id2 = repository::insert_tuning_recommendation_dedup(&state.db, &rec, 300).await.unwrap();
    assert!(id2.is_none());

    let rec_id = id1.unwrap();

    // Applying recommendation on Monitor mode host returns BAD_REQUEST (400)
    let req = Request::builder()
        .uri(format!("/api/adaptive-tuning/recommendations/{rec_id}/apply"))
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
