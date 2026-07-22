use bearust::control_plane::{build_state, router, repository};
use bearust::control_plane::auth::{token_hash, hash_password};
use bearust::adaptive_tuning::{TuningMode, TuningPolicy};
use axum::{body::Body, http::{Request, StatusCode}};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn adaptive_tuning_policy_endpoint() {
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

    // PUT policy update for host 1
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

    // Emergency disable toggle
    let req = Request::builder()
        .uri("/api/adaptive-tuning/emergency-disable")
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
