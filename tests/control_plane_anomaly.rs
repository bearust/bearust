use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::control_plane::auth::{hash_password, token_hash};
use bearust::control_plane::{build_state, repository, router};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn anomalies_requires_authentication() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap();
    let app = router(state);

    let req = Request::builder()
        .uri("/api/analytics/anomalies")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn anomalies_list_and_ack() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap();

    let admin = repository::insert_initial_admin(
        &state.db,
        "admin@example.com",
        &hash_password("admin12345678").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    repository::create_session(
        &state.db,
        admin.id,
        &token_hash("admin-token"),
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    let app = router(state.clone());

    // GET anomalies (empty initial)
    let req = Request::builder()
        .uri("/api/analytics/anomalies")
        .method("GET")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // POST ack unknown anomaly
    let req = Request::builder()
        .uri("/api/analytics/anomalies/999/ack")
        .method("POST")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
