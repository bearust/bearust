use bearust::control_plane::{build_state, router};
use axum::{body::Body, http::{Request, StatusCode}, Router};
use tower::util::ServiceExt;

#[tokio::test]
async fn creates_schema_and_reports_first_run_status() {
    let dir = tempfile::tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    let app: Router = router(state);
    let response = app.oneshot(Request::builder().uri("/api/setup/status").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], br#"{"initialized":false}"#);
}
