use axum::{body::Body, http::{Request, StatusCode}};
use tower::ServiceExt;
use tempfile::tempdir;
use bearust::control_plane::{build_state, router};

#[tokio::test]
async fn analytics_requires_authentication() {
    let dir = tempdir().unwrap();
    let app = router(build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap());
    let response = app.oneshot(Request::get("/api/analytics/summary").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn analytics_rejects_malformed_or_oversized_filters() {
    let dir = tempdir().unwrap();
    let app = router(build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap());
    for uri in ["/api/analytics/summary?from=not-a-date", "/api/analytics/timeseries?limit=1441", "/api/analytics/summary?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z"] {
        let response = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
