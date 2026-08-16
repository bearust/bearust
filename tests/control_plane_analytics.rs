use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::control_plane::{build_state, router};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn analytics_requires_authentication() {
    let dir = tempdir().unwrap();
    let app = router(
        build_state("sqlite::memory:", dir.path(), "setup-token")
            .await
            .unwrap(),
    );
    let response = app
        .oneshot(
            Request::get("/api/analytics/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn analytics_rejects_malformed_or_oversized_filters() {
    let dir = tempdir().unwrap();
    let app = router(
        build_state("sqlite::memory:", dir.path(), "setup-token")
            .await
            .unwrap(),
    );
    let setup = app
        .clone()
        .oneshot(
            Request::post("/api/setup/initialize")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"admin@example.com","password":"correct horse battery"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    for uri in [
        "/api/analytics/summary?from=not-a-date",
        "/api/analytics/timeseries?limit=10081",
        "/api/analytics/summary?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
