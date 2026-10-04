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
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    for (minute, latency) in [(61, 10), (62, 1000)] {
        state.analytics.record(bearust::analytics::AnalyticsEvent {
            proxy_host_id: 1,
            timestamp: chrono::DateTime::from_timestamp(minute * 60, 0).unwrap(),
            status_code: 200,
            latency_ms: latency,
            security: Default::default(),
        });
    }
    let app = router(state);
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
        "/api/analytics/timeseries?interval=week",
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
    for (query, length, requests) in [
        ("", 2, 1),
        ("?interval=minute", 2, 1),
        ("?interval=hour&limit=1", 1, 2),
        ("?interval=day", 1, 2),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/analytics/timeseries{query}"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), length);
        assert_eq!(rows[0]["requests"], requests);
        if length == 1 {
            assert_eq!(rows[0]["p50_ms"], 10);
            assert_eq!(rows[0]["p95_ms"], 1000);
        }
    }
}
