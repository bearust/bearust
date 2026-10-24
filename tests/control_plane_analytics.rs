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

#[tokio::test]
async fn analytics_history_serves_durable_rollups_beyond_minute_retention() {
    use bearust::analytics::{PersistedAnalyticsBucket, RollupGranularity};
    use bearust::control_plane::repository;
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let old_hour =
        RollupGranularity::Hour.truncate(chrono::Utc::now() - chrono::Duration::days(20));
    let row: PersistedAnalyticsBucket = serde_json::from_value(serde_json::json!({
        "timestamp": old_hour, "proxy_host_id": 3, "requests": 42,
        "status_2xx": 40, "status_3xx": 0, "status_4xx": 2, "status_5xx": 0,
        "waf_blocks": 1, "bot_blocks": 0, "bot_challenges": 0, "rate_limited": 0,
        "bandwidth_bytes": 4096, "latency_histogram": [0,0,42,0,0,0,0,0,0,0,0,0,0,0],
        "top_endpoints": [{"key": "/api", "count": 42}], "top_upstreams": [],
        "top_attacker_ips": [], "attack_types": []
    }))
    .unwrap();
    repository::persist_analytics_rollups(&state.db, RollupGranularity::Hour, &[row])
        .await
        .unwrap();
    let app = router(state);
    let cookie = admin_cookie(&app).await;
    let from = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    let query =
        serde_urlencoded::to_string([("from", from.as_str()), ("interval", "hour")]).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/analytics/history?{query}"))
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
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["summary"]["requests"], 42);
    assert_eq!(json["timeseries"].as_array().unwrap().len(), 1);
    assert_eq!(json["dimensions"]["top_endpoints"][0]["key"], "/api");

    for uri in [
        "/api/analytics/history",
        "/api/analytics/history?from=bad",
        "/api/analytics/history?from=2020-01-01T00:00:00Z&interval=minute",
        "/api/analytics/history?from=2020-01-01T00:00:00Z&interval=hour",
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
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

async fn admin_cookie(app: &axum::Router) -> String {
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
    login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
