//! Feedback-driven retraining: false-positive reports demote rules, and
//! demotions can be reverted.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::{build_state, router, AppState};
use bearust::waf::{evaluate, InspectionContext};
use serde_json::{json, Value};
use tower::util::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(
            req.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
        cookie,
    )
}

async fn admin() -> (Router, AppState, String) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let app = router(state.clone());
    call(&app, "POST", "/api/setup/initialize", None, Some(json!({
        "email": "admin@example.com", "password": "correct horse battery", "setup_token": "setup-token"
    }))).await;
    let (_, _, cookie) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "email": "admin@example.com", "password": "correct horse battery"
        })),
    )
    .await;
    (app, state, cookie.unwrap())
}

fn sqli() -> InspectionContext {
    InspectionContext {
        method: "GET".into(),
        path: "/".into(),
        query: "id=1%27%20OR%201%3D1--%20".into(),
        headers: vec![
            ("Host".into(), "example.com".into()),
            ("User-Agent".into(), "Mozilla/5.0".into()),
        ],
        body: Vec::new(),
    }
}

#[tokio::test]
async fn false_positive_feedback_demotes_rules_and_reverts() {
    let (app, state, cookie) = admin().await;
    let cookie = Some(cookie.as_str());
    let (status, _, _) = call(
        &app,
        "PUT",
        "/api/waf/seclang",
        cookie,
        Some(json!({
            "crs_enabled": true, "paranoia_level": 1, "inbound_threshold": 5, "custom_rules": ""
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, rule, _) = call(
        &app,
        "POST",
        "/api/waf/rules",
        cookie,
        Some(json!({
            "name": "custom", "category": "custom", "severity": "medium", "action": "block",
            "matcher": {"field": "query", "pattern": "evil"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let custom_id = rule["id"].as_i64().unwrap();
    assert!(evaluate(&state.waf.snapshot(), &sqli())
        .matched_rule_ids
        .contains(&942100));

    let report = |rule_id: i64, label: &'static str| {
        let app = app.clone();
        async move {
            let (status, _, _) = call(
                &app,
                "POST",
                "/api/waf/feedback",
                cookie,
                Some(json!({ "rule_id": rule_id, "label": label })),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
    };
    for _ in 0..5 {
        report(custom_id, "false_positive").await;
        report(942100, "false_positive").await;
    }
    report(942100, "true_positive").await;
    // Mixed feedback stays.
    for _ in 0..5 {
        report(941100, "false_positive").await;
        report(941100, "true_positive").await;
    }

    let (_, recs, _) = call(
        &app,
        "GET",
        "/api/waf/retrain/recommendations",
        cookie,
        None,
    )
    .await;
    let mut ids: Vec<i64> = recs
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule_id"].as_i64().unwrap())
        .collect();
    ids.sort();
    let mut expected = vec![custom_id, 942100];
    expected.sort();
    assert_eq!(ids, expected);

    // Off: nothing is applied.
    let (status, _, _) = call(&app, "POST", "/api/waf/retrain/run", cookie, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, _) = call(
        &app,
        "PUT",
        "/api/waf/retrain",
        cookie,
        Some(json!({
            "mode": "recommend", "min_reports": 5, "false_positive_percent": 80, "window_days": 30
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, applied, _) = call(&app, "POST", "/api/waf/retrain/run", cookie, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(applied.as_array().unwrap().len(), 2);

    let (_, rules, _) = call(&app, "GET", "/api/waf/rules", cookie, None).await;
    let custom = rules
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"].as_i64() == Some(custom_id))
        .unwrap();
    assert_eq!(custom["action"], "log");
    assert!(!evaluate(&state.waf.snapshot(), &sqli())
        .matched_rule_ids
        .contains(&942100));
    let (_, tunings, _) = call(&app, "GET", "/api/waf/retrain/tunings", cookie, None).await;
    assert_eq!(tunings.as_array().unwrap().len(), 2);
    // Already-demoted rules are not recommended again.
    let (_, recs, _) = call(
        &app,
        "GET",
        "/api/waf/retrain/recommendations",
        cookie,
        None,
    )
    .await;
    assert!(recs.as_array().unwrap().is_empty());

    // Revert restores the original behaviour.
    let (status, _, _) = call(
        &app,
        "DELETE",
        "/api/waf/retrain/tunings/942100",
        cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(evaluate(&state.waf.snapshot(), &sqli())
        .matched_rule_ids
        .contains(&942100));
    let (status, _, _) = call(
        &app,
        "DELETE",
        &format!("/api/waf/retrain/tunings/{custom_id}"),
        cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, rules, _) = call(&app, "GET", "/api/waf/rules", cookie, None).await;
    let custom = rules
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"].as_i64() == Some(custom_id))
        .unwrap();
    assert_eq!(custom["action"], "block");
}
