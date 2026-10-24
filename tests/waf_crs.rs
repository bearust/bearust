//! OWASP CRS through the WAF settings API and the proxy's evaluator.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::{build_state, router, AppState};
use bearust::waf::{evaluate, InspectionContext, WafDecision};
use serde_json::{json, Value};
use tower::util::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, String, Option<String>) {
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
    (status, String::from_utf8_lossy(&body).into_owned(), cookie)
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

fn request(path: &str, query: &str) -> InspectionContext {
    InspectionContext {
        method: "GET".into(),
        path: path.into(),
        query: query.into(),
        headers: vec![
            ("Host".into(), "shop.example.com".into()),
            (
                "User-Agent".into(),
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0".into(),
            ),
            ("Accept".into(), "text/html".into()),
        ],
        body: Vec::new(),
    }
}

#[tokio::test]
async fn enabling_crs_blocks_attacks_and_leaves_normal_traffic_alone() {
    let (app, state, cookie) = admin().await;
    let (status, body, _) = call(&app, "GET", "/api/waf/seclang", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    let initial: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (
            initial["crs_enabled"].as_bool(),
            initial["active_rules"].as_u64()
        ),
        (Some(false), Some(0))
    );
    assert_eq!(initial["crs_version"], "4.7.0");

    // Invalid custom rules are rejected with a useful message.
    let (status, body, _) = call(
        &app,
        "PUT",
        "/api/waf/seclang",
        Some(&cookie),
        Some(json!({
            "crs_enabled": false, "paranoia_level": 1, "inbound_threshold": 5,
            "custom_rules": "SecRule ARGS \"@frobnicate x\" \"id:10001,phase:2,deny\""
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("frobnicate"), "{body}");

    let (status, body, _) = call(&app, "PUT", "/api/waf/seclang", Some(&cookie), Some(json!({
        "crs_enabled": true, "paranoia_level": 1, "inbound_threshold": 5,
        "custom_rules": "SecRule REQUEST_HEADERS:X-Internal \"@streq letmein\" \"id:10001,phase:1,deny,msg:'custom'\""
    }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_str::<Value>(&body).unwrap()["active_rules"]
            .as_u64()
            .unwrap()
            > 400
    );
    let (status, _, _) = call(
        &app,
        "PATCH",
        "/api/waf/config",
        Some(&cookie),
        Some(json!({"mode": "block"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let snapshot = state.waf.snapshot();
    let sqli = evaluate(
        &snapshot,
        &request("/products", "id=1%27%20OR%201%3D1--%20"),
    );
    assert_eq!(sqli.decision, WafDecision::Block);
    assert!(
        sqli.matched_rule_ids.contains(&949110),
        "{:?}",
        sqli.matched_rule_ids
    );
    assert!(
        sqli.categories.iter().any(|c| c == "sqli"),
        "{:?}",
        sqli.categories
    );

    let xss = evaluate(
        &snapshot,
        &request("/search", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    );
    assert_eq!(xss.decision, WafDecision::Block);

    let mut custom = request("/", "");
    custom.headers.push(("X-Internal".into(), "letmein".into()));
    assert_eq!(evaluate(&snapshot, &custom).decision, WafDecision::Block);

    for (path, query) in [
        ("/", ""),
        ("/products/42", "page=2&sort=price"),
        ("/search", "q=red+shoes"),
    ] {
        let normal = evaluate(&snapshot, &request(path, query));
        assert_eq!(
            normal.decision,
            WafDecision::Allow,
            "{path}?{query}: {:?}",
            normal.matched_rule_ids
        );
    }

    // Monitor-only logs instead of blocking.
    call(
        &app,
        "PATCH",
        "/api/waf/config",
        Some(&cookie),
        Some(json!({"mode": "monitor-only"})),
    )
    .await;
    let monitored = evaluate(
        &state.waf.snapshot(),
        &request("/products", "id=1%27%20OR%201%3D1--%20"),
    );
    assert_eq!(monitored.decision, WafDecision::Log);
}
