use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::{build_state, router};
use serde_json::Value;
use tower::util::ServiceExt;

async fn app() -> (Router, String) {
    let directory = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let app = router(
        build_state("sqlite::memory:", directory.path(), "setup-token")
            .await
            .unwrap(),
    );
    let setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/setup/initialize")
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
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
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
    (app, cookie)
}

async fn request(
    app: Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: &str,
) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

#[tokio::test]
async fn ip_policies_and_feedback_are_persisted_and_reloaded() {
    let (app, cookie) = app().await;
    let (status, rule) = request(
        app.clone(),
        "POST",
        "/api/ip-security/rules",
        &cookie,
        r#"{"cidr":"203.0.113.0/24","action":"block","score":90,"country_code":"ID","enabled":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = rule["id"].as_i64().unwrap();
    assert_eq!(rule["country_code"], "ID");

    let (status, rules) = request(app.clone(), "GET", "/api/ip-security/rules", &cookie, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rules.as_array().unwrap().len(), 1);
    assert_eq!(
        request(
            app.clone(),
            "PATCH",
            &format!("/api/ip-security/rules/{id}"),
            &cookie,
            r#"{"enabled":false,"action":"monitor"}"#,
        )
        .await
        .0,
        StatusCode::OK
    );

    let (status, feedback) = request(
        app.clone(),
        "POST",
        "/api/waf/feedback",
        &cookie,
        &format!(
            r#"{{"request_id":"req-123","rule_id":{id},"label":"false_positive","note":"safe integration test"}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(feedback["label"], "false_positive");
    assert_eq!(
        request(
            app,
            "DELETE",
            &format!("/api/ip-security/rules/{id}"),
            &cookie,
            ""
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn analytics_retention_is_admin_configurable_and_bounded() {
    let (app, cookie) = app().await;
    let (status, current) =
        request(app.clone(), "GET", "/api/analytics/retention", &cookie, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["retention_minutes"], 1440);
    let (status, updated) = request(
        app.clone(),
        "PATCH",
        "/api/analytics/retention",
        &cookie,
        r#"{"retention_minutes":10080}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["retention_minutes"], 10080);
    assert_eq!(
        request(
            app,
            "PATCH",
            "/api/analytics/retention",
            &cookie,
            r#"{"retention_minutes":30}"#,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn host_auth_secret_is_hashed_and_never_returned() {
    let (app, cookie) = app().await;
    let (status, host) = request(
        app.clone(),
        "POST",
        "/api/proxy-hosts",
        &cookie,
        r#"{"name":"Private API","domain":"private.example.com","upstream_host":"127.0.0.1","upstream_port":8080}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let host_id = host["id"].as_i64().unwrap();
    let (status, auth) = request(
        app.clone(),
        "PUT",
        &format!("/api/proxy-hosts/{host_id}/auth"),
        &cookie,
        r#"{"enabled":true,"realm":"Private API","username":"alice","password":"a sufficiently long secret"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(auth["enabled"], true);
    assert!(auth.get("password_hash").is_none());
    assert!(auth.get("password").is_none());

    let (status, auth) = request(
        app,
        "GET",
        &format!("/api/proxy-hosts/{host_id}/auth"),
        &cookie,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(auth["username"], "alice");
    assert!(auth.get("password_hash").is_none());
}
