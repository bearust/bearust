use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use bearust::control_plane::{build_state, router};
use tower::util::ServiceExt;

async fn app() -> (Router, String, String) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let app = router(build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap());
    let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/setup/initialize").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#)).unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery"}"#)).unwrap()).await.unwrap();
    let admin = login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    let create = app.clone().oneshot(Request::builder().method("POST").uri("/api/users").header("cookie", &admin).header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#)).unwrap()).await.unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123"}"#)).unwrap()).await.unwrap();
    let viewer = login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    (app, admin, viewer)
}

async fn call(app: Router, method: &str, uri: &str, cookie: &str, body: &str) -> (StatusCode, String) {
    let response = app.oneshot(Request::builder().method(method).uri(uri).header("cookie", cookie).header("content-type", "application/json").body(Body::from(body.to_owned())).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn bot_policy_defaults_to_monitor_and_requires_rbac() {
    let (app, admin, viewer) = app().await;
    assert_eq!(call(app.clone(), "GET", "/api/bot/config", &viewer, "").await.0, StatusCode::FORBIDDEN);
    let (status, body) = call(app.clone(), "GET", "/api/bot/config", &admin, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("monitor"));
    assert_eq!(call(app, "PATCH", "/api/bot/config", &admin, r#"{"mode":"challenge","threshold":70}"#).await.0, StatusCode::OK);
}

#[tokio::test]
async fn trusted_crawler_crud_emits_redacted_event() {
    let (app, admin, _) = app().await;
    let (status, body) = call(app.clone(), "POST", "/api/bot/trusted-crawlers", &admin, r#"{"user_agent":"Googlebot","domain":"googlebot.com"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_i64().unwrap();
    let (status, list) = call(app.clone(), "GET", "/api/bot/trusted-crawlers", &admin, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.contains("googlebot.com"));
    assert_eq!(call(app, "DELETE", &format!("/api/bot/trusted-crawlers/{id}"), &admin, "").await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn oversized_and_over_limit_imports_are_rejected_before_mutation() {
    let (app, admin, _) = app().await;
    let (status, _) = call(app.clone(), "POST", "/api/bot/trusted-crawlers", &admin, r#"{"user_agent":"Googlebot","domain":"googlebot.com"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let huge = format!("version = 1\nmode = 'block'\n#{}", "x".repeat(70_000));
    assert_eq!(call(app.clone(), "POST", "/api/bot/config/import", &admin, &huge).await.0, StatusCode::BAD_REQUEST);
    let mut over = String::from("version = 1\n");
    for _ in 0..33 { over.push_str("[[trusted_crawlers]]\nuser_agent = 'bot'\ndomain = 'example.com'\n\n"); }
    assert_eq!(call(app.clone(), "POST", "/api/bot/config/import", &admin, &over).await.0, StatusCode::BAD_REQUEST);
    let (_, exported) = call(app, "GET", "/api/bot/config/export", &admin, "").await;
    assert!(exported.contains("googlebot.com"));
    assert!(exported.contains("mode = 'monitor'"));
}
