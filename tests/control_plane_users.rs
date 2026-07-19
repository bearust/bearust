use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use bearust::control_plane::{build_state, router};
use sqlx::Row;
use tower::util::ServiceExt;

async fn app() -> (Router, sqlx::SqlitePool) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    (router(state.clone()), state.db)
}

async fn json(app: Router, method: &str, uri: &str, cookie: Option<&str>, body: &str) -> (StatusCode, String, Option<String>) {
    let mut request = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(cookie) = cookie { request = request.header("cookie", cookie); }
    let response = app.oneshot(request.body(Body::from(body.to_owned())).unwrap()).await.unwrap();
    let status = response.status();
    let cookie = response.headers().get("set-cookie").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap(), cookie)
}

async fn login(app: Router, email: &str, password: &str) -> (StatusCode, Option<String>) {
    let (status, _, cookie) = json(app, "POST", "/api/auth/login", None,
        &format!(r#"{{"email":"{email}","password":"{password}"}}"#)).await;
    (status, cookie.map(|v| v.split(';').next().unwrap().to_owned()))
}

#[tokio::test]
async fn admin_user_crud_redacts_secrets_and_enforces_invariants() {
    let (app, db) = app().await;
    let (status, _, _) = json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let cookie = cookie.unwrap();
    let (status, body, _) = json(app.clone(), "GET", "/api/users", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("password_hash"));
    let (status, body, _) = json(app.clone(), "POST", "/api/users", Some(&cookie), r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!body.contains("password_hash"));
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_i64().unwrap();
    let (status, _, _) = json(app.clone(), "PATCH", &format!("/api/users/{id}"), Some(&cookie), r#"{"disabled":true}"#).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = login(app.clone(), "operator@example.com", "operator password 123").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = json(app.clone(), "DELETE", &format!("/api/users/{id}"), Some(&cookie), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = json(app.clone(), "DELETE", "/api/users/1", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let rows = sqlx::query("SELECT event,details FROM audit_logs WHERE event LIKE 'user_%' ORDER BY id")
        .fetch_all(&db).await.unwrap();
    assert!(rows.iter().any(|r| r.get::<String, _>("event") == "user_created"));
    assert!(rows.iter().any(|r| r.get::<String, _>("event") == "user_disabled"));
    assert!(rows.iter().any(|r| r.get::<String, _>("event") == "user_deleted"));
    for row in rows { assert!(!row.get::<String, _>("details").contains("password")); }
}

#[tokio::test]
async fn role_authorization_and_denials_are_enforced_and_audited() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    let (_, op_body, _) = json(app.clone(), "POST", "/api/users", Some(&admin_cookie), r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#).await;
    let op_id = serde_json::from_str::<serde_json::Value>(&op_body).unwrap()["id"].as_i64().unwrap();
    let (_, viewer_body, _) = json(app.clone(), "POST", "/api/users", Some(&admin_cookie), r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#).await;
    let viewer_id = serde_json::from_str::<serde_json::Value>(&viewer_body).unwrap()["id"].as_i64().unwrap();
    let (_, op_cookie) = login(app.clone(), "operator@example.com", "operator password 123").await;
    let (_, viewer_cookie) = login(app.clone(), "viewer@example.com", "viewer password 123").await;
    for cookie in [op_cookie.as_deref(), viewer_cookie.as_deref()] {
        assert_eq!(json(app.clone(), "GET", "/api/users", cookie, "").await.0, StatusCode::FORBIDDEN);
        assert_eq!(json(app.clone(), "PATCH", &format!("/api/users/{op_id}"), cookie, r#"{"disabled":true}"#).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(json(app.clone(), "PATCH", "/api/users/1", Some(&admin_cookie), r#"{"disabled":true}"#).await.0, StatusCode::FORBIDDEN);
    assert_eq!(json(app.clone(), "DELETE", "/api/users/1", Some(&admin_cookie), "").await.0, StatusCode::FORBIDDEN);
    assert_eq!(json(app.clone(), "PATCH", &format!("/api/users/{viewer_id}"), Some(&admin_cookie), r#"{"role":"bogus","disabled":true}"#).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(json(app.clone(), "PATCH", "/api/users/9999", Some(&admin_cookie), r#"{"disabled":true}"#).await.0, StatusCode::NOT_FOUND);
    let rows = sqlx::query("SELECT event,details FROM audit_logs WHERE event LIKE '%denied' OR event LIKE 'user_%_denied'").fetch_all(&db).await.unwrap();
    assert!(rows.len() >= 5);
    assert!(rows.iter().all(|r| r.get::<String, _>("details").contains("reason=")));
}

#[tokio::test]
async fn combined_patch_is_atomic_when_last_admin_would_be_removed() {
    let (app, _) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let cookie = cookie.unwrap();
    let (status, _body, _) = json(app.clone(), "PATCH", "/api/users/1", Some(&cookie), r#"{"role":"viewer"}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body, _) = json(app.clone(), "GET", "/api/auth/me", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("admin"));
}
