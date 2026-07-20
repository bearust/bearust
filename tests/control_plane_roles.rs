use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use bearust::control_plane::{build_state, repository, router};
use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, Row};
use std::{str::FromStr, time::Duration};
use tower::util::ServiceExt;

async fn app() -> (Router, sqlx::SqlitePool) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    (router(state.clone()), state.db)
}

async fn request(app: Router, method: &str, uri: &str, cookie: Option<&str>, body: &str) -> (StatusCode, String, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(cookie) = cookie { builder = builder.header("cookie", cookie); }
    let response = app.oneshot(builder.body(Body::from(body.to_owned())).unwrap()).await.unwrap();
    let status = response.status();
    let cookie = response.headers().get("set-cookie").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap(), cookie)
}

async fn login(app: Router, email: &str, password: &str) -> String {
    request(app, "POST", "/api/auth/login", None, &format!(r#"{{"email":"{email}","password":"{password}"}}"#)).await.2.unwrap().split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn delete_role_rolls_back_when_commit_is_busy() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("roles.sqlite");
    let url = format!("sqlite://{}", db_path.display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .unwrap()
                .create_if_missing(true)
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(0)),
        )
        .await
        .unwrap();
    repository::migrate(&pool).await.unwrap();
    let role = repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
        .await
        .unwrap();

    let blocker = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&url)
                .unwrap()
                .create_if_missing(true)
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(0)),
        )
        .await
        .unwrap();
    let mut blocker_conn = blocker.acquire().await.unwrap();
    sqlx::query("BEGIN").execute(&mut *blocker_conn).await.unwrap();
    sqlx::query("SELECT id FROM roles WHERE id=?")
        .bind(role.id)
        .fetch_one(&mut *blocker_conn)
        .await
        .unwrap();

    let err = repository::delete_role(&pool, role.id).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("busy") || err.to_string().to_lowercase().contains("locked"));

    drop(blocker_conn);
    drop(blocker);

    assert!(repository::get_role(&pool, role.id).await.unwrap().is_some());

    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await.unwrap();
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
}

#[tokio::test]
async fn admin_role_lifecycle_and_audits_are_safe() {
    let (app, db) = app().await;
    assert_eq!(request(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let (status, body, _) = request(app.clone(), "GET", "/api/roles", Some(&admin), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap().as_array().unwrap().len(), 3);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permissions").fetch_one(&db).await.unwrap(), 10);
    let (status, body, _) = request(app.clone(), "POST", "/api/roles", Some(&admin), r#"{"slug":" Security_Auditor ","name":"Security Auditor","permissions":["audit_logs.read"]}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let role = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    assert_eq!(role["slug"], "security-auditor");
    let id = role["id"].as_i64().unwrap();
    let (status, body, _) = request(app.clone(), "PATCH", &format!("/api/roles/{id}"), Some(&admin), r#"{"name":"Updated","permissions":["audit_logs.read","sessions.revoke"]}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["permissions"].as_array().unwrap().len(), 2);
    assert_eq!(request(app.clone(), "DELETE", &format!("/api/roles/{id}"), Some(&admin), "").await.0, StatusCode::NO_CONTENT);
    let events: Vec<String> = sqlx::query_scalar("SELECT event FROM audit_logs WHERE event LIKE 'role_%'").fetch_all(&db).await.unwrap();
    for event in ["role_created", "role_updated", "role_permissions_changed", "role_deleted"] { assert!(events.iter().any(|item| item == event), "missing {event}"); }
}

#[tokio::test]
async fn non_admin_and_invalid_role_requests_are_denied_with_envelopes_and_audits() {
    let (app, db) = app().await;
    request(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await;
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    request(app.clone(), "POST", "/api/users", Some(&admin), r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#).await;
    let viewer = login(app.clone(), "viewer@example.com", "viewer password 123").await;
    assert_eq!(request(app.clone(), "GET", "/api/roles", Some(&viewer), "").await.0, StatusCode::FORBIDDEN);
    let (status, body, _) = request(app.clone(), "POST", "/api/roles", Some(&admin), r#"{"slug":"bad","name":"Bad","permissions":["not-a-permission"]}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["code"], "invalid_input");
    assert_eq!(request(app.clone(), "POST", "/api/roles", Some(&admin), r#"{"slug":"bad","name":"Bad","scope":"host"}"#).await.0, StatusCode::BAD_REQUEST);
    let denied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event='role_mutation_denied'").fetch_one(&db).await.unwrap();
    assert!(denied >= 3);
}

#[tokio::test]
async fn built_in_update_and_assigned_custom_delete_conflict() {
    let (app, db) = app().await;
    request(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await;
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let (status, _, _) = request(app.clone(), "PATCH", "/api/roles/1", Some(&admin), r#"{"name":"Nope"}"#).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let role = bearust::control_plane::repository::insert_role(&db, "assigned", "Assigned", "").await.unwrap();
    bearust::control_plane::repository::insert_user(&db, "assigned@example.com", "hash", &role.slug).await.unwrap();
    assert_eq!(request(app, "DELETE", &format!("/api/roles/{}", role.id), Some(&admin), "").await.0, StatusCode::CONFLICT);
}
