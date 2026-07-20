use bearust::control_plane::models::AuditLogQuery;
use bearust::control_plane::repository;
use sqlx::SqlitePool;
use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}};
use tower::util::ServiceExt;
use bearust::control_plane::{build_state, router};
use bearust::control_plane::auth;

async fn pool() -> SqlitePool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

async fn insert_audit(pool: &SqlitePool, user_id: Option<i64>, event: &str, details: &str, created_at: &str) {
    sqlx::query("INSERT INTO audit_logs(user_id,event,details,created_at) VALUES(?,?,?,?)")
        .bind(user_id)
        .bind(event)
        .bind(details)
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
}

async fn http_app() -> axum::Router {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    router(state)
}

async fn request(app: axum::Router, uri: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = cookie { req = req.header("cookie", cookie); }
    let response = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn login(app: axum::Router, email: &str, password: &str) -> String {
    let response = app.oneshot(Request::builder().method("POST").uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"email":"{email}","password":"{password}"}}"#))).unwrap()).await.unwrap();
    response.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn audit_log_endpoint_authenticates_roles_validates_query_and_redacts_secrets() {
    let app = http_app().await;
    assert_eq!(request(app.clone(), "/api/audit-logs", None).await.0, StatusCode::UNAUTHORIZED);
    let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/setup/initialize")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#)).unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let (_, op_body, _) = {
        let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/users")
            .header("cookie", &admin).header("content-type", "application/json")
            .body(Body::from(r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#)).unwrap()).await.unwrap();
        let status = response.status(); let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), None::<String>)
    };
    assert!(!op_body.is_empty());
    let (_, viewer_body, _) = {
        let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/users")
            .header("cookie", &admin).header("content-type", "application/json")
            .body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#)).unwrap()).await.unwrap();
        let status = response.status(); let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), None::<String>)
    };
    assert!(!viewer_body.is_empty());
    let operator = login(app.clone(), "operator@example.com", "operator password 123").await;
    let viewer = login(app.clone(), "viewer@example.com", "viewer password 123").await;
    for cookie in [&admin, &operator, &viewer] {
        let (status, body) = request(app.clone(), "/api/audit-logs?page=1&page_size=25", Some(cookie)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("password_hash") && !body.contains("token_hash") && !body.contains("setup-token"));
    }
    for uri in ["/api/audit-logs?page=0", "/api/audit-logs?page_size=0", "/api/audit-logs?page_size=101", "/api/audit-logs?actor_id=-1", "/api/audit-logs?from=not-a-date"] {
        let (status, body) = request(app.clone(), uri, Some(&admin)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_input"));
        assert!(!body.contains("password_hash") && !body.contains("token_hash"));
    }
}

#[tokio::test]
async fn audit_log_endpoint_rejects_unknown_persisted_role() {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    sqlx::query("INSERT INTO users(email,password_hash,role,created_at,disabled) VALUES(?,?,?,?,0)")
        .bind("unknown@example.com").bind("hash").bind("future-role").bind("2026-07-20T00:00:00Z")
        .execute(&state.db).await.unwrap();
    let unknown_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email=?").bind("unknown@example.com").fetch_one(&state.db).await.unwrap();
    let token = "unknown-session";
    repository::create_session(&state.db, unknown_id, &auth::token_hash(token), "2099-01-01T00:00:00Z").await.unwrap();
    let (status, body) = request(router(state), "/api/audit-logs", Some(&format!("bearust_session={token}"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.contains("future-role"));
}

#[tokio::test]
async fn repository_lists_filtered_paginated_rows() {
    let pool = pool().await;
    let active = repository::insert_user(&pool, "active@example.com", "hash", "operator")
        .await
        .unwrap();
    let deleted = repository::insert_user(&pool, "deleted@example.com", "hash", "viewer")
        .await
        .unwrap();

    insert_audit(&pool, None, "system_started", "reason=boot", "2026-07-20T10:00:00Z").await;
    insert_audit(&pool, Some(active.id), "user_updated", "target=proxy;reason=changed", "2026-07-20T10:01:00Z").await;
    insert_audit(&pool, Some(deleted.id), "user_deleted", "target=account;reason=retired", "2026-07-20T10:02:00Z").await;
    repository::delete_user(&pool, deleted.id).await.unwrap();
    insert_audit(&pool, Some(active.id), "user_login", "reason=success", "2026-07-20T10:03:00Z").await;

    let page = repository::list_audit_logs(
        &pool,
        &AuditLogQuery { event: None, actor_id: None, from: None, to: None, q: None, page: 1, page_size: 2 },
    ).await.unwrap();
    assert_eq!(page.page, 1);
    assert_eq!(page.page_size, 2);
    assert_eq!(page.total, 4);
    assert_eq!(page.items.iter().map(|item| item.event.as_str()).collect::<Vec<_>>(), ["user_login", "user_deleted"]);
    assert_eq!(page.items[0].actor, "active@example.com");
    assert_eq!(page.items[1].actor, "deleted-user");

    let second = repository::list_audit_logs(
        &pool,
        &AuditLogQuery { event: None, actor_id: None, from: None, to: None, q: None, page: 2, page_size: 2 },
    ).await.unwrap();
    assert_eq!(second.items.iter().map(|item| item.event.as_str()).collect::<Vec<_>>(), ["user_updated", "system_started"]);
    assert_eq!(second.items[1].actor, "system");

    insert_audit(&pool, Some(active.id), "credential_event", r#"{"password":"super-secret","provider_token":"provider-secret","request_body":{"private_key":"pem-secret"},"reason":"safe"}"#, "2026-07-20T10:04:00Z").await;

    let event = repository::list_audit_logs(&pool, &AuditLogQuery { event: Some("user_updated".into()), actor_id: None, from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(event.total, 1);
    assert_eq!(event.items[0].details, "target=proxy;reason=changed");

    let secret = repository::list_audit_logs(&pool, &AuditLogQuery { event: Some("credential_event".into()), actor_id: None, from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(secret.items[0].details, r#"{"password":"[REDACTED]","provider_token":"[REDACTED]","reason":"safe","request_body":"[REDACTED]"}"#);

    insert_audit(&pool, Some(active.id), "overlap_event", "password=password=chained-secret", "2026-07-20T10:05:00Z").await;
    let overlap = repository::list_audit_logs(&pool, &AuditLogQuery { event: Some("overlap_event".into()), actor_id: None, from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(overlap.items[0].details, "password=[REDACTED]");

    let actor = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: Some(active.id), from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(actor.total, 4);

    let time = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: None, from: Some("2026-07-20T10:01:00Z".into()), to: Some("2026-07-20T10:02:00Z".into()), q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(time.items.iter().map(|item| item.event.as_str()).collect::<Vec<_>>(), ["user_deleted", "user_updated"]);

    let text = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: None, from: None, to: None, q: Some("proxy".into()), page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(text.total, 1);
    assert_eq!(text.items[0].event, "user_updated");
}
