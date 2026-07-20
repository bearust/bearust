use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::{build_state, router};
use bearust::control_plane::repository;
use tower::util::ServiceExt;
use sqlx::Row;

#[tokio::test]
async fn creates_schema_and_reports_first_run_status() {
    let dir = tempfile::tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let app: Router = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/setup/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], br#"{"initialized":false}"#);
}

async fn test_pool() -> sqlx::SqlitePool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn existing_users_migrate_to_default_enabled_and_list_without_hashes() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL,created_at TEXT NOT NULL)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(email,password_hash,role,created_at) VALUES('old@example.com','secret-hash','admin','2024-01-01T00:00:00Z')")
        .execute(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let users = repository::list_users(&pool).await.unwrap();
    assert_eq!(users.len(), 1);
    assert!(!users[0].disabled);
    assert_eq!(users[0].email, "old@example.com");
    let columns = sqlx::query("PRAGMA table_info(users)").fetch_all(&pool).await.unwrap();
    assert!(columns.iter().any(|r| r.get::<String, _>("name") == "disabled"));
}

#[tokio::test]
async fn user_lifecycle_updates_role_status_and_sessions() {
    let pool = test_pool().await;
    let admin = repository::insert_user(&pool, "admin@example.com", "hash", "admin").await.unwrap();
    let operator = repository::insert_user(&pool, "operator@example.com", "hash", "operator").await.unwrap();
    repository::create_session(&pool, operator.id, "session-hash", "2999-01-01T00:00:00Z").await.unwrap();
    assert_eq!(repository::count_active_admins(&pool).await.unwrap(), 1);
    assert_eq!(repository::update_user_role(&pool, operator.id, "viewer").await.unwrap(), 1);
    assert_eq!(repository::list_users(&pool).await.unwrap()[1].role, "viewer");
    assert_eq!(repository::set_user_disabled(&pool, operator.id, true).await.unwrap(), 1);
    assert!(repository::find_user(&pool, "operator@example.com").await.unwrap().is_none());
    assert!(repository::find_user_by_session(&pool, "session-hash").await.unwrap().is_none());
    assert_eq!(sqlx::query("SELECT COUNT(*) c FROM sessions WHERE user_id=? AND revoked_at IS NOT NULL").bind(operator.id).fetch_one(&pool).await.unwrap().get::<i64,_>("c"), 1);
    assert_eq!(repository::set_user_disabled(&pool, operator.id, false).await.unwrap(), 1);
    assert!(repository::find_user(&pool, "operator@example.com").await.unwrap().is_some());
    assert_eq!(repository::delete_user(&pool, operator.id).await.unwrap(), 1);
    assert!(repository::list_users(&pool).await.unwrap().iter().all(|u| u.id != operator.id));
    assert_eq!(admin.role, "admin");
}

#[tokio::test]
async fn repository_protects_last_active_admin_and_rejects_unknown_roles() {
    let pool = test_pool().await;
    let admin = repository::insert_user(&pool, "admin@example.com", "hash", "admin").await.unwrap();
    assert!(repository::insert_user(&pool, "invalid@example.com", "hash", "invalid").await.is_err());
    assert!(repository::set_user_disabled(&pool, admin.id, true).await.is_err());
    assert!(repository::update_user_role(&pool, admin.id, "invalid").await.is_err());
    assert_eq!(repository::count_active_admins(&pool).await.unwrap(), 1);
}

#[tokio::test]
async fn migration_seeds_builtin_roles_and_all_permissions_idempotently() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();

    let roles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE system_managed=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let permissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM permissions")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(roles, 3);
    assert_eq!(permissions, 10);
    assert_eq!(repository::role_by_slug(&pool, "admin").await.unwrap().unwrap().slug, "admin");
}

#[tokio::test]
async fn role_lifecycle_contracts_exist_for_role_management() {
    let pool = test_pool().await;
    let role = repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
        .await
        .unwrap();
    repository::set_role_permissions(&pool, role.id, &["audit_logs.read"])
        .await
        .unwrap();
    assert_eq!(repository::role_permissions(&pool, role.id).await.unwrap().len(), 1);
    assert_eq!(repository::list_roles(&pool).await.unwrap().iter().any(|r| r.slug == "security-auditor"), true);
    assert_eq!(repository::update_role(&pool, role.id, "Security Auditor", "updated").await.unwrap(), 1);
    assert_eq!(repository::delete_role(&pool, role.id).await.unwrap(), 1);
}
