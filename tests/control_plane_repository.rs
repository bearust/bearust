use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::repository;
use bearust::control_plane::{build_state, router};
use sqlx::Row;
use tower::util::ServiceExt;

#[test]
fn database_url_validation_accepts_supported_backends() {
    for url in [
        "sqlite://./data.db",
        "postgres://user:secret@localhost/db",
        "mysql://user:secret@localhost/db",
    ] {
        repository::validate_database_url(url).expect(url);
    }
}

#[test]
fn database_url_validation_rejects_unsupported_urls_without_credentials() {
    for url in ["redis://user:super-secret@example.test/cache", ""] {
        let error = repository::validate_database_url(url).expect_err("URL should be rejected");
        let message = error.to_string();
        assert!(message.contains("unsupported database URL"));
        assert!(!message.contains("super-secret"));
    }
}

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

async fn test_pool() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn scoped_user_lists_only_assigned_proxy_hosts() {
    let pool = test_pool().await;
    sqlx::query("INSERT INTO proxy_hosts(name,domain,upstream_host,upstream_port,tls_mode,created_at,updated_at) VALUES ('one','one.test','127.0.0.1',80,'disabled',datetime('now'),datetime('now')),('two','two.test','127.0.0.1',80,'disabled',datetime('now'),datetime('now'))")
        .execute(&pool).await.unwrap();
    repository::insert_role(&pool, "scoped-list", "Scoped list", "")
        .await
        .unwrap();
    repository::insert_user(&pool, "scoped-list@example.test", "hash", "scoped-list")
        .await
        .unwrap();
    let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE slug='scoped-list'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let permission_id: i64 =
        sqlx::query_scalar("SELECT id FROM permissions WHERE key='proxy_hosts.read'")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES (?,?, 'proxy_host',1)")
        .bind(role_id).bind(permission_id).execute(&pool).await.unwrap();
    let user_id: i64 =
        sqlx::query_scalar("SELECT id FROM users WHERE email='scoped-list@example.test'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let hosts = repository::list_hosts_for_user(&pool, user_id)
        .await
        .unwrap();
    assert_eq!(
        hosts.iter().map(|host| host.id).collect::<Vec<_>>(),
        vec![1]
    );
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
    let columns = sqlx::query("PRAGMA table_info(users)")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(columns
        .iter()
        .any(|r| r.get::<String, _>("name") == "disabled"));
}

#[tokio::test]
async fn user_lifecycle_updates_role_status_and_sessions() {
    let pool = test_pool().await;
    let admin = repository::insert_user(&pool, "admin@example.com", "hash", "admin")
        .await
        .unwrap();
    let operator = repository::insert_user(&pool, "operator@example.com", "hash", "operator")
        .await
        .unwrap();
    repository::create_session(&pool, operator.id, "session-hash", "2999-01-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(repository::count_active_admins(&pool).await.unwrap(), 1);
    assert_eq!(
        repository::update_user_role(&pool, operator.id, "viewer")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        repository::find_user(&pool, "operator@example.com")
            .await
            .unwrap()
            .unwrap()
            .0
            .role,
        "viewer"
    );
    assert_eq!(
        repository::set_user_disabled(&pool, operator.id, true)
            .await
            .unwrap(),
        1
    );
    assert!(repository::find_user(&pool, "operator@example.com")
        .await
        .unwrap()
        .is_none());
    assert!(repository::find_user_by_session(&pool, "session-hash")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sqlx::query("SELECT COUNT(*) c FROM sessions WHERE user_id=? AND revoked_at IS NOT NULL")
            .bind(operator.id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<i64, _>("c"),
        1
    );
    assert_eq!(
        repository::set_user_disabled(&pool, operator.id, false)
            .await
            .unwrap(),
        1
    );
    assert!(repository::find_user(&pool, "operator@example.com")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        repository::delete_user(&pool, operator.id).await.unwrap(),
        1
    );
    assert!(repository::list_users(&pool)
        .await
        .unwrap()
        .iter()
        .all(|u| u.id != operator.id));
    assert_eq!(admin.role, "admin");
}

#[tokio::test]
async fn revoke_user_sessions_only_revokes_active_sessions_and_returns_count() {
    let pool = test_pool().await;
    let user = repository::insert_user(&pool, "sessions@example.com", "hash", "admin")
        .await
        .unwrap();
    repository::create_session(&pool, user.id, "active-hash", "2999-01-01T00:00:00Z")
        .await
        .unwrap();
    repository::create_session(&pool, user.id, "active-hash-2", "2999-01-01T00:00:00Z")
        .await
        .unwrap();
    repository::revoke_session(&pool, "active-hash-2")
        .await
        .unwrap();
    assert_eq!(
        repository::revoke_user_sessions(&pool, user.id)
            .await
            .unwrap(),
        1
    );
    assert!(repository::find_user_by_session(&pool, "active-hash")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn repository_protects_last_active_admin_and_rejects_unknown_roles() {
    let pool = test_pool().await;
    let admin = repository::insert_user(&pool, "admin@example.com", "hash", "admin")
        .await
        .unwrap();
    assert!(
        repository::insert_user(&pool, "invalid@example.com", "hash", "invalid")
            .await
            .is_err()
    );
    assert!(repository::set_user_disabled(&pool, admin.id, true)
        .await
        .is_err());
    assert!(repository::update_user_role(&pool, admin.id, "invalid")
        .await
        .is_err());
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
    assert_eq!(permissions, 11);
    assert_eq!(
        repository::role_by_slug(&pool, "admin")
            .await
            .unwrap()
            .unwrap()
            .slug,
        "admin"
    );
}

#[tokio::test]
async fn migrations_record_order_and_seed_exact_permissions() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7]);
    let lock_row: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM setup_lock WHERE id=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lock_row, 1);
    let permission_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM permissions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(permission_count, 11);
    repository::migrate(&pool).await.unwrap();
    let role_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE system_managed=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role_count, 3);
    let global_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions WHERE scope_type='' AND scope_id=0",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        global_rows, 19,
        "built-in roles must retain every expected global grant"
    );
    let nullable_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions WHERE scope_type IS NULL OR scope_id IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        nullable_rows, 0,
        "global scopes use the portable non-null sentinel"
    );
}

#[tokio::test]
async fn migration_preserves_legacy_records() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL)")
        .execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, user_id INTEGER, event TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash,role,created_at) VALUES(7,'legacy@example.test','hash','admin','2024-01-01T00:00:00Z')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO audit_logs(id,user_id,event,details,created_at) VALUES(9,7,'legacy.event','{}','2024-01-01T00:00:00Z')")
        .execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE roles (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', system_managed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE permissions (id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '')").execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE role_permissions (role_id INTEGER NOT NULL, permission_id INTEGER NOT NULL, scope_type TEXT, scope_id INTEGER, PRIMARY KEY(role_id,permission_id,scope_type,scope_id))").execute(&pool).await.unwrap();
    sqlx::query("CREATE INDEX idx_role_permissions_scope ON role_permissions(scope_type, scope_id, role_id, permission_id)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO roles(id,slug,name,created_at,updated_at) VALUES(42,'legacy-role','Legacy','2024-01-01','2024-01-01')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO permissions(id,key) VALUES(43,'proxy_hosts.read')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(42,43,NULL,NULL),(42,43,NULL,7),(42,43,'',0),(42,43,'proxy_host',99)").execute(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let user: (String, i64) = sqlx::query_as("SELECT email,disabled FROM users WHERE id=7")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(user.0, "legacy@example.test");
    assert_eq!(user.1, 0);
    let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE id=9")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit_count, 1);
    let global: (String, i64) = sqlx::query_as("SELECT scope_type,scope_id FROM role_permissions WHERE role_id=42 AND permission_id=43 AND scope_id=0")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(global, (String::new(), 0));
    let global_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM role_permissions WHERE role_id=42 AND permission_id=43 AND scope_type='' AND scope_id=0").fetch_one(&pool).await.unwrap();
    assert_eq!(global_count, 1);
    let scoped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM role_permissions WHERE role_id=42 AND permission_id=43 AND scope_type='proxy_host' AND scope_id=99")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(scoped, 1);
}

#[tokio::test]
async fn update_user_accepts_existing_custom_role_slug() {
    let pool = test_pool().await;
    let role =
        repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
            .await
            .unwrap();
    let user = repository::insert_user(&pool, "auditee@example.com", "hash", "viewer")
        .await
        .unwrap();

    let updated = repository::update_user(&pool, user.id, Some(&role.slug), None)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated.role, "security-auditor");
}

#[tokio::test]
async fn role_lifecycle_contracts_exist_for_role_management() {
    let pool = test_pool().await;
    let role =
        repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
            .await
            .unwrap();
    repository::set_role_permissions(&pool, role.id, &["audit_logs.read"])
        .await
        .unwrap();
    assert_eq!(
        repository::role_permissions(&pool, role.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(repository::list_roles(&pool)
        .await
        .unwrap()
        .iter()
        .any(|r| r.slug == "security-auditor"));
    let updated =
        repository::update_role(&pool, role.id, Some("Security Auditor"), Some("updated"))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(updated.id, role.id);
    assert_eq!(updated.slug, "security-auditor");
    assert_eq!(updated.name, "Security Auditor");
    assert_eq!(updated.description, "updated");
    assert!(!updated.system_managed);
    assert_eq!(updated.permissions, vec!["audit_logs.read".to_string()]);
    assert_eq!(repository::delete_role(&pool, role.id).await.unwrap(), 1);
}

#[tokio::test]
async fn role_scopes_replace_atomically_and_preserve_global_permissions() {
    let pool = test_pool().await;
    sqlx::query("INSERT INTO proxy_hosts(name,domain,upstream_host,upstream_port,tls_mode,created_at,updated_at) VALUES('one','one.test','127.0.0.1',80,'disabled',datetime('now'),datetime('now')),('two','two.test','127.0.0.1',80,'disabled',datetime('now'),datetime('now'))").execute(&pool).await.unwrap();
    let role = repository::insert_role(&pool, "scoped-role", "Scoped", "")
        .await
        .unwrap();
    repository::set_role_permissions(&pool, role.id, &["proxy_hosts.read"])
        .await
        .unwrap();
    let scopes = vec![bearust::control_plane::models::RolePermissionScope {
        permission: "proxy_hosts.write".into(),
        proxy_host_ids: vec![2, 1],
    }];
    let updated = repository::replace_role_scopes(&pool, role.id, &scopes)
        .await
        .unwrap();
    assert_eq!(updated.permissions, vec!["proxy_hosts.read"]);
    assert_eq!(updated.scopes[0].proxy_host_ids, vec![1, 2]);
    repository::replace_role_scopes(&pool, role.id, &[])
        .await
        .unwrap();
    assert!(repository::get_role(&pool, role.id)
        .await
        .unwrap()
        .unwrap()
        .scopes
        .is_empty());
}

#[tokio::test]
async fn role_scopes_reject_unknown_hosts_invalid_permissions_and_duplicate_permissions() {
    let pool = test_pool().await;
    sqlx::query("INSERT INTO proxy_hosts(name,domain,upstream_host,upstream_port,tls_mode,created_at,updated_at) VALUES('one','one.test','127.0.0.1',80,'disabled',datetime('now'),datetime('now'))").execute(&pool).await.unwrap();
    let role = repository::insert_role(&pool, "scoped-role", "Scoped", "")
        .await
        .unwrap();
    let unknown = bearust::control_plane::models::RolePermissionScope {
        permission: "proxy_hosts.read".into(),
        proxy_host_ids: vec![999],
    };
    assert!(repository::replace_role_scopes(&pool, role.id, &[unknown])
        .await
        .is_err());
    let invalid = bearust::control_plane::models::RolePermissionScope {
        permission: "certificates.read".into(),
        proxy_host_ids: vec![1],
    };
    assert!(repository::replace_role_scopes(&pool, role.id, &[invalid])
        .await
        .is_err());
    let duplicate_hosts = bearust::control_plane::models::RolePermissionScope {
        permission: "proxy_hosts.read".into(),
        proxy_host_ids: vec![1, 1],
    };
    let normalized = repository::replace_role_scopes(&pool, role.id, &[duplicate_hosts])
        .await
        .unwrap();
    assert_eq!(normalized.scopes[0].proxy_host_ids, vec![1]);
    let duplicate_permissions = vec![
        bearust::control_plane::models::RolePermissionScope {
            permission: "proxy_hosts.read".into(),
            proxy_host_ids: vec![1],
        },
        bearust::control_plane::models::RolePermissionScope {
            permission: "proxy_hosts.read".into(),
            proxy_host_ids: vec![1],
        },
    ];
    assert!(
        repository::replace_role_scopes(&pool, role.id, &duplicate_permissions)
            .await
            .is_err()
    );
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE slug='admin'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(repository::replace_role_scopes(&pool, admin_id, &[])
        .await
        .is_err());
}
