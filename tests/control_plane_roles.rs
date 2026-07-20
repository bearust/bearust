use bearust::control_plane::repository;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{str::FromStr, time::Duration};

#[tokio::test]
async fn custom_role_permissions_can_change_while_assigned_but_assigned_role_cannot_delete() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let role = repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
        .await
        .unwrap();
    repository::set_role_permissions(&pool, role.id, &["audit_logs.read"])
        .await
        .unwrap();
    let user = repository::insert_user(&pool, "auditor@example.com", "hash", &role.slug)
        .await
        .unwrap();

    repository::set_role_permissions(&pool, role.id, &["audit_logs.read", "sessions.revoke"])
        .await
        .unwrap();
    assert!(repository::user_has_permission(&pool, user.id, "sessions.revoke", None)
        .await
        .unwrap());
    assert!(repository::delete_role(&pool, role.id).await.is_err());
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

    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await.unwrap();
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
}

