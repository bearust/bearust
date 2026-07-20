use bearust::control_plane::models::AuditLogQuery;
use bearust::control_plane::repository;
use sqlx::SqlitePool;

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

    let event = repository::list_audit_logs(&pool, &AuditLogQuery { event: Some("user_updated".into()), actor_id: None, from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(event.total, 1);
    assert_eq!(event.items[0].details, "target=proxy;reason=changed");

    let actor = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: Some(active.id), from: None, to: None, q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(actor.total, 2);

    let time = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: None, from: Some("2026-07-20T10:01:00Z".into()), to: Some("2026-07-20T10:02:00Z".into()), q: None, page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(time.items.iter().map(|item| item.event.as_str()).collect::<Vec<_>>(), ["user_deleted", "user_updated"]);

    let text = repository::list_audit_logs(&pool, &AuditLogQuery { event: None, actor_id: None, from: None, to: None, q: Some("proxy".into()), page: 1, page_size: 25 }).await.unwrap();
    assert_eq!(text.total, 1);
    assert_eq!(text.items[0].event, "user_updated");
}
