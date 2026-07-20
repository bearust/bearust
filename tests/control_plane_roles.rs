use bearust::control_plane::repository;

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
