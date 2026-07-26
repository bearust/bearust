mod support;

use bearust::control_plane::repository;
use uuid::Uuid;

const PERMISSIONS: [&str; 14] = [
    "proxy_hosts.read",
    "proxy_hosts.write",
    "certificates.read",
    "certificates.write",
    "users.manage",
    "roles.manage",
    "audit_logs.read",
    "audit_logs.export",
    "system.settings.manage",
    "sessions.revoke",
    "bot_protection.manage",
    "ai_advisor.read",
    "ai_advisor.request",
    "ai_advisor.approve",
];

#[tokio::test]
async fn external_database_migrates_seeds_rbac_and_round_trips_user() {
    let Some(database_url) = support::external_database_url() else {
        eprintln!("skipping external database test: DATABASE_URL_EXTERNAL is not set");
        return;
    };
    let target = support::redacted_database_target(&database_url);
    let pool = repository::connect(&database_url)
        .await
        .unwrap_or_else(|_| panic!("could not connect to external database {target}"));
    repository::migrate(&pool)
        .await
        .unwrap_or_else(|_| panic!("could not migrate external database {target}"));
    repository::migrate(&pool)
        .await
        .unwrap_or_else(|_| panic!("external migration is not idempotent for {target}"));

    let permissions: Vec<String> = sqlx::query_scalar("SELECT key FROM permissions ORDER BY key")
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|_| panic!("could not read permissions from {target}"));
    let mut expected_permissions: Vec<String> = PERMISSIONS
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect();
    expected_permissions.sort();
    assert_eq!(permissions, expected_permissions);

    let roles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE system_managed=1")
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|_| panic!("could not read built-in roles from {target}"));
    assert_eq!(roles, 3);

    let admin = repository::role_by_slug(&pool, "admin")
        .await
        .unwrap_or_else(|_| panic!("could not read administrator role from {target}"))
        .expect("administrator role should be seeded");
    let admin_permissions = repository::role_permissions(&pool, admin.id)
        .await
        .unwrap_or_else(|_| panic!("could not read administrator permissions from {target}"));
    assert_eq!(admin_permissions, expected_permissions);

    let email = format!("external-{}@example.test", Uuid::new_v4());
    let user = repository::insert_user(&pool, &email, "test-password-hash", "admin")
        .await
        .unwrap_or_else(|_| panic!("could not create user in {target}"));
    let (read_user, password_hash) = repository::find_user(&pool, &email)
        .await
        .unwrap_or_else(|_| panic!("could not read user from {target}"))
        .expect("newly created user should be readable");
    assert_eq!(read_user.id, user.id);
    assert_eq!(read_user.email, email);
    assert_eq!(read_user.role, "admin");
    assert_eq!(password_hash, "test-password-hash");

    // Keep the test repeatable for shared external databases.
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap_or_else(|_| panic!("could not clean up test user in {target}"));
    pool.close().await;
}

#[test]
fn redacted_external_database_target_contains_no_credentials() {
    let redacted = support::redacted_database_target(
        "postgres://bearust:super-secret@[2001:db8::1]:5432/bearust?sslmode=require",
    );
    assert_eq!(redacted, "postgres://[2001:db8::1]");
    assert!(!redacted.contains("super-secret"));
    assert!(!redacted.contains("bearust"));
}
