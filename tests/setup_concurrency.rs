use bearust::control_plane::repository;
use std::sync::Once;

#[tokio::test]
async fn concurrent_initial_admin_setup_allows_only_one_creator() {
    static DRIVERS: Once = Once::new();
    DRIVERS.call_once(sqlx::any::install_default_drivers);
    let pool = repository::connect("sqlite:file:setup_concurrency?mode=memory&cache=shared")
        .await
        .unwrap();
    repository::migrate(&pool).await.unwrap();
    let (a, b) = tokio::join!(
        repository::insert_initial_admin(&pool, "a@example.test", "hash-a"),
        repository::insert_initial_admin(&pool, "b@example.test", "hash-b"),
    );
    assert!(a.unwrap().is_some() ^ b.unwrap().is_some());
    assert_eq!(repository::user_count(&pool).await.unwrap(), 1);
}
