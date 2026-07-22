use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::control_plane::auth::{hash_password, token_hash};
use bearust::control_plane::{build_state, models::RolePermissionScope, repository, router};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn baseline_requires_authentication() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap();
    let app = router(state);

    let req = Request::builder()
        .uri("/api/analytics/baseline")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn baseline_endpoint_scoped_viewer_and_admin() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap();

    // Create admin user & session
    let admin = repository::insert_initial_admin(
        &state.db,
        "admin@example.com",
        &hash_password("admin12345678").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    repository::create_session(
        &state.db,
        admin.id,
        &token_hash("admin-token"),
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    // Create proxy host 1 & 2
    let host1 = repository::insert_host(
        &state.db,
        &bearust::control_plane::models::ProxyHost {
            id: 0,
            name: "Host 1".into(),
            domain: "h1.example.com".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8080,
            tls_mode: "off".into(),
            certificate_id: None,
            enabled: true,
        },
    )
    .await
    .unwrap();

    let host2 = repository::insert_host(
        &state.db,
        &bearust::control_plane::models::ProxyHost {
            id: 0,
            name: "Host 2".into(),
            domain: "h2.example.com".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8081,
            tls_mode: "off".into(),
            certificate_id: None,
            enabled: true,
        },
    )
    .await
    .unwrap();

    // Create scoped role for host 1 only
    let role = repository::insert_role(&state.db, "scoped-viewer", "Scoped Viewer", "")
        .await
        .unwrap();
    repository::replace_role_scopes(
        &state.db,
        role.id,
        &[RolePermissionScope {
            permission: "proxy_hosts.read".into(),
            proxy_host_ids: vec![host1.id],
        }],
    )
    .await
    .unwrap();

    let scoped_user = repository::insert_user(
        &state.db,
        "scoped@example.com",
        &hash_password("password12345678").unwrap(),
        "scoped-viewer",
    )
    .await
    .unwrap();
    repository::create_session(
        &state.db,
        scoped_user.id,
        &token_hash("scoped-token"),
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    let app = router(state.clone());

    // Admin can query any host baseline
    let req = Request::builder()
        .uri(format!(
            "/api/analytics/baseline?proxy_host_id={}&window=5m",
            host1.id
        ))
        .method("GET")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Scoped user can query host 1
    let req = Request::builder()
        .uri(format!(
            "/api/analytics/baseline?proxy_host_id={}&window=5m",
            host1.id
        ))
        .method("GET")
        .header("Cookie", "bearust_session=scoped-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Scoped user CANNOT query host 2
    let req = Request::builder()
        .uri(format!(
            "/api/analytics/baseline?proxy_host_id={}&window=5m",
            host2.id
        ))
        .method("GET")
        .header("Cookie", "bearust_session=scoped-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
