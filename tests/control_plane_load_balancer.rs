use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use bearust::{
    control_plane::{
        auth::{hash_password, token_hash},
        build_state,
        models::LoadBalancerSnapshot,
        repository, router,
    },
    runtime::RuntimeStore,
};
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

async fn state_with_runtime() -> (
    bearust::control_plane::AppState,
    Arc<RuntimeStore>,
    tempfile::TempDir,
) {
    let directory = tempdir().unwrap();
    let config_path = directory.path().join("bearust.toml");
    std::fs::write(&config_path, include_str!("fixtures/valid.toml")).unwrap();

    let runtime = Arc::new(RuntimeStore::from_path(&config_path).await.unwrap());
    let mut state = build_state("sqlite::memory:", directory.path(), "setup-token")
        .await
        .unwrap();
    let admin = repository::insert_initial_admin(
        &state.db,
        "admin@example.test",
        &hash_password("admin-password-123").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    repository::create_session(
        &state.db,
        admin.id,
        &token_hash("admin-session"),
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    state = state.with_runtime(
        Arc::clone(&runtime),
        Arc::new(config_path),
        Arc::new(directory.path().join("missing.pid")),
    );
    (state, runtime, directory)
}

#[tokio::test]
async fn load_balancer_requires_authentication() {
    let (state, runtime, _directory) = state_with_runtime().await;
    let response = router(state)
        .oneshot(
            Request::get("/api/load-balancer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn load_balancer_reads_and_applies_live_topology() {
    let (state, runtime, _directory) = state_with_runtime().await;
    let app = router(state);
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/load-balancer")
                .header("Cookie", "bearust_session=admin-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let initial: LoadBalancerSnapshot =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.pools[0].name, "api");

    let response = app
        .oneshot(
            Request::put("/api/load-balancer")
                .header("Cookie", "bearust_session=admin-session")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "pools": [{
                            "name": "edge",
                            "algorithm": "least_connections",
                            "connect_timeout_seconds": 2,
                            "request_timeout_seconds": 15,
                            "backends": [{
                                "address": "127.0.0.1:19001",
                                "health_check": "tcp",
                                "health_path": null
                            }]
                        }],
                        "routes": [{
                            "name": "edge",
                            "host": "edge.example.test",
                            "path_prefix": "/",
                            "upstream_pool": "edge"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated: LoadBalancerSnapshot =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(updated.generation, 2);
    assert_eq!(updated.pools[0].name, "edge");
    assert_eq!(updated.routes[0].upstream_pool, "edge");
    assert_eq!(runtime.load().config().upstream_pools[0].name, "edge");
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn proxy_host_crud_materializes_a_live_runtime_route() {
    let (state, runtime, directory) = state_with_runtime().await;
    let app = router(state);
    let response = app
        .oneshot(
            Request::post("/api/proxy-hosts")
                .header("Cookie", "bearust_session=admin-session")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Status page",
                        "domain": "status.example.test",
                        "upstream_host": "127.0.0.1",
                        "upstream_port": 19002,
                        "tls_mode": "disabled",
                        "certificate_id": null,
                        "enabled": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let host: bearust::control_plane::models::ProxyHost =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let pool_name = format!("proxy-host-{}", host.id);
    let snapshot = runtime.load();
    let (route, _) = snapshot
        .route("status.example.test", "/health")
        .expect("proxy host should be active in the runtime");
    assert_eq!(route.upstream_pool, pool_name);
    assert!(snapshot.pool(&pool_name).is_some());
    let persisted = std::fs::read_to_string(directory.path().join("bearust.toml")).unwrap();
    assert!(persisted.contains(&pool_name));
    runtime.shutdown().await.unwrap();
}
