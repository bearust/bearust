use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::cluster::ClusterService;
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::{
    auth::{hash_password, token_hash},
    build_state, repository, router,
};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn cluster_status_endpoint_requires_authentication() {
    let dir = tempdir().unwrap();
    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap();

    let app = router(state);
    let req = Request::builder()
        .uri("/api/cluster/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cluster_status_endpoint_returns_snapshot_for_authenticated_user() {
    let dir = tempdir().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);

    let cluster_config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![
            ClusterPeer {
                node_id: "node2".into(),
                address: healthy_addr,
            },
            ClusterPeer {
                node_id: "node3".into(),
                address: closed_addr,
            },
        ],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
    };
    let cluster = Arc::new(ClusterService::new(&cluster_config));

    let state = build_state("sqlite::memory:", dir.path(), "setup-token-123")
        .await
        .unwrap()
        .with_cluster(cluster);

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

    let app = router(state);
    let req = Request::builder()
        .uri("/api/cluster/status")
        .method("GET")
        .header("Cookie", "bearust_session=admin-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let snapshot: bearust::cluster::ClusterSnapshot = serde_json::from_slice(&body).unwrap();

    assert_eq!(snapshot.local_node_id, "node1");
    assert!(snapshot.cluster_enabled);
    assert_eq!(snapshot.total_peers, 2);
    assert_eq!(snapshot.healthy_peers, 1);
    assert_eq!(snapshot.peers.len(), 2);
}
