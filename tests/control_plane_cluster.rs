use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::cluster::{handshake_tag, ClusterService, HANDSHAKE_MAGIC};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::{
    auth::{hash_password, token_hash},
    build_state, repository, router,
};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

/// Spawn a cluster listener that speaks the full Phase 10A handshake protocol.
async fn spawn_protocol_responder(responder_node_id: &'static str) -> std::net::SocketAddr {
    const SECRET: &[u8] = b"01234567890123456789012345678901";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read: magic + id_len + id bytes + nonce + request proof.
        let mut magic = [0u8; 8];
        stream.read_exact(&mut magic).await.unwrap();
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await.unwrap();
        let id_len = len_buf[0] as usize;
        let mut id_buf = vec![0u8; id_len];
        stream.read_exact(&mut id_buf).await.unwrap();
        let mut nonce = [0u8; 16];
        stream.read_exact(&mut nonce).await.unwrap();
        let mut request_tag = [0u8; 32];
        stream.read_exact(&mut request_tag).await.unwrap();
        assert_eq!(
            request_tag,
            handshake_tag(SECRET, b"request", &nonce, &id_buf)
        );
        // Respond with nonce, node ID, and response proof.
        let peer_bytes = responder_node_id.as_bytes();
        let resp_len = peer_bytes.len().min(255) as u8;
        let response_tag = handshake_tag(SECRET, b"response", &nonce, peer_bytes);
        let mut resp = Vec::with_capacity(9 + 16 + resp_len as usize + 32);
        resp.extend_from_slice(HANDSHAKE_MAGIC);
        resp.extend_from_slice(&nonce);
        resp.push(resp_len);
        resp.extend_from_slice(&peer_bytes[..resp_len as usize]);
        resp.extend_from_slice(&response_tag);
        stream.write_all(&resp).await.unwrap();
    });
    addr
}

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

    // Healthy peer: speaks the proper cluster handshake protocol.
    let healthy_addr = spawn_protocol_responder("node2").await;

    // Unhealthy peer: port closed.
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
        timeout_seconds: 2,
        auth_token: "01234567890123456789012345678901".into(),
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

    // Verify node addresses are not in the JSON response.
    let json = String::from_utf8(body.to_vec()).unwrap();
    assert!(!json.contains("127.0.0."));
}
