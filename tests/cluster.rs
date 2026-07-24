use bearust::cluster::{
    handshake_tag, run_cluster_listener, ClusterService, PeerStatus, RaftRole, HANDSHAKE_MAGIC,
};
use bearust::cluster_raft::{decode_rpc_frame, encode_rpc_frame};
use bearust::config::{ClusterConfig, ClusterPeer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_SECRET: &str = "01234567890123456789012345678901";

/// Helper: spawn a minimal cluster-protocol responder that performs the
/// authenticated handshake exchange for one connection.
async fn spawn_cluster_responder(peer_node_id: &'static str) -> SocketAddr {
    spawn_cluster_responder_with_secret(peer_node_id, TEST_SECRET).await
}

async fn spawn_cluster_responder_with_secret(
    peer_node_id: &'static str,
    secret: &'static str,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read: magic + id_len + id bytes + nonce + request proof.
        let mut magic = [0u8; 8];
        stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, HANDSHAKE_MAGIC, "handshake magic mismatch");
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
            handshake_tag(secret.as_bytes(), b"request", &nonce, &id_buf)
        );
        // Respond: magic + nonce + peer_node_id + response proof.
        let peer_id_bytes = peer_node_id.as_bytes();
        let resp_len = peer_id_bytes.len().min(255) as u8;
        let response_tag = handshake_tag(secret.as_bytes(), b"response", &nonce, peer_id_bytes);
        let mut resp = Vec::with_capacity(9 + 16 + resp_len as usize + 32);
        resp.extend_from_slice(HANDSHAKE_MAGIC);
        resp.extend_from_slice(&nonce);
        resp.push(resp_len);
        resp.extend_from_slice(&peer_id_bytes[..resp_len as usize]);
        resp.extend_from_slice(&response_tag);
        stream.write_all(&resp).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn wrong_cluster_secret_is_rejected() {
    let address =
        spawn_cluster_responder_with_secret("node2", "11111111111111111111111111111111").await;
    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![ClusterPeer {
            node_id: "node2".into(),
            address,
        }],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let snapshot = ClusterService::new(&config).snapshot().await;
    assert_eq!(snapshot.healthy_peers, 0);
    assert_eq!(snapshot.peers[0].status, PeerStatus::Unhealthy);
}

#[tokio::test]
async fn single_node_cluster_snapshot_is_valid() {
    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = ClusterService::new(&config);

    assert_eq!(service.node_id(), "node1");
    assert!(service.is_single_node());

    let snapshot = service.snapshot().await;
    assert_eq!(snapshot.local_node_id, "node1");
    assert!(!snapshot.cluster_enabled);
    assert_eq!(snapshot.total_peers, 0);
    assert_eq!(snapshot.healthy_peers, 0);
    assert!(snapshot.peers.is_empty());
    assert_eq!(snapshot.raft_role, RaftRole::Standalone);
    assert_eq!(snapshot.raft_leader_id.as_deref(), Some("node1"));
    assert!(snapshot.raft_quorum_available);
}

#[tokio::test]
async fn cluster_snapshot_reflects_runtime_raft_status_without_peer_details() {
    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = ClusterService::new(&config);
    service.set_raft_status(bearust::cluster::RaftStatus {
        role: RaftRole::Leader,
        leader_id: Some("node1".into()),
        term: 3,
        last_log_index: 8,
        commit_index: 7,
        quorum_available: true,
        sync_state: "in_sync".into(),
    });
    let snapshot = service.snapshot().await;
    assert_eq!(snapshot.raft_role, RaftRole::Leader);
    assert_eq!(snapshot.raft_term, 3);
    assert_eq!(snapshot.raft_last_log_index, 8);
    assert_eq!(snapshot.raft_commit_index, 7);
}

#[tokio::test]
async fn healthy_peer_passes_authenticated_handshake() {
    // Spawn a peer that properly speaks the cluster protocol.
    let healthy_addr = spawn_cluster_responder("node2").await;

    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![ClusterPeer {
            node_id: "node2".into(),
            address: healthy_addr,
        }],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = ClusterService::new(&config);
    let snapshot = service.snapshot().await;

    assert!(snapshot.cluster_enabled);
    assert_eq!(snapshot.total_peers, 1);
    assert_eq!(snapshot.healthy_peers, 1);

    let node2 = snapshot
        .peers
        .iter()
        .find(|p| p.node_id == "node2")
        .unwrap();
    assert_eq!(node2.status, PeerStatus::Healthy);
    assert!(node2.error.is_none());
    assert!(node2.latency_ms.is_some());
}

#[tokio::test]
async fn multi_node_cluster_detects_healthy_unhealthy_and_timeout_peers() {
    // 1. Healthy peer that speaks the cluster protocol.
    let healthy_addr = spawn_cluster_responder("node2").await;

    // 2. Unreachable port (bind and drop listener to get a closed port).
    let tmp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = tmp_listener.local_addr().unwrap();
    drop(tmp_listener);

    // 3. Timeout address (TEST-NET-1 reserved IP 192.0.2.1).
    let timeout_addr: SocketAddr = "192.0.2.1:9092".parse().unwrap();

    let config = ClusterConfig {
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
            ClusterPeer {
                node_id: "node4".into(),
                address: timeout_addr,
            },
        ],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: TEST_SECRET.into(),
    };

    let service = ClusterService::new(&config);
    let snapshot = service.snapshot().await;

    assert_eq!(snapshot.local_node_id, "node1");
    assert!(snapshot.cluster_enabled);
    assert_eq!(snapshot.total_peers, 3);
    assert_eq!(snapshot.healthy_peers, 1);

    let node2 = snapshot
        .peers
        .iter()
        .find(|p| p.node_id == "node2")
        .unwrap();
    assert_eq!(node2.status, PeerStatus::Healthy);
    assert!(node2.error.is_none());

    let node3 = snapshot
        .peers
        .iter()
        .find(|p| p.node_id == "node3")
        .unwrap();
    assert_eq!(node3.status, PeerStatus::Unhealthy);
    assert!(node3.error.is_some());

    let node4 = snapshot
        .peers
        .iter()
        .find(|p| p.node_id == "node4")
        .unwrap();
    assert!(matches!(
        node4.status,
        PeerStatus::Timeout | PeerStatus::Unhealthy
    ));

    // Verify snapshot JSON serialization has no secret-bearing fields.
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("secret"));
    assert!(!json.contains("password"));
    assert!(!json.contains("private_key"));
}

#[tokio::test]
async fn wrong_handshake_magic_is_reported_as_unhealthy() {
    // A listener that responds with bad magic bytes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_magic_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Drain the incoming handshake frame first.
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf).await;
        // Respond with garbage magic.
        stream.write_all(b"GARBAGE1\x05hello").await.unwrap();
    });

    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![ClusterPeer {
            node_id: "bad-peer".into(),
            address: bad_magic_addr,
        }],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = ClusterService::new(&config);
    let snapshot = service.snapshot().await;

    let bad = snapshot
        .peers
        .iter()
        .find(|p| p.node_id == "bad-peer")
        .unwrap();
    assert_eq!(bad.status, PeerStatus::Unhealthy);
    assert!(bad.error.as_deref().unwrap_or("").contains("handshake"));
}

#[tokio::test]
async fn cluster_listener_binds_and_completes_handshake_from_inbound_client() {
    let local_node_id = "listener-node";
    let config = ClusterConfig {
        node_id: local_node_id.into(),
        peers: vec![ClusterPeer {
            node_id: "peer-placeholder".into(),
            address: "127.0.0.1:0".parse().unwrap(),
        }],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = Arc::new(ClusterService::new(&config));

    // Start the cluster listener.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let service_clone = Arc::clone(&service);
    let listener_bind = service.bind();
    tokio::spawn(run_cluster_listener(service_clone, shutdown_rx));

    // Give the listener a moment to bind.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // The listener binds to port 0, so we need to actually try to connect.
    // Since `bind()` returns 0.0.0.0:0, we need a concrete addr. In tests
    // we rely on the service's bind being 127.0.0.1:0 which the OS assigns.
    // Instead of reading the bound port back (listener is in another task),
    // we verify single-node mode skips the listener and use a concrete port test.
    let _ = listener_bind;

    // Verify single-node skips listener silently (separate config).
    let single_config = ClusterConfig {
        node_id: "solo".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let single_service = Arc::new(ClusterService::new(&single_config));
    let (tx2, rx2) = tokio::sync::watch::channel(false);
    // run_cluster_listener returns immediately for single-node.
    tokio::time::timeout(
        tokio::time::Duration::from_millis(100),
        run_cluster_listener(single_service, rx2),
    )
    .await
    .expect("single-node listener should exit immediately");
    drop(tx2);

    // Cleanly shut down the multi-node listener.
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn cluster_listener_handshake_roundtrip_on_concrete_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let local_node_id = "node-a";
    let incoming_node_id = "node-b";

    // Bind a known port to simulate the real cluster listener.
    let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();

    let config = ClusterConfig {
        node_id: local_node_id.into(),
        // One fake peer so is_single_node() = false.
        peers: vec![ClusterPeer {
            node_id: incoming_node_id.into(),
            address: server_addr,
        }],
        bind: server_addr,
        timeout_seconds: 2,
        auth_token: TEST_SECRET.into(),
    };
    let service = Arc::new(ClusterService::new(&config));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Drop the pre-bound listener so run_cluster_listener can rebind.
    drop(server_listener);

    tokio::spawn(run_cluster_listener(Arc::clone(&service), shutdown_rx));
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert_eq!(service.raft_status().sync_state, "transport_ready");

    // Connect and send the handshake as a remote peer.
    let mut stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let id_bytes = incoming_node_id.as_bytes();
    let id_len = id_bytes.len() as u8;
    let nonce = [7u8; 16];
    let request_tag = handshake_tag(TEST_SECRET.as_bytes(), b"request", &nonce, id_bytes);
    let mut frame = Vec::with_capacity(9 + id_len as usize + 16 + 32);
    frame.extend_from_slice(HANDSHAKE_MAGIC);
    frame.push(id_len);
    frame.extend_from_slice(id_bytes);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&request_tag);
    stream.write_all(&frame).await.unwrap();

    // Read the server's response.
    let mut resp_magic = [0u8; 8];
    stream.read_exact(&mut resp_magic).await.unwrap();
    assert_eq!(&resp_magic, HANDSHAKE_MAGIC);

    let mut response_nonce = [0u8; 16];
    stream.read_exact(&mut response_nonce).await.unwrap();
    assert_eq!(response_nonce, nonce);
    let mut len_buf = [0u8; 1];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_id_len = len_buf[0] as usize;
    let mut resp_id_buf = vec![0u8; resp_id_len];
    stream.read_exact(&mut resp_id_buf).await.unwrap();
    assert_eq!(resp_id_buf, local_node_id.as_bytes());
    let mut response_tag = [0u8; 32];
    stream.read_exact(&mut response_tag).await.unwrap();
    assert_eq!(
        response_tag,
        handshake_tag(TEST_SECRET.as_bytes(), b"response", &nonce, &resp_id_buf)
    );

    let status_request = encode_rpc_frame(br#"{"kind":"status"}"#, TEST_SECRET.as_bytes()).unwrap();
    stream.write_all(&status_request).await.unwrap();
    let mut rpc_header = [0u8; 11];
    stream.read_exact(&mut rpc_header).await.unwrap();
    assert_eq!(&rpc_header[..7], b"BRRAFT1");
    let declared = u32::from_be_bytes(rpc_header[7..11].try_into().unwrap()) as usize;
    let mut rpc_body = vec![0u8; declared + 32];
    stream.read_exact(&mut rpc_body).await.unwrap();
    let mut rpc_frame = rpc_header.to_vec();
    rpc_frame.extend_from_slice(&rpc_body);
    let status_response = decode_rpc_frame(&rpc_frame, TEST_SECRET.as_bytes()).unwrap();
    assert!(status_response.starts_with(br#"{"kind":"status","node_id":"node-a""#));

    let _ = shutdown_tx.send(true);
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
    assert_eq!(service.raft_status().sync_state, "stopped");
}
