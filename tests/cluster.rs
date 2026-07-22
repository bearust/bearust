use bearust::cluster::{ClusterService, PeerStatus};
use bearust::config::{ClusterConfig, ClusterPeer};
use std::net::SocketAddr;

#[tokio::test]
async fn single_node_cluster_snapshot_is_valid() {
    let config = ClusterConfig {
        node_id: "node1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 2,
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
}

#[tokio::test]
async fn multi_node_cluster_detects_healthy_unhealthy_and_timeout_peers() {
    // 1. Healthy listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    // 2. Unreachable port (bind and drop listener to get a closed port)
    let tmp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = tmp_listener.local_addr().unwrap();
    drop(tmp_listener);

    // 3. Timeout address (TEST-NET-1 reserved IP 192.0.2.1)
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
    };

    let service = ClusterService::new(&config);
    let snapshot = service.snapshot().await;

    assert_eq!(snapshot.local_node_id, "node1");
    assert!(snapshot.cluster_enabled);
    assert_eq!(snapshot.total_peers, 3);
    assert_eq!(snapshot.healthy_peers, 1);

    let node2_health = snapshot.peers.iter().find(|p| p.node_id == "node2").unwrap();
    assert_eq!(node2_health.status, PeerStatus::Healthy);
    assert!(node2_health.error.is_none());

    let node3_health = snapshot.peers.iter().find(|p| p.node_id == "node3").unwrap();
    assert_eq!(node3_health.status, PeerStatus::Unhealthy);
    assert!(node3_health.error.is_some());

    let node4_health = snapshot.peers.iter().find(|p| p.node_id == "node4").unwrap();
    assert!(matches!(
        node4_health.status,
        PeerStatus::Timeout | PeerStatus::Unhealthy
    ));

    // Verify snapshot JSON serialization has no secret-bearing fields
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("secret"));
    assert!(!json.contains("password"));
    assert!(!json.contains("private_key"));
}
