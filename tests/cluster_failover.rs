//! Phase 10C failover and readiness acceptance coverage.

use bearust::cluster::{raft_status_from_metrics, ClusterService, RaftRole};
use bearust::cluster_raft_runtime::{construct_raft_with_id, initialize_membership};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::repository;
use openraft::BasicNode;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

async fn ephemeral_addresses() -> [std::net::SocketAddr; 3] {
    let mut addresses = Vec::new();
    for _ in 0..3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
    }
    addresses.try_into().unwrap()
}

#[tokio::test]
async fn three_node_failover_fixture_elects_a_leader_and_shuts_down_cleanly() {
    let addresses = ephemeral_addresses().await;
    let ids = ["failover-1", "failover-2", "failover-3"];
    let mut services = Vec::new();
    let mut rafts = Vec::new();
    let mut shutdowns = Vec::new();
    let mut listeners = Vec::new();

    for (index, (id, address)) in ids.iter().zip(addresses).enumerate() {
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let peers = ids
            .iter()
            .zip(addresses)
            .filter(|(peer_id, _)| *peer_id != id)
            .map(|(peer_id, address)| ClusterPeer {
                node_id: (*peer_id).to_string(),
                address,
            })
            .collect();
        let config = ClusterConfig {
            node_id: (*id).to_string(),
            peers,
            bind: address,
            timeout_seconds: 1,
            auth_token: "failover-secret".into(),
        };
        let service = Arc::new(ClusterService::new(&config));
        let raft = construct_raft_with_id(pool, *id, b"failover-secret", (index + 1) as u64)
            .await
            .unwrap();
        service.set_raft_handler(Arc::new(
            bearust::cluster_raft_runtime::OpenRaftRpcHandler::new(raft.clone()),
        ));
        let (tx, rx) = watch::channel(false);
        listeners.push(tokio::spawn(bearust::cluster::run_cluster_listener(
            service.clone(),
            rx,
        )));
        services.push(service);
        rafts.push(raft);
        shutdowns.push(tx);
    }

    let members = addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| ((index + 1) as u64, BasicNode::new(address.to_string())))
        .collect::<BTreeMap<_, _>>();
    initialize_membership(&rafts[0], &services[0], members)
        .await
        .unwrap();

    let leader = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            for raft in &rafts {
                let metrics = raft.metrics();
                let metrics = metrics.borrow();
                if metrics.state.is_leader() && metrics.current_leader == Some(metrics.id) {
                    return metrics.id;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("three-node failover fixture did not elect a leader");
    assert!((1..=3).contains(&leader));
    let leader_index = (leader - 1) as usize;
    let leader_metrics = rafts[leader_index].metrics();
    services[leader_index].update_raft_status_from_metrics(&leader_metrics.borrow());
    assert_eq!(services[leader_index].raft_status().role, RaftRole::Leader);

    for shutdown in shutdowns {
        shutdown.send(true).unwrap();
    }
    for listener in listeners {
        listener.await.unwrap();
    }
    for raft in rafts {
        raft.shutdown().await.unwrap();
    }
    assert!(services.iter().all(|service| {
        service.raft_status().sync_state == "stopped" || service.is_single_node()
    }));
}

#[tokio::test]
async fn readiness_mapping_exposes_leader_and_quorum_loss() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let raft = construct_raft_with_id(pool, "status-node", b"status-secret", 1)
        .await
        .unwrap();
    let metrics = raft.metrics();
    let status = raft_status_from_metrics(&metrics.borrow());
    assert!(matches!(
        status.role,
        RaftRole::Follower | RaftRole::Candidate
    ));
    assert!(!status.quorum_available);
    assert_eq!(status.sync_state, "quorum_unavailable");
    raft.shutdown().await.unwrap();
}
