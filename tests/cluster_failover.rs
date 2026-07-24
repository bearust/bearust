//! Phase 10C failover and readiness acceptance coverage.

use bearust::cluster::{raft_status_from_metrics, ClusterService, RaftRole};
use bearust::cluster_raft::ConfigCommand;
use bearust::cluster_raft_runtime::{
    construct_raft_with_id, initialize_membership, OpenRaftRpcHandler,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use openraft::BasicNode;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::watch;
use uuid::Uuid;

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

    // A stale leader announcement must not make a follower report quorum
    // readiness: OpenRaft's quorum lease is leader-only.
    let mut follower_metrics = metrics.borrow().clone();
    follower_metrics.state = openraft::ServerState::Follower;
    follower_metrics.current_leader = Some(99);
    let follower_status = raft_status_from_metrics(&follower_metrics);
    assert_eq!(follower_status.role, RaftRole::Follower);
    assert!(!follower_status.quorum_available);
    assert_eq!(follower_status.sync_state, "quorum_unavailable");

    raft.shutdown().await.unwrap();
}

/// A node that is restarted with its durable SQL log must catch up entries
/// committed while it was offline. This exercises the authenticated Raft
/// transport rather than only checking that a fresh in-memory handle elects.
#[tokio::test]
async fn rejoining_node_catches_up_committed_configuration() {
    let addresses = ephemeral_addresses().await;
    let ids = ["rejoin-1", "rejoin-2", "rejoin-3"];
    let secret = b"rejoin-secret";
    let directory = tempdir().unwrap();
    let members = addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| ((index + 1) as u64, BasicNode::new(address.to_string())))
        .collect::<BTreeMap<_, _>>();

    let mut services = Vec::new();
    let mut pools = Vec::new();
    let mut rafts = Vec::new();
    let mut shutdowns = Vec::new();
    let mut listeners = Vec::new();
    for (index, (id, address)) in ids.iter().zip(addresses).enumerate() {
        let db = directory.path().join(format!("node-{index}.db"));
        let pool = repository::connect(&format!("sqlite://{}?mode=rwc", db.display()))
            .await
            .unwrap();
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
            auth_token: String::from_utf8(secret.to_vec()).unwrap(),
        };
        let service = Arc::new(bearust::cluster::ClusterService::new(&config));
        let raft = construct_raft_with_id(pool.clone(), *id, secret, (index + 1) as u64)
            .await
            .unwrap();
        service.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(raft.clone())));
        let (shutdown, receiver) = watch::channel(false);
        listeners.push(tokio::spawn(bearust::cluster::run_cluster_listener(
            service.clone(),
            receiver,
        )));
        services.push(service);
        pools.push(pool);
        rafts.push(raft);
        shutdowns.push(shutdown);
    }

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
    .expect("rejoin fixture did not elect a leader");
    let leader_index = (leader - 1) as usize;

    let first = ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: ProxyHost {
            id: 501,
            name: "before-rejoin".into(),
            domain: "before-rejoin.example.test".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8080,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    };
    let first_response = rafts[leader_index].client_write(first).await.unwrap();
    for raft in &rafts {
        raft.wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(first_response.log_id.index), "first command applied")
            .await
            .unwrap();
    }

    // Stop one follower while keeping the leader and the other voter alive.
    let rejoining_index = if leader_index == 2 { 1 } else { 2 };
    shutdowns[rejoining_index].send(true).unwrap();
    listeners.swap_remove(rejoining_index).await.unwrap();
    rafts[rejoining_index].shutdown().await.unwrap();

    let second = ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: ProxyHost {
            id: 502,
            name: "while-offline".into(),
            domain: "while-offline.example.test".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8081,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    };
    let second_response = rafts[leader_index].client_write(second).await.unwrap();
    for (index, raft) in rafts.iter().enumerate() {
        if index != rejoining_index {
            raft.wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(
                    Some(second_response.log_id.index),
                    "offline command applied",
                )
                .await
                .unwrap();
        }
    }

    // Reconstruct the same node from its durable database and reattach its
    // authenticated listener. OpenRaft should replay the missing entry.
    let db = directory.path().join(format!("node-{rejoining_index}.db"));
    let pool = repository::connect(&format!("sqlite://{}?mode=rwc", db.display()))
        .await
        .unwrap();
    let service = Arc::new(bearust::cluster::ClusterService::new(&ClusterConfig {
        node_id: ids[rejoining_index].into(),
        peers: ids
            .iter()
            .zip(addresses)
            .filter(|(peer_id, _)| *peer_id != &ids[rejoining_index])
            .map(|(peer_id, address)| ClusterPeer {
                node_id: (*peer_id).into(),
                address,
            })
            .collect(),
        bind: addresses[rejoining_index],
        timeout_seconds: 1,
        auth_token: String::from_utf8(secret.to_vec()).unwrap(),
    }));
    let rejoined = construct_raft_with_id(
        pool.clone(),
        ids[rejoining_index],
        secret,
        (rejoining_index + 1) as u64,
    )
    .await
    .unwrap();
    service.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(rejoined.clone())));
    let (shutdown, receiver) = watch::channel(false);
    let listener = tokio::spawn(bearust::cluster::run_cluster_listener(service, receiver));
    rejoined
        .wait(Some(Duration::from_secs(10)))
        .applied_index_at_least(
            Some(second_response.log_id.index),
            "rejoining node caught up",
        )
        .await
        .unwrap();
    let hosts = repository::list_hosts(&pool).await.unwrap();
    assert!(hosts.iter().any(|host| host.id == 502));

    shutdown.send(true).unwrap();
    listener.await.unwrap();
    rejoined.shutdown().await.unwrap();
    for (index, raft) in rafts.into_iter().enumerate() {
        if index != rejoining_index {
            shutdowns[index].send(true).unwrap();
            raft.shutdown().await.unwrap();
        }
    }
    drop(pools);
}
