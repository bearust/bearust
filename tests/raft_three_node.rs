use bearust::cluster::{run_cluster_listener, ClusterService};
use bearust::cluster_raft_runtime::{
    construct_raft_with_id, initialize_membership, OpenRaftRpcHandler,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::repository;
use openraft::BasicNode;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Construction smoke test for deterministic three-node IDs. This verifies
/// the durable adapters can be attached to three independent Raft handles;
/// election is intentionally not asserted because the network listener is not
/// connected to a Raft registry in this milestone.
#[tokio::test]
async fn three_node_raft_handles_construct_and_shutdown() {
    let mut handles = Vec::new();
    for id in 1..=3u64 {
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let raft = construct_raft_with_id(pool, format!("node-{id}"), b"test-secret-raft", id)
            .await
            .unwrap();
        handles.push(raft);
    }
    assert_eq!(handles.len(), 3);
    for raft in &handles {
        raft.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn three_node_cluster_elects_leader_over_authenticated_transport() {
    let secret = "three-node-test-secret".to_string();
    let mut reserved = Vec::new();
    for _ in 0..3 {
        reserved.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addresses: [SocketAddr; 3] = reserved
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    drop(reserved);
    let ids = ["node-1", "node-2", "node-3"];
    let mut services = Vec::new();
    let mut handles = Vec::new();
    let mut shutdowns = Vec::new();
    for (idx, (id, address)) in ids.iter().zip(addresses).enumerate() {
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
            timeout_seconds: 2,
            auth_token: secret.clone(),
        };
        let service = Arc::new(ClusterService::new(&config));
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let raft = construct_raft_with_id(pool, *id, secret.as_bytes(), (idx + 1) as u64)
            .await
            .unwrap();
        service.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(raft.clone())));
        let (tx, rx) = watch::channel(false);
        tokio::spawn(run_cluster_listener(service.clone(), rx));
        services.push(service);
        handles.push(raft);
        shutdowns.push(tx);
    }

    let members = addresses
        .into_iter()
        .enumerate()
        .map(|(idx, address)| {
            (
                (idx + 1) as u64,
                BasicNode {
                    addr: address.to_string(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    initialize_membership(&handles[0], &services[0], members)
        .await
        .unwrap();
    let leader = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            for raft in &handles {
                if let Some(leader) = raft.current_leader().await {
                    return leader;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("three-node election timed out");
    assert!((1..=3).contains(&leader));

    for shutdown in shutdowns {
        shutdown.send(true).unwrap();
    }
    for raft in handles {
        raft.shutdown().await.unwrap();
    }
    drop(services);
}
