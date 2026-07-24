use bearust::cluster::{run_cluster_listener, ClusterService};
use bearust::cluster_command::{ClusterWriteError, CommandActor, ConfigCommandGateway};
use bearust::cluster_raft::ConfigCommand;
use bearust::cluster_raft_runtime::{
    bootstrap_single_node, construct_raft_with_id, OpenRaftRpcHandler,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use openraft::BasicNode;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

fn test_actor() -> CommandActor {
    CommandActor {
        user_id: 7,
        email: "operator@example.test".into(),
        role: "admin".into(),
    }
}

fn test_create_command() -> ConfigCommand {
    ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: ProxyHost {
            id: 42,
            name: "gateway-test".into(),
            domain: "gateway.example.test".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8080,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    }
}

struct ThreeNodeGatewayCluster {
    gateways: Vec<ConfigCommandGateway>,
    rafts: Vec<openraft::Raft<bearust::cluster_raft::BearustRaftConfig>>,
    shutdowns: Vec<watch::Sender<bool>>,
}

impl ThreeNodeGatewayCluster {
    async fn shutdown(self) {
        for shutdown in self.shutdowns {
            let _ = shutdown.send(true);
        }
        for raft in self.rafts {
            raft.shutdown().await.unwrap();
        }
    }
}

async fn three_node_gateway_cluster(base_port: u16) -> ThreeNodeGatewayCluster {
    let secret = "cluster-command-test".to_string();
    let addresses: [SocketAddr; 3] = [
        format!("127.0.0.1:{base_port}").parse().unwrap(),
        format!("127.0.0.1:{}", base_port + 1).parse().unwrap(),
        format!("127.0.0.1:{}", base_port + 2).parse().unwrap(),
    ];
    let ids = ["node-1", "node-2", "node-3"];
    let mut gateways = Vec::new();
    let mut rafts = Vec::new();
    let mut shutdowns = Vec::new();

    for (index, (node_id, bind)) in ids.iter().zip(addresses).enumerate() {
        let peers = ids
            .iter()
            .zip(addresses)
            .filter(|(peer_id, _)| *peer_id != node_id)
            .map(|(peer_id, address)| ClusterPeer {
                node_id: (*peer_id).to_string(),
                address,
            })
            .collect();
        let config = ClusterConfig {
            node_id: (*node_id).to_string(),
            peers,
            bind,
            timeout_seconds: 2,
            auth_token: secret.clone(),
        };
        let cluster = Arc::new(ClusterService::new(&config));
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let raft = construct_raft_with_id(pool, *node_id, secret.as_bytes(), (index + 1) as u64)
            .await
            .unwrap();
        cluster.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(raft.clone())));
        let (shutdown, receiver) = watch::channel(false);
        tokio::spawn(run_cluster_listener(cluster.clone(), receiver));
        gateways.push(ConfigCommandGateway::new(Arc::new(raft.clone()), cluster));
        rafts.push(raft);
        shutdowns.push(shutdown);
    }

    let members = addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| {
            (
                (index + 1) as u64,
                BasicNode {
                    addr: address.to_string(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    rafts[0].initialize(members).await.unwrap();

    ThreeNodeGatewayCluster {
        gateways,
        rafts,
        shutdowns,
    }
}

async fn wait_for_live_leader(
    rafts: &[openraft::Raft<bearust::cluster_raft::BearustRaftConfig>],
) -> usize {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            for (index, raft) in rafts.iter().enumerate() {
                let metrics = raft.metrics();
                let metrics = metrics.borrow();
                if metrics.state.is_leader()
                    && metrics.current_leader == Some(metrics.id)
                    && metrics.millis_since_quorum_ack.is_some()
                {
                    return index;
                }
                drop(metrics);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("three-node leader did not receive a quorum acknowledgement")
}

#[tokio::test]
async fn follower_gateway_does_not_mutate_local_database() {
    let cluster = three_node_gateway_cluster(42301).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    let applied_before = cluster.rafts[follower].metrics().borrow().last_applied;

    let result = cluster.gateways[follower]
        .submit(test_create_command(), test_actor())
        .await;

    assert!(matches!(result, Err(ClusterWriteError::LeaderUnknown)));
    assert_eq!(
        cluster.rafts[follower].metrics().borrow().last_applied,
        applied_before
    );
    cluster.shutdown().await;
}

#[tokio::test]
async fn leader_gateway_commits_through_actual_three_node_quorum() {
    let cluster = three_node_gateway_cluster(42311).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;

    let receipt = cluster.gateways[leader]
        .submit(test_create_command(), test_actor())
        .await
        .unwrap();

    assert_eq!(receipt.leader_id, (leader + 1) as u64);
    for raft in &cluster.rafts {
        raft.wait(Some(Duration::from_secs(2)))
            .applied_index_at_least(Some(receipt.commit_index), "gateway command applied")
            .await
            .unwrap();
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn gateway_rejects_writes_after_actual_quorum_loss() {
    let cluster = three_node_gateway_cluster(42321).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let applied_before = cluster.rafts[leader].metrics().borrow().last_applied;
    for index in 0..cluster.rafts.len() {
        if index != leader {
            cluster.shutdowns[index].send(true).unwrap();
            cluster.rafts[index].shutdown().await.unwrap();
        }
    }
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let metrics = cluster.rafts[leader].metrics();
            let metrics = metrics.borrow();
            if !metrics.state.is_leader()
                || metrics.millis_since_quorum_ack.unwrap_or(u64::MAX) > 1_000
            {
                return;
            }
            drop(metrics);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("leader did not observe quorum loss");

    let result = cluster.gateways[leader]
        .submit(test_create_command(), test_actor())
        .await;

    assert!(matches!(
        result,
        Err(ClusterWriteError::LeaderUnknown | ClusterWriteError::QuorumUnavailable)
    ));
    assert_eq!(
        cluster.rafts[leader].metrics().borrow().last_applied,
        applied_before
    );
    for index in 0..cluster.rafts.len() {
        if index == leader {
            let _ = cluster.shutdowns[index].send(true);
            cluster.rafts[index].shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn single_node_gateway_keeps_local_command_submission() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let raft = construct_raft_with_id(pool, "node-1", b"cluster-command-test", 1)
        .await
        .unwrap();
    bootstrap_single_node(&raft, 1, "127.0.0.1:0")
        .await
        .unwrap();
    let config = ClusterConfig {
        node_id: "node-1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: "cluster-command-test".into(),
    };
    let gateway = ConfigCommandGateway::new(
        Arc::new(raft.clone()),
        Arc::new(ClusterService::new(&config)),
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let metrics = raft.metrics();
            let metrics = metrics.borrow();
            if metrics.state.is_leader() && metrics.current_leader == Some(1) {
                return;
            }
            drop(metrics);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("single node did not elect itself");

    let receipt = gateway
        .submit(test_create_command(), test_actor())
        .await
        .unwrap();

    assert_eq!(receipt.leader_id, 1);
    assert!(receipt.commit_index > 0);
    raft.shutdown().await.unwrap();
}
