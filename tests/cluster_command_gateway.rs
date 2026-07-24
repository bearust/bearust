use bearust::cluster::{ClusterService, RaftRole, RaftStatus};
use bearust::cluster_command::{ClusterWriteError, CommandActor, ConfigCommandGateway};
use bearust::cluster_raft::ConfigCommand;
use bearust::cluster_raft_runtime::{bootstrap_single_node, construct_raft_with_id};
use bearust::config::ClusterConfig;
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use std::sync::Arc;
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

async fn test_gateway_with_role(
    role: RaftRole,
    leader_id: Option<&str>,
    quorum_available: bool,
    single_node: bool,
) -> (
    ConfigCommandGateway,
    openraft::Raft<bearust::cluster_raft::BearustRaftConfig>,
) {
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
        peers: if single_node {
            vec![]
        } else {
            vec![bearust::config::ClusterPeer {
                node_id: "node-2".into(),
                address: "127.0.0.1:1".parse().unwrap(),
            }]
        },
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: "cluster-command-test".into(),
    };
    let cluster = Arc::new(ClusterService::new(&config));
    cluster.set_raft_status(RaftStatus {
        role,
        leader_id: leader_id.map(str::to_owned),
        term: 1,
        last_log_index: 0,
        commit_index: 0,
        quorum_available,
        sync_state: "in_sync".into(),
    });

    (
        ConfigCommandGateway::new(Arc::new(raft.clone()), cluster),
        raft,
    )
}

#[tokio::test]
async fn follower_gateway_does_not_mutate_local_database() {
    let (gateway, raft) = test_gateway_with_role(RaftRole::Follower, None, true, false).await;

    let result = gateway.submit(test_create_command(), test_actor()).await;

    assert!(matches!(result, Err(ClusterWriteError::LeaderUnknown)));
    assert_eq!(raft.metrics().borrow().last_applied, None);
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn leader_gateway_submits_only_after_quorum_is_available() {
    let (gateway, raft) = test_gateway_with_role(RaftRole::Leader, Some("1"), true, false).await;

    let receipt = gateway
        .submit(test_create_command(), test_actor())
        .await
        .unwrap();

    assert_eq!(receipt.leader_id, 1);
    assert!(receipt.commit_index > 0);
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_rejects_writes_when_quorum_is_unavailable() {
    let (gateway, raft) = test_gateway_with_role(RaftRole::Leader, Some("1"), false, false).await;

    let result = gateway.submit(test_create_command(), test_actor()).await;

    assert!(matches!(result, Err(ClusterWriteError::QuorumUnavailable)));
    assert_eq!(raft.metrics().borrow().last_applied, None);
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn single_node_gateway_keeps_local_command_submission() {
    let (gateway, raft) =
        test_gateway_with_role(RaftRole::Standalone, Some("node-1"), true, true).await;

    let receipt = gateway
        .submit(test_create_command(), test_actor())
        .await
        .unwrap();

    assert_eq!(receipt.leader_id, 1);
    assert!(receipt.commit_index > 0);
    raft.shutdown().await.unwrap();
}
