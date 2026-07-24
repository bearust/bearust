use bearust::cluster::{run_cluster_listener, ClusterService};
use bearust::cluster_command::{
    committed_event_kind, decode_forwarded_command, encode_forwarded_command, ClusterWriteError,
    CommandActor, ConfigCommandGateway,
};
use bearust::cluster_raft::{decode_rpc_frame, encode_rpc_frame, ConfigCommand, RPC_TAG_BYTES};
use bearust::cluster_raft_runtime::{
    bootstrap_single_node, construct_raft_with_id, decode_raft_rpc, encode_raft_rpc,
    initialize_membership, send_authenticated_rpc_with_identity, OpenRaftRpcHandler,
    RpcTransportError,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use openraft::BasicNode;
use sqlx::any::AnyPoolOptions;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use uuid::Uuid;

const TEST_SECRET: &str = "cluster-command-test";

fn test_actor() -> CommandActor {
    CommandActor {
        user_id: 7,
        email: "operator@example.test".into(),
        role: "operator".into(),
    }
}

fn test_create_command() -> ConfigCommand {
    create_command(42, "gateway.example.test")
}

fn create_command(host_id: i64, domain: &str) -> ConfigCommand {
    ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: ProxyHost {
            id: host_id,
            name: "gateway-test".into(),
            domain: domain.into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8080,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    }
}

#[test]
fn replicated_commands_map_to_existing_public_event_kinds() {
    let proxy = test_create_command();
    let runtime = ConfigCommand::UpdateRuntimePolicy {
        command_id: Uuid::new_v4(),
        host_id: 42,
        policy: bearust::rate_limit::RateLimitPolicy::default(),
    };

    assert_eq!(committed_event_kind(&proxy), Some("proxy_hosts.changed"));
    assert_eq!(committed_event_kind(&runtime), Some("rate_limit.changed"));
    assert_eq!(
        committed_event_kind(&ConfigCommand::Noop {
            command_id: Uuid::new_v4(),
        }),
        None
    );
}

#[test]
fn system_actor_is_limited_to_runtime_policy_commands() {
    let runtime = ConfigCommand::UpdateRuntimePolicy {
        command_id: Uuid::new_v4(),
        host_id: 42,
        policy: bearust::rate_limit::RateLimitPolicy::default(),
    };

    assert!(encode_forwarded_command("node-1", runtime, CommandActor::system()).is_ok());
    assert_eq!(
        encode_forwarded_command("node-1", test_create_command(), CommandActor::system()),
        Err(ClusterWriteError::ForwardAuthentication)
    );
}

async fn seed_test_actor(pool: &repository::DbPool) {
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,role,created_at,disabled)
         VALUES(7,'operator@example.test','hash','operator','2026-01-01T00:00:00Z',0)",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[test]
fn forwarded_command_accepts_structurally_valid_viewer_for_authoritative_authorization() {
    let command = test_create_command();
    let mut payload = encode_forwarded_command("node-1", command, test_actor()).unwrap();
    let actor = payload
        .get_mut("actor")
        .and_then(serde_json::Value::as_object_mut)
        .expect("forwarded command has an actor object");
    actor.insert("role".into(), serde_json::Value::String("viewer".into()));

    let (_, _, decoded_actor) = decode_forwarded_command(&payload).unwrap();
    assert_eq!(decoded_actor.role, "viewer");
}

#[test]
fn forwarded_command_rejects_command_id_mismatch() {
    let command = test_create_command();
    let mut payload = encode_forwarded_command("node-1", command, test_actor()).unwrap();
    payload["command_id"] = serde_json::json!(Uuid::new_v4());

    assert!(matches!(
        decode_forwarded_command(&payload),
        Err(ClusterWriteError::ForwardAuthentication)
    ));
}

#[test]
fn forwarded_command_rejects_oversized_origin() {
    assert_eq!(
        encode_forwarded_command(&"n".repeat(256), test_create_command(), test_actor()),
        Err(ClusterWriteError::ForwardAuthentication)
    );
}

struct ThreeNodeGatewayCluster {
    addresses: [SocketAddr; 3],
    clusters: Vec<Arc<ClusterService>>,
    gateways: Vec<ConfigCommandGateway>,
    pools: Vec<repository::DbPool>,
    rafts: Vec<openraft::Raft<bearust::cluster_raft::BearustRaftConfig>>,
    shutdowns: Vec<watch::Sender<bool>>,
}

impl ThreeNodeGatewayCluster {
    async fn shutdown(self) {
        for shutdown in self.shutdowns {
            let _ = shutdown.send(true);
        }
        for raft in self.rafts {
            let _ = raft.shutdown().await;
        }
    }
}

async fn three_node_gateway_cluster(base_port: u16) -> ThreeNodeGatewayCluster {
    let secret = TEST_SECRET.to_string();
    let addresses: [SocketAddr; 3] = [
        format!("127.0.0.1:{base_port}").parse().unwrap(),
        format!("127.0.0.1:{}", base_port + 1).parse().unwrap(),
        format!("127.0.0.1:{}", base_port + 2).parse().unwrap(),
    ];
    let ids = ["node-1", "node-2", "node-3"];
    let mut clusters = Vec::new();
    let mut gateways = Vec::new();
    let mut pools = Vec::new();
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
        seed_test_actor(&pool).await;
        let raft = construct_raft_with_id(
            pool.clone(),
            *node_id,
            secret.as_bytes(),
            (index + 1) as u64,
        )
        .await
        .unwrap();
        cluster.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(raft.clone())));
        let (shutdown, receiver) = watch::channel(false);
        tokio::spawn(run_cluster_listener(cluster.clone(), receiver));
        let gateway =
            ConfigCommandGateway::new(Arc::new(raft.clone()), cluster.clone(), pool.clone());
        cluster.set_command_handler(Arc::new(gateway.clone()));
        clusters.push(cluster);
        gateways.push(gateway);
        pools.push(pool);
        rafts.push(raft);
        shutdowns.push(shutdown);
    }

    for (index, address) in addresses.iter().enumerate() {
        let request = encode_raft_rpc("status", &serde_json::json!({})).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(response) = send_authenticated_rpc_with_identity(
                    &address.to_string(),
                    ids[(index + 1) % ids.len()],
                    &request,
                    TEST_SECRET.as_bytes(),
                    Duration::from_millis(100),
                )
                .await
                {
                    let response: serde_json::Value = decode_raft_rpc(&response, "status").unwrap();
                    if response["node_id"] == ids[index] && response["status"] == "transport_ready"
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cluster listener did not accept authenticated RPCs");
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
    initialize_membership(&rafts[0], &clusters[0], members)
        .await
        .unwrap();

    ThreeNodeGatewayCluster {
        addresses,
        clusters,
        gateways,
        pools,
        rafts,
        shutdowns,
    }
}

async fn wait_for_live_leader(
    rafts: &[openraft::Raft<bearust::cluster_raft::BearustRaftConfig>],
) -> usize {
    tokio::time::timeout(Duration::from_secs(12), async {
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
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("three-node leader did not receive a quorum acknowledgement")
}

async fn listener_fixture(
    timeout_seconds: u64,
) -> (SocketAddr, watch::Sender<bool>, Arc<ClusterService>) {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let config = ClusterConfig {
        node_id: "node-a".into(),
        peers: vec![ClusterPeer {
            node_id: "node-b".into(),
            address: "127.0.0.1:1".parse().unwrap(),
        }],
        bind: address,
        timeout_seconds,
        auth_token: TEST_SECRET.into(),
    };
    let service = Arc::new(ClusterService::new(&config));
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(run_cluster_listener(service.clone(), receiver));
    let request = encode_raft_rpc("status", &serde_json::json!({})).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if send_authenticated_rpc_with_identity(
                &address.to_string(),
                "node-b",
                &request,
                TEST_SECRET.as_bytes(),
                Duration::from_millis(100),
            )
            .await
            .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cluster listener did not become ready");
    (address, shutdown, service)
}

async fn complete_handshake(stream: &mut TcpStream, node_id: &str) {
    let nonce = *Uuid::new_v4().as_bytes();
    let node_id = node_id.as_bytes();
    let tag = bearust::cluster::handshake_tag(TEST_SECRET.as_bytes(), b"request", &nonce, node_id);
    let mut request = Vec::new();
    request.extend_from_slice(bearust::cluster::HANDSHAKE_MAGIC);
    request.push(node_id.len() as u8);
    request.extend_from_slice(node_id);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&tag);
    stream.write_all(&request).await.unwrap();

    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic).await.unwrap();
    assert_eq!(&magic, bearust::cluster::HANDSHAKE_MAGIC);
    let mut echoed_nonce = [0u8; 16];
    stream.read_exact(&mut echoed_nonce).await.unwrap();
    assert_eq!(echoed_nonce, nonce);
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await.unwrap();
    let mut peer_id = vec![0u8; len[0] as usize];
    stream.read_exact(&mut peer_id).await.unwrap();
    let mut response_tag = [0u8; 32];
    stream.read_exact(&mut response_tag).await.unwrap();
    let expected =
        bearust::cluster::handshake_tag(TEST_SECRET.as_bytes(), b"response", &nonce, &peer_id);
    assert_eq!(response_tag, expected);
}

#[tokio::test]
async fn cluster_listener_rejects_valid_hmac_from_unknown_node_id() {
    let (address, shutdown, _service) = listener_fixture(2).await;
    let request = encode_raft_rpc("status", &serde_json::json!({})).unwrap();

    let result = send_authenticated_rpc_with_identity(
        &address.to_string(),
        "unknown-node",
        &request,
        TEST_SECRET.as_bytes(),
        Duration::from_secs(1),
    )
    .await;

    let _ = shutdown.send(true);
    assert_eq!(result, Err(RpcTransportError::Malformed));
}

#[tokio::test]
async fn cluster_listener_accepts_rpc_frame_delayed_beyond_fifty_milliseconds() {
    let (address, shutdown, _service) = listener_fixture(2).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    complete_handshake(&mut stream, "node-b").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let request = encode_raft_rpc("status", &serde_json::json!({})).unwrap();
    let frame = encode_rpc_frame(&request, TEST_SECRET.as_bytes()).unwrap();
    stream.write_all(&frame).await.unwrap();

    let response = tokio::time::timeout(Duration::from_secs(1), async {
        let mut header = [0u8; 11];
        stream.read_exact(&mut header).await.unwrap();
        let declared = u32::from_be_bytes(header[7..11].try_into().unwrap()) as usize;
        let mut rest = vec![0u8; declared + RPC_TAG_BYTES];
        stream.read_exact(&mut rest).await.unwrap();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&rest);
        decode_rpc_frame(&frame, TEST_SECRET.as_bytes())
            .unwrap()
            .to_vec()
    })
    .await
    .expect("listener closed before the configured operation timeout");
    let response: serde_json::Value = serde_json::from_slice(&response).unwrap();

    let _ = shutdown.send(true);
    assert_eq!(response["kind"], "status");
    assert_eq!(response["node_id"], "node-a");
}

#[tokio::test]
async fn forwarded_command_rejects_origin_that_differs_from_handshake_identity() {
    let cluster = three_node_gateway_cluster(42291).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let caller = (leader + 1) % cluster.rafts.len();
    let claimed_origin = format!("node-{}", ((caller + 1) % cluster.rafts.len()) + 1);
    let authenticated_origin = format!("node-{}", caller + 1);
    let envelope =
        encode_forwarded_command(&claimed_origin, test_create_command(), test_actor()).unwrap();
    let request = encode_raft_rpc("config_command", &envelope).unwrap();

    let response = send_authenticated_rpc_with_identity(
        &cluster.addresses[leader].to_string(),
        &authenticated_origin,
        &request,
        TEST_SECRET.as_bytes(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let response: serde_json::Value =
        decode_raft_rpc(&response, "config_command_response").unwrap();
    cluster.shutdown().await;

    assert_eq!(
        response,
        serde_json::json!({
            "result": "error",
            "code": "forward_authentication",
        })
    );
}

#[tokio::test]
async fn follower_gateway_forwards_without_locally_committing() {
    let cluster = three_node_gateway_cluster(42301).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();

    let receipt = cluster.gateways[follower]
        .submit(test_create_command(), test_actor())
        .await
        .unwrap();

    assert_eq!(receipt.leader_id, (leader + 1) as u64);
    for raft in &cluster.rafts {
        raft.wait(Some(Duration::from_secs(2)))
            .applied_index_at_least(Some(receipt.commit_index), "forwarded command applied")
            .await
            .unwrap();
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn forwarded_receipt_is_preserved_when_local_apply_is_pending() {
    let cluster = three_node_gateway_cluster(42351).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    cluster.rafts[follower].shutdown().await.unwrap();
    let command = test_create_command();
    let command_id = command.command_id();

    let result = cluster.gateways[follower]
        .submit(command, test_actor())
        .await;

    let receipt = match result {
        Err(ClusterWriteError::LocalApplyPending { receipt }) => receipt,
        other => panic!("expected committed local-apply-pending outcome, got {other:?}"),
    };
    assert_eq!(receipt.command_id, command_id);
    assert_eq!(receipt.leader_id, (leader + 1) as u64);
    assert!(repository::load_raft_command_receipt(
        &cluster.pools[leader],
        &receipt.command_id.to_string()
    )
    .await
    .unwrap()
    .is_some());
    cluster.shutdown().await;
}

#[tokio::test]
async fn repeated_forwarded_command_returns_the_original_receipt() {
    let cluster = three_node_gateway_cluster(42306).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    let command = test_create_command();

    let first = cluster.gateways[follower]
        .submit(command.clone(), test_actor())
        .await
        .unwrap();
    let second = cluster.gateways[follower]
        .submit(command, test_actor())
        .await
        .unwrap();

    assert_eq!(second, first);
    cluster.shutdown().await;
}

#[tokio::test]
async fn deposed_leader_only_submission_does_not_forward() {
    let cluster = three_node_gateway_cluster(42356).await;
    let old_leader = wait_for_live_leader(&cluster.rafts).await;
    cluster.rafts[old_leader].shutdown().await.unwrap();
    assert!(!cluster.gateways[old_leader].is_confirmed_local_leader());
    let command = ConfigCommand::UpdateRuntimePolicy {
        command_id: Uuid::new_v4(),
        host_id: 42,
        policy: bearust::rate_limit::RateLimitPolicy::default(),
    };
    let command_id = command.command_id();

    let result = cluster.gateways[old_leader]
        .submit_leader_only(command, CommandActor::system())
        .await;

    assert_eq!(result, Err(ClusterWriteError::LeaderUnknown));
    tokio::time::sleep(Duration::from_millis(100)).await;
    for pool in &cluster.pools {
        assert!(
            repository::load_raft_command_receipt(pool, &command_id.to_string())
                .await
                .unwrap()
                .is_none(),
            "a deposed scheduled actor must not forward its stale decision"
        );
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn concurrent_stale_create_conflict_is_a_result_and_raft_stays_writable() {
    let cluster = three_node_gateway_cluster(42361).await;
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let first_follower = (leader + 1) % cluster.rafts.len();
    let second_follower = (leader + 2) % cluster.rafts.len();
    let first = cluster.gateways[first_follower]
        .submit(create_command(101, "conflict.example.test"), test_actor());
    let second = cluster.gateways[second_follower]
        .submit(create_command(102, "conflict.example.test"), test_actor());

    let (first, second) = tokio::join!(first, second);

    assert!(
        matches!(
            (&first, &second),
            (Ok(_), Err(ClusterWriteError::DuplicateDomain))
                | (Err(ClusterWriteError::DuplicateDomain), Ok(_))
        ),
        "one ordered create must apply and the stale concurrent create must conflict: first={first:?}, second={second:?}"
    );
    let receipt = cluster.gateways[leader]
        .submit(
            create_command(103, "still-writable.example.test"),
            test_actor(),
        )
        .await
        .unwrap();
    for raft in &cluster.rafts {
        raft.wait(Some(Duration::from_secs(2)))
            .applied_index_at_least(Some(receipt.commit_index), "post-conflict command applied")
            .await
            .unwrap();
    }
    for pool in &cluster.pools {
        let conflict_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM proxy_hosts WHERE domain=?")
                .bind("conflict.example.test")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(conflict_count, 1);
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn receipt_survives_log_purge_and_gateway_restart() {
    let cluster = three_node_gateway_cluster(42326).await;
    for pool in &cluster.pools {
        sqlx::query("UPDATE users SET role='admin' WHERE id=7")
            .execute(pool)
            .await
            .unwrap();
    }
    let mut actor = test_actor();
    actor.role = "admin".into();
    let leader = wait_for_live_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    let command = test_create_command();
    let original = cluster.gateways[follower]
        .submit(command.clone(), actor.clone())
        .await
        .unwrap();
    for raft in &cluster.rafts {
        raft.wait(Some(Duration::from_secs(2)))
            .applied_index_at_least(Some(original.commit_index), "original command applied")
            .await
            .unwrap();
    }
    repository::purge_raft_log(
        &cluster.pools[leader],
        &format!("node-{}", leader + 1),
        original.commit_index as i64,
    )
    .await
    .unwrap();
    let restarted = ConfigCommandGateway::new(
        Arc::new(cluster.rafts[leader].clone()),
        cluster.clusters[leader].clone(),
        cluster.pools[leader].clone(),
    );
    cluster.clusters[leader].set_command_handler(Arc::new(restarted.clone()));

    let retried = restarted.submit(command, actor).await.unwrap();

    assert_eq!(retried, original);
    cluster.shutdown().await;
}

#[tokio::test]
async fn standalone_command_retry_after_membership_transition_is_committed() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    seed_test_actor(&pool).await;
    let raft = construct_raft_with_id(pool.clone(), "node-1", TEST_SECRET.as_bytes(), 1)
        .await
        .unwrap();
    let config = ClusterConfig {
        node_id: "node-1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: TEST_SECRET.into(),
    };
    let cluster = Arc::new(ClusterService::new(&config));
    let gateway = ConfigCommandGateway::new(Arc::new(raft.clone()), cluster.clone(), pool.clone());
    let command = test_create_command();
    let command_id = command.command_id();

    let local = gateway
        .submit_with_standalone_fallback(command.clone(), test_actor())
        .await
        .unwrap();
    assert_eq!(local.leader_id, 0);
    bootstrap_single_node(&raft, &cluster, 1, "127.0.0.1:0")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if gateway.is_confirmed_local_leader() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("single node did not elect itself after topology transition");

    let committed = gateway
        .submit_with_standalone_fallback(command, test_actor())
        .await
        .unwrap();

    assert_eq!(committed.command_id, command_id);
    assert_eq!(committed.leader_id, 1);
    assert!(committed.commit_index > 0);
    assert!(
        repository::load_raft_command_receipt(&pool, &command_id.to_string())
            .await
            .unwrap()
            .is_some()
    );
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn membership_initialization_waits_for_in_flight_standalone_apply() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("control.db");
    std::fs::File::create(&database_path).unwrap();
    let database_url = format!("sqlite://{}", database_path.display());
    let raft_pool = repository::connect(&database_url).await.unwrap();
    repository::migrate(&raft_pool).await.unwrap();
    seed_test_actor(&raft_pool).await;
    let gateway_pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    let held_connection = gateway_pool.acquire().await.unwrap();
    let raft = construct_raft_with_id(raft_pool, "node-1", TEST_SECRET.as_bytes(), 1)
        .await
        .unwrap();
    let config = ClusterConfig {
        node_id: "node-1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: TEST_SECRET.into(),
    };
    let cluster = Arc::new(ClusterService::new(&config));
    let gateway = ConfigCommandGateway::new(Arc::new(raft.clone()), cluster.clone(), gateway_pool);
    let fallback = tokio::spawn({
        let gateway = gateway.clone();
        async move {
            gateway
                .submit_with_standalone_fallback(test_create_command(), test_actor())
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut initialization = tokio::spawn({
        let raft = raft.clone();
        let cluster = cluster.clone();
        async move {
            initialize_membership(
                &raft,
                &cluster,
                BTreeMap::from([(1, BasicNode::new("127.0.0.1:0"))]),
            )
            .await
        }
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut initialization)
            .await
            .is_err(),
        "membership activated while a standalone submission was in flight"
    );
    drop(held_connection);
    let local = tokio::time::timeout(Duration::from_secs(2), fallback)
        .await
        .expect("standalone submission remained blocked")
        .unwrap()
        .unwrap();
    assert_eq!(local.leader_id, 0);
    assert_eq!(local.commit_index, 0);
    tokio::time::timeout(Duration::from_secs(2), initialization)
        .await
        .expect("membership initialization remained blocked")
        .unwrap()
        .unwrap();
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn completed_membership_initialization_prevents_immediate_standalone_fallback() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    seed_test_actor(&pool).await;
    let raft = construct_raft_with_id(pool.clone(), "node-1", TEST_SECRET.as_bytes(), 1)
        .await
        .unwrap();
    let config = ClusterConfig {
        node_id: "node-1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: TEST_SECRET.into(),
    };
    let cluster = Arc::new(ClusterService::new(&config));
    let gateway = ConfigCommandGateway::new(Arc::new(raft.clone()), cluster.clone(), pool);

    initialize_membership(
        &raft,
        &cluster,
        BTreeMap::from([(1, BasicNode::new("127.0.0.1:0"))]),
    )
    .await
    .unwrap();
    let result = gateway
        .submit_with_standalone_fallback(test_create_command(), test_actor())
        .await;

    if let Ok(receipt) = result {
        assert_ne!(
            (receipt.leader_id, receipt.commit_index),
            (0, 0),
            "completed membership initialization returned a standalone receipt"
        );
    }
    raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_denies_viewer_disabled_and_actor_mismatch() {
    let cluster = three_node_gateway_cluster(42331).await;
    let node = wait_for_live_leader(&cluster.rafts).await;
    let pool = &cluster.pools[node];

    sqlx::query("UPDATE users SET role='viewer',disabled=0 WHERE id=7")
        .execute(pool)
        .await
        .unwrap();
    let mut actor = test_actor();
    actor.role = "viewer".into();
    assert_eq!(
        cluster.gateways[node]
            .submit(test_create_command(), actor)
            .await,
        Err(ClusterWriteError::ForwardAuthentication)
    );

    sqlx::query("UPDATE users SET role='operator',disabled=1 WHERE id=7")
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        cluster.gateways[node]
            .submit(test_create_command(), test_actor())
            .await,
        Err(ClusterWriteError::ForwardAuthentication)
    );

    sqlx::query("UPDATE users SET disabled=0 WHERE id=7")
        .execute(pool)
        .await
        .unwrap();
    let mut mismatched = test_actor();
    mismatched.role = "admin".into();
    assert_eq!(
        cluster.gateways[node]
            .submit(test_create_command(), mismatched)
            .await,
        Err(ClusterWriteError::ForwardAuthentication)
    );

    let mut mismatched = test_actor();
    mismatched.user_id += 1;
    assert_eq!(
        cluster.gateways[node]
            .submit(test_create_command(), mismatched)
            .await,
        Err(ClusterWriteError::ForwardAuthentication)
    );

    let mut mismatched = test_actor();
    mismatched.email = "different@example.test".into();
    assert_eq!(
        cluster.gateways[node]
            .submit(test_create_command(), mismatched)
            .await,
        Err(ClusterWriteError::ForwardAuthentication)
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
    seed_test_actor(&pool).await;
    let raft = construct_raft_with_id(pool.clone(), "node-1", TEST_SECRET.as_bytes(), 1)
        .await
        .unwrap();
    let config = ClusterConfig {
        node_id: "node-1".into(),
        peers: vec![],
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout_seconds: 1,
        auth_token: TEST_SECRET.into(),
    };
    let cluster = Arc::new(ClusterService::new(&config));
    bootstrap_single_node(&raft, &cluster, 1, "127.0.0.1:0")
        .await
        .unwrap();
    let gateway = ConfigCommandGateway::new(Arc::new(raft.clone()), cluster, pool);
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
