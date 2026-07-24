use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::adaptive_tuning::{PolicyPatch, PolicyRecommendation, TuningMode, TuningPolicy};
use bearust::cluster::{handshake_tag, run_cluster_listener, ClusterService, HANDSHAKE_MAGIC};
use bearust::cluster_command::ConfigCommandGateway;
use bearust::cluster_raft_runtime::{
    construct_raft_with_id, decode_raft_rpc, encode_raft_rpc, send_authenticated_rpc_with_identity,
    OpenRaftRpcHandler,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::{
    auth::{hash_password, token_hash},
    build_state, repository, router, AppState,
};
use openraft::BasicNode;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
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

const COMMAND_TEST_SECRET: &str = "01234567890123456789012345678901";

struct ControlPlaneCommandCluster {
    states: Vec<AppState>,
    apps: Vec<Router>,
    rafts: Vec<openraft::Raft<bearust::cluster_raft::BearustRaftConfig>>,
    shutdowns: Vec<watch::Sender<bool>>,
}

impl ControlPlaneCommandCluster {
    async fn shutdown(self) {
        for shutdown in self.shutdowns {
            let _ = shutdown.send(true);
        }
        for raft in self.rafts {
            let _ = raft.shutdown().await;
        }
    }
}

async fn reserve_cluster_addresses() -> [SocketAddr; 3] {
    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let third = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    [
        first.local_addr().unwrap(),
        second.local_addr().unwrap(),
        third.local_addr().unwrap(),
    ]
}

async fn command_cluster() -> ControlPlaneCommandCluster {
    let addresses = reserve_cluster_addresses().await;
    let ids = ["api-node-1", "api-node-2", "api-node-3"];
    let mut states = Vec::new();
    let mut rafts = Vec::new();
    let mut shutdowns = Vec::new();

    for (index, (node_id, bind)) in ids.iter().zip(addresses).enumerate() {
        let directory = Box::leak(Box::new(tempdir().unwrap()));
        let mut state = build_state("sqlite::memory:", directory.path(), "setup-token")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,role,created_at,disabled)
             VALUES(7,'admin@example.test','hash','admin','2026-01-01T00:00:00Z',0)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        repository::create_session(
            &state.db,
            7,
            &token_hash("cluster-admin-token"),
            "2099-01-01T00:00:00Z",
        )
        .await
        .unwrap();

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
            auth_token: COMMAND_TEST_SECRET.into(),
        };
        let cluster = Arc::new(ClusterService::new(&config));
        let raft = construct_raft_with_id(
            state.db.clone(),
            *node_id,
            COMMAND_TEST_SECRET.as_bytes(),
            (index + 1) as u64,
        )
        .await
        .unwrap();
        cluster.set_raft_handler(Arc::new(OpenRaftRpcHandler::new(raft.clone())));
        let gateway =
            ConfigCommandGateway::new(Arc::new(raft.clone()), cluster.clone(), state.db.clone());
        cluster.set_command_handler(Arc::new(gateway.clone()));
        state = state
            .with_cluster(cluster.clone())
            .with_config_gateway(gateway.clone());

        let (shutdown, receiver) = watch::channel(false);
        tokio::spawn(run_cluster_listener(cluster.clone(), receiver));
        states.push(state);
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
                    COMMAND_TEST_SECRET.as_bytes(),
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
    rafts[0].initialize(members).await.unwrap();

    ControlPlaneCommandCluster {
        apps: states.iter().cloned().map(router).collect(),
        states,
        rafts,
        shutdowns,
    }
}

async fn wait_for_command_leader(
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
    .expect("three-node API cluster did not elect a live leader")
}

async fn api_request(
    app: Router,
    method: &str,
    uri: impl AsRef<str>,
    body: impl Into<Body>,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri.as_ref())
                .header("Cookie", "bearust_session=cluster-admin-token")
                .header("Content-Type", "application/json")
                .body(body.into())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

async fn wait_for_applied_command(cluster: &ControlPlaneCommandCluster, command_count: i64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut ready = true;
            for state in &cluster.states {
                let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM raft_command_receipts")
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
                ready &= applied >= command_count;
            }
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("replicated API command did not apply on every node");
}

#[tokio::test]
async fn follower_proxy_host_mutations_forward_and_reads_stay_local() {
    let cluster = command_cluster().await;
    let leader = wait_for_command_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    let app = cluster.apps[follower].clone();
    let mut committed_events = cluster.states[follower].realtime.subscribe_committed();

    let (status, created) = api_request(
        app.clone(),
        "POST",
        "/api/proxy-hosts",
        Body::from(
            r#"{"name":"forwarded","domain":"forwarded.example.test","upstream_host":"127.0.0.1","upstream_port":8080}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let host_id = created["id"].as_i64().unwrap();
    let committed = committed_events.recv().await.unwrap();
    assert_eq!(committed.event.kind, "proxy_hosts.changed");
    let receipt = repository::load_raft_command_receipt(
        &cluster.states[follower].db,
        &committed.command_id.to_string(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(receipt.leader_id, committed.leader_id as i64);
    assert_eq!(receipt.log_index, committed.commit_index as i64);
    let public_event = serde_json::to_value(&committed.event).unwrap();
    assert!(public_event.get("command_id").is_none());
    assert!(public_event.get("commit_index").is_none());
    wait_for_applied_command(&cluster, 1).await;
    for state in &cluster.states {
        assert_eq!(
            repository::get_host(&state.db, host_id)
                .await
                .unwrap()
                .unwrap()
                .domain,
            "forwarded.example.test"
        );
    }

    let local_only_id = repository::insert_host(
        &cluster.states[follower].db,
        &bearust::control_plane::models::ProxyHost {
            id: 991,
            name: "local-read".into(),
            domain: "local-read.example.test".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8091,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    )
    .await
    .unwrap()
    .id;
    let (status, read) = api_request(
        app.clone(),
        "GET",
        format!("/api/proxy-hosts/{local_only_id}"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["domain"], "local-read.example.test");
    assert!(
        repository::get_host(&cluster.states[leader].db, local_only_id)
            .await
            .unwrap()
            .is_none(),
        "GET must use the follower's committed local view instead of forwarding"
    );

    let (status, updated) = api_request(
        app.clone(),
        "PATCH",
        format!("/api/proxy-hosts/{host_id}"),
        Body::from(
            r#"{"name":"updated","domain":"updated.example.test","upstream_host":"127.0.0.1","upstream_port":8081}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["domain"], "updated.example.test");
    wait_for_applied_command(&cluster, 2).await;

    let (status, _) = api_request(
        app,
        "DELETE",
        format!("/api/proxy-hosts/{host_id}"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    wait_for_applied_command(&cluster, 3).await;
    for state in &cluster.states {
        assert!(repository::get_host(&state.db, host_id)
            .await
            .unwrap()
            .is_none());
    }

    cluster.shutdown().await;
}

#[tokio::test]
async fn follower_runtime_policy_apply_and_rollback_forward() {
    let cluster = command_cluster().await;
    let leader = wait_for_command_leader(&cluster.rafts).await;
    let follower = (leader + 1) % cluster.rafts.len();
    let host_id = 77;
    let recommendation = PolicyRecommendation {
        id: 0,
        host_id,
        patch: PolicyPatch {
            capacity: Some(25),
            refill_per_second: Some(2.5),
            waf_mode: None,
        },
        confidence: 0.95,
        reason: "forward runtime policy".into(),
        created_at: chrono::Utc::now(),
        applied: false,
        applied_at: None,
        previous_config_json: None,
    };
    repository::update_tuning_policy(
        &cluster.states[follower].db,
        host_id,
        &TuningPolicy {
            mode: TuningMode::Recommend,
            ..TuningPolicy::default()
        },
    )
    .await
    .unwrap();
    let recommendation_id =
        repository::insert_tuning_recommendation(&cluster.states[follower].db, &recommendation)
            .await
            .unwrap();

    let (status, _) = api_request(
        cluster.apps[follower].clone(),
        "POST",
        format!("/api/adaptive-tuning/recommendations/{recommendation_id}/apply"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_for_applied_command(&cluster, 1).await;
    for state in &cluster.states {
        let policy = repository::get_host_rate_limit_config(&state.db, host_id)
            .await
            .unwrap();
        assert_eq!(policy.capacity, 25);
        assert_eq!(policy.refill_per_second, 2.5);
    }

    let (status, _) = api_request(
        cluster.apps[follower].clone(),
        "POST",
        format!("/api/adaptive-tuning/recommendations/{recommendation_id}/rollback"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_for_applied_command(&cluster, 2).await;
    for state in &cluster.states {
        let policy = repository::get_host_rate_limit_config(&state.db, host_id)
            .await
            .unwrap();
        assert_eq!(policy.capacity, 100);
        assert_eq!(policy.refill_per_second, 10.0);
    }

    cluster.shutdown().await;
}
