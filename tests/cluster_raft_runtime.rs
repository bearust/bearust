use async_trait::async_trait;
use bearust::cluster_raft::encode_rpc_frame;
use bearust::cluster_raft::BearustRaftConfig;
use bearust::cluster_raft_runtime::deterministic_raft_id;
use bearust::cluster_raft_runtime::AuthenticatedRaftNetworkFactory;
use bearust::cluster_raft_runtime::{decode_raft_rpc, encode_raft_rpc};
use bearust::cluster_raft_runtime::{
    dispatch_authenticated_rpc, send_authenticated_rpc, validate_multi_node_join, BootstrapError,
    RpcTransportError,
};
use bearust::cluster_raft_runtime::{dispatch_authenticated_rpc_with_handler, RaftRpcHandler};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// This smoke test locks the OpenRaft 0.9.21 integration boundary in place.
/// It deliberately does not instantiate a node: no durable SQLx adapters are
/// available yet, and a fake adapter would invalidate the recovery contract.
#[test]
fn openraft_runtime_requires_durable_adapter_set() {
    fn assert_config<C: openraft::RaftTypeConfig<NodeId = u64>>() {}
    assert_config::<BearustRaftConfig>();
    assert_eq!(std::mem::size_of::<BearustRaftConfig>(), 0);
}

#[test]
fn authenticated_network_factory_requires_secret() {
    assert!(AuthenticatedRaftNetworkFactory::new([]).is_none());
    assert!(AuthenticatedRaftNetworkFactory::new([7u8; 32]).is_some());
}

#[test]
fn deterministic_raft_ids_match_across_nodes() {
    let members = vec!["node-c".into(), "node-a".into(), "node-b".into()];
    assert_eq!(deterministic_raft_id("node-a", &members), Ok(1));
    assert_eq!(deterministic_raft_id("node-b", &members), Ok(2));
    assert_eq!(deterministic_raft_id("node-c", &members), Ok(3));
}

#[tokio::test]
async fn authenticated_rpc_rejects_tampered_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 50];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut request)
            .await
            .unwrap();
        let mut response = encode_rpc_frame(b"ok", b"correct-secret").unwrap();
        *response.last_mut().unwrap() ^= 1;
        stream.write_all(&response).await.unwrap();
    });
    let result = send_authenticated_rpc(
        &address.to_string(),
        b"request",
        b"correct-secret",
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result, Err(RpcTransportError::AuthenticationFailed));
}

#[tokio::test]
async fn authenticated_rpc_times_out_without_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let result = send_authenticated_rpc(
        &address.to_string(),
        b"request",
        b"correct-secret",
        Duration::from_millis(10),
    )
    .await;
    assert_eq!(result, Err(RpcTransportError::Timeout));
}

#[test]
fn dispatcher_rejects_unknown_and_unavailable_rpc_kinds() {
    let secret = b"correct-secret";
    for (payload, code) in [
        (br#"{"kind":"unknown"}"#.as_slice(), "unknown_rpc_kind"),
        (br#"{"kind":"vote"}"#.as_slice(), "raft_handler_unavailable"),
    ] {
        let frame = encode_rpc_frame(payload, secret).unwrap();
        let response = dispatch_authenticated_rpc(&frame, secret, "node-a").unwrap();
        let response = bearust::cluster_raft::decode_rpc_frame(&response, secret).unwrap();
        let value: serde_json::Value = serde_json::from_slice(response).unwrap();
        assert_eq!(value["code"], code);
    }
}

#[test]
fn dispatcher_rejects_malformed_json() {
    let frame = encode_rpc_frame(b"not-json", b"correct-secret").unwrap();
    assert_eq!(
        dispatch_authenticated_rpc(&frame, b"correct-secret", "node-a"),
        Err(RpcTransportError::Malformed)
    );
}

#[test]
fn multi_node_join_guard_requires_three_members_and_local_identity() {
    let mut members = BTreeMap::new();
    members.insert(1, openraft::BasicNode::new("a"));
    members.insert(2, openraft::BasicNode::new("b"));
    assert_eq!(
        validate_multi_node_join(1, &members),
        Err(BootstrapError::InvalidMultiNodeMembership)
    );
    members.insert(3, openraft::BasicNode::new("c"));
    assert_eq!(
        validate_multi_node_join(9, &members),
        Err(BootstrapError::LocalNodeMissing)
    );
    assert!(validate_multi_node_join(1, &members).is_ok());
}

#[test]
fn raft_rpc_envelope_round_trip_is_bounded_and_kind_checked() {
    let payload = encode_raft_rpc("vote", &serde_json::json!({"term": 3})).unwrap();
    let decoded: serde_json::Value = decode_raft_rpc(&payload, "vote").unwrap();
    assert_eq!(decoded["term"], 3);
    assert_eq!(
        decode_raft_rpc::<serde_json::Value>(&payload, "append_entries"),
        Err(RpcTransportError::Malformed)
    );
}

struct TestRpcHandler;
#[async_trait]
impl RaftRpcHandler for TestRpcHandler {
    async fn handle(&self, kind: &str, _payload: &[u8]) -> Result<Vec<u8>, RpcTransportError> {
        encode_raft_rpc("handled", &serde_json::json!({"kind": kind}))
            .map_err(|_| RpcTransportError::Malformed)
    }
}

#[tokio::test]
async fn dispatcher_invokes_rpc_handler_for_authenticated_envelope() {
    let secret = b"correct-secret";
    let body = encode_raft_rpc("vote", &serde_json::json!({"term": 1})).unwrap();
    let frame = bearust::cluster_raft::encode_rpc_frame(&body, secret).unwrap();
    let response =
        dispatch_authenticated_rpc_with_handler(&frame, secret, "node-a", &TestRpcHandler)
            .await
            .unwrap();
    let payload = bearust::cluster_raft::decode_rpc_frame(&response, secret).unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(envelope["kind"], "handled");
}
