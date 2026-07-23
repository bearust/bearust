use bearust::cluster_raft::encode_rpc_frame;
use bearust::cluster_raft::BearustRaftConfig;
use bearust::cluster_raft_runtime::AuthenticatedRaftNetworkFactory;
use bearust::cluster_raft_runtime::{dispatch_authenticated_rpc, send_authenticated_rpc, RpcTransportError};
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
