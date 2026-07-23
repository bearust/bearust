//! Compile-time contract for the OpenRaft runtime integration.
//!
//! This module intentionally does not provide placeholder storage or network
//! implementations.  OpenRaft 0.9's `storage-v2` API requires durable log,
//! vote, commit, state-machine, snapshot, and all RPC transport operations;
//! silently returning defaults here would make a node appear healthy while
//! losing committed data.  The contract below keeps the dependency/API
//! integration checked while the SQLx-backed adapters are implemented.

use crate::cluster_raft::BearustRaftConfig;
use crate::cluster_raft_storage::SqlxRaftStorage;
use crate::control_plane::repository::DbPool;
use async_trait::async_trait;
use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const RPC_MAGIC_LEN: usize = 7;
const RPC_HEADER_LEN: usize = RPC_MAGIC_LEN + 4;
const RPC_TAG_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcTransportError {
    #[error("raft RPC transport timed out")]
    Timeout,
    #[error("raft RPC transport unavailable")]
    Unavailable,
    #[error("raft RPC response malformed")]
    Malformed,
    #[error("raft RPC response authentication failed")]
    AuthenticationFailed,
    #[error("raft RPC payload exceeds configured limit")]
    PayloadTooLarge,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RaftRpcEnvelope {
    pub kind: String,
    pub payload: Value,
}

/// Serialize an OpenRaft request into a bounded, authenticated-envelope
/// payload. The actual request type remains opaque to the transport layer.
pub fn encode_raft_rpc<T: Serialize>(
    kind: &str,
    request: &T,
) -> Result<Vec<u8>, RpcTransportError> {
    let payload = serde_json::to_value(request).map_err(|_| RpcTransportError::Malformed)?;
    let envelope = RaftRpcEnvelope {
        kind: kind.to_string(),
        payload,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| RpcTransportError::Malformed)?;
    if bytes.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
        return Err(RpcTransportError::PayloadTooLarge);
    }
    Ok(bytes)
}

pub fn decode_raft_rpc<T: DeserializeOwned>(
    payload: &[u8],
    expected_kind: &str,
) -> Result<T, RpcTransportError> {
    if payload.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
        return Err(RpcTransportError::PayloadTooLarge);
    }
    let envelope: RaftRpcEnvelope =
        serde_json::from_slice(payload).map_err(|_| RpcTransportError::Malformed)?;
    if envelope.kind != expected_kind {
        return Err(RpcTransportError::Malformed);
    }
    serde_json::from_value(envelope.payload).map_err(|_| RpcTransportError::Malformed)
}

#[async_trait]
pub trait RaftRpcHandler: Send + Sync {
    async fn handle(&self, kind: &str, payload: &[u8]) -> Result<Vec<u8>, RpcTransportError>;
}

pub struct OpenRaftRpcHandler {
    raft: openraft::Raft<BearustRaftConfig>,
}

pub async fn dispatch_authenticated_rpc_with_handler(
    frame: &[u8],
    secret: &[u8],
    node_id: &str,
    handler: &dyn RaftRpcHandler,
) -> Result<Vec<u8>, RpcTransportError> {
    let payload = crate::cluster_raft::decode_rpc_frame(frame, secret)
        .map_err(|_| RpcTransportError::AuthenticationFailed)?;
    let envelope: RaftRpcEnvelope =
        serde_json::from_slice(payload).map_err(|_| RpcTransportError::Malformed)?;
    if envelope.kind == "status" {
        let status = encode_raft_rpc(
            "status",
            &serde_json::json!({"node_id": node_id, "status": "transport_ready"}),
        )?;
        return crate::cluster_raft::encode_rpc_frame(&status, secret)
            .map_err(|_| RpcTransportError::Malformed);
    }
    let request = serde_json::to_vec(&envelope).map_err(|_| RpcTransportError::Malformed)?;
    let response = handler.handle(&envelope.kind, &request).await?;
    crate::cluster_raft::encode_rpc_frame(&response, secret)
        .map_err(|_| RpcTransportError::Malformed)
}

impl OpenRaftRpcHandler {
    pub fn new(raft: openraft::Raft<BearustRaftConfig>) -> Self {
        Self { raft }
    }
}

#[async_trait]
impl RaftRpcHandler for OpenRaftRpcHandler {
    async fn handle(&self, kind: &str, payload: &[u8]) -> Result<Vec<u8>, RpcTransportError> {
        match kind {
            "vote" => {
                let request: VoteRequest<u64> = decode_raft_rpc(payload, kind)?;
                let response = self
                    .raft
                    .vote(request)
                    .await
                    .map_err(|_| RpcTransportError::Unavailable)?;
                encode_raft_rpc("vote_response", &response)
            }
            "append_entries" => {
                let request: AppendEntriesRequest<BearustRaftConfig> =
                    decode_raft_rpc(payload, kind)?;
                let response = self
                    .raft
                    .append_entries(request)
                    .await
                    .map_err(|_| RpcTransportError::Unavailable)?;
                encode_raft_rpc("append_entries_response", &response)
            }
            "install_snapshot" => {
                let request: InstallSnapshotRequest<BearustRaftConfig> =
                    decode_raft_rpc(payload, kind)?;
                if request.data.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
                    return Err(RpcTransportError::PayloadTooLarge);
                }
                let response = self
                    .raft
                    .install_snapshot(request)
                    .await
                    .map_err(|_| RpcTransportError::Unavailable)?;
                encode_raft_rpc("install_snapshot_response", &response)
            }
            _ => Err(RpcTransportError::Malformed),
        }
    }
}

/// Send one authenticated framed request and receive one authenticated framed
/// response. The operation is bounded by `timeout_duration` and the response
/// length is checked before allocation/read, preventing oversized allocations.
pub async fn send_authenticated_rpc(
    endpoint: &str,
    payload: &[u8],
    secret: &[u8],
    timeout_duration: Duration,
) -> Result<Vec<u8>, RpcTransportError> {
    let operation = async {
        let frame =
            crate::cluster_raft::encode_rpc_frame(payload, secret).map_err(
                |error| match error {
                    crate::cluster_raft::CommandError::PayloadTooLarge => {
                        RpcTransportError::PayloadTooLarge
                    }
                    crate::cluster_raft::CommandError::AuthenticationFailed => {
                        RpcTransportError::AuthenticationFailed
                    }
                    _ => RpcTransportError::Malformed,
                },
            )?;
        let mut stream = TcpStream::connect(endpoint)
            .await
            .map_err(|_| RpcTransportError::Unavailable)?;
        stream
            .write_all(&frame)
            .await
            .map_err(|_| RpcTransportError::Unavailable)?;
        let mut header = [0u8; RPC_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| RpcTransportError::Malformed)?;
        let declared = u32::from_be_bytes(header[RPC_MAGIC_LEN..].try_into().unwrap()) as usize;
        if declared > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
            return Err(RpcTransportError::PayloadTooLarge);
        }
        let mut rest = vec![0u8; declared + RPC_TAG_LEN];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(|_| RpcTransportError::Malformed)?;
        let mut response = Vec::with_capacity(RPC_HEADER_LEN + rest.len());
        response.extend_from_slice(&header);
        response.extend_from_slice(&rest);
        crate::cluster_raft::decode_rpc_frame(&response, secret)
            .map(|value| value.to_vec())
            .map_err(|error| match error {
                crate::cluster_raft::CommandError::AuthenticationFailed => {
                    RpcTransportError::AuthenticationFailed
                }
                crate::cluster_raft::CommandError::PayloadTooLarge => {
                    RpcTransportError::PayloadTooLarge
                }
                _ => RpcTransportError::Malformed,
            })
    };
    timeout(timeout_duration, operation)
        .await
        .map_err(|_| RpcTransportError::Timeout)?
}

/// Validate and classify one authenticated control-plane frame.  Until the
/// OpenRaft instance is attached, recognized RPC kinds return an explicit
/// protocol response instead of pretending to have handled the request.
pub fn dispatch_authenticated_rpc(
    frame: &[u8],
    secret: &[u8],
    node_id: &str,
) -> Result<Vec<u8>, RpcTransportError> {
    let payload =
        crate::cluster_raft::decode_rpc_frame(frame, secret).map_err(|error| match error {
            crate::cluster_raft::CommandError::AuthenticationFailed => {
                RpcTransportError::AuthenticationFailed
            }
            crate::cluster_raft::CommandError::PayloadTooLarge => {
                RpcTransportError::PayloadTooLarge
            }
            _ => RpcTransportError::Malformed,
        })?;
    let value: Value = serde_json::from_slice(payload).map_err(|_| RpcTransportError::Malformed)?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(RpcTransportError::Malformed)?;
    let body = match kind {
        "status" => {
            serde_json::json!({"kind":"status", "node_id":node_id, "status":"transport_ready"})
        }
        "vote" | "append_entries" | "install_snapshot" => serde_json::json!({
            "kind":"error", "code":"raft_handler_unavailable"
        }),
        _ => serde_json::json!({"kind":"error", "code":"unknown_rpc_kind"}),
    };
    let body = serde_json::to_vec(&body).map_err(|_| RpcTransportError::Malformed)?;
    crate::cluster_raft::encode_rpc_frame(&body, secret).map_err(|error| match error {
        crate::cluster_raft::CommandError::AuthenticationFailed => {
            RpcTransportError::AuthenticationFailed
        }
        crate::cluster_raft::CommandError::PayloadTooLarge => RpcTransportError::PayloadTooLarge,
        _ => RpcTransportError::Malformed,
    })
}

/// The complete set of adapters required by `openraft::Raft::new`.
pub trait RaftRuntimeAdapters:
    openraft::storage::RaftLogStorage<BearustRaftConfig>
    + openraft::storage::RaftStateMachine<BearustRaftConfig>
    + openraft::RaftNetworkFactory<BearustRaftConfig>
{
}

/// Construct an OpenRaft instance with the durable SQLx log/state-machine
/// adapters and authenticated network factory. The caller owns the returned
/// handle and must explicitly bootstrap/join it; construction alone does not
/// claim quorum or leadership.
pub async fn build_raft(
    id: u64,
    storage: SqlxRaftStorage,
    secret: impl AsRef<[u8]>,
) -> Result<openraft::Raft<BearustRaftConfig>, openraft::error::Fatal<u64>> {
    let network =
        AuthenticatedRaftNetworkFactory::new(secret).ok_or(openraft::error::Fatal::Panicked)?;
    let config = Arc::new(openraft::Config::default());
    openraft::Raft::new(id, config, network, storage.clone(), storage).await
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("single-node bootstrap requires exactly one member")]
    NotSingleNode,
    #[error("multi-node membership must contain at least three members")]
    InvalidMultiNodeMembership,
    #[error("local node is not present in membership")]
    LocalNodeMissing,
}

/// Explicitly bootstrap a pristine single-node instance. This is opt-in and
/// never called by `build_raft`; successful initialization starts election.
pub async fn bootstrap_single_node(
    raft: &openraft::Raft<BearustRaftConfig>,
    local_id: u64,
    local_addr: impl Into<String>,
) -> Result<(), BootstrapError> {
    let local_addr: String = local_addr.into();
    raft.initialize(BTreeMap::from([(
        local_id,
        openraft::BasicNode::new(local_addr),
    )]))
    .await
    .map_err(|_| BootstrapError::NotSingleNode)
}

/// Validate a multi-node join request without mutating Raft membership. The
/// caller must perform leader-mediated `add_learner`/`change_membership` only
/// after this guard succeeds.
pub fn validate_multi_node_join(
    local_id: u64,
    members: &BTreeMap<u64, openraft::BasicNode>,
) -> Result<(), BootstrapError> {
    if members.len() < 3 {
        return Err(BootstrapError::InvalidMultiNodeMembership);
    }
    if !members.contains_key(&local_id) {
        return Err(BootstrapError::LocalNodeMissing);
    }
    Ok(())
}

impl<T> RaftRuntimeAdapters for T where
    T: openraft::storage::RaftLogStorage<BearustRaftConfig>
        + openraft::storage::RaftStateMachine<BearustRaftConfig>
        + openraft::RaftNetworkFactory<BearustRaftConfig>
{
}

/// Network factory for the authenticated cluster transport.
///
/// The wire framing/authentication is implemented by `encode_rpc_frame` and
/// `decode_rpc_frame`.  Actual TCP request/response dispatch is deliberately
/// not implemented yet; each RPC returns `Unreachable` so OpenRaft cannot
/// interpret a transport stub as a successful replication.
#[derive(Clone, Debug)]
pub struct AuthenticatedRaftNetworkFactory {
    secret: Vec<u8>,
}

impl AuthenticatedRaftNetworkFactory {
    pub fn new(secret: impl AsRef<[u8]>) -> Option<Self> {
        let secret = secret.as_ref().to_vec();
        (!secret.is_empty()).then_some(Self { secret })
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedRaftNetwork {
    _target: u64,
    endpoint: String,
    secret: Vec<u8>,
}

impl RaftNetworkFactory<BearustRaftConfig> for AuthenticatedRaftNetworkFactory {
    type Network = AuthenticatedRaftNetwork;

    async fn new_client(&mut self, target: u64, node: &openraft::BasicNode) -> Self::Network {
        AuthenticatedRaftNetwork {
            _target: target,
            endpoint: node.addr.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl RaftNetwork<BearustRaftConfig> for AuthenticatedRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<BearustRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        let payload = encode_raft_rpc("append_entries", &rpc).map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC encode failed",
            )))
        })?;
        let response = send_authenticated_rpc(
            &self.endpoint,
            &payload,
            &self.secret,
            Duration::from_secs(2),
        )
        .await
        .map_err(|_| {
            RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "raft RPC unavailable",
            )))
        })?;
        decode_raft_rpc(&response, "append_entries_response").map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC response malformed",
            )))
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<BearustRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, openraft::BasicNode, RaftError<u64, openraft::error::InstallSnapshotError>>,
    > {
        if rpc.data.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
            return Err(RPCError::Network(openraft::error::NetworkError::new(
                &io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raft snapshot chunk exceeds transport limit",
                ),
            )));
        }
        let payload = encode_raft_rpc("install_snapshot", &rpc).map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC encode failed",
            )))
        })?;
        let response = send_authenticated_rpc(
            &self.endpoint,
            &payload,
            &self.secret,
            Duration::from_secs(2),
        )
        .await
        .map_err(|_| {
            RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "raft RPC unavailable",
            )))
        })?;
        decode_raft_rpc(&response, "install_snapshot_response").map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC response malformed",
            )))
        })
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
        let payload = encode_raft_rpc("vote", &rpc).map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC encode failed",
            )))
        })?;
        let response = send_authenticated_rpc(
            &self.endpoint,
            &payload,
            &self.secret,
            Duration::from_secs(2),
        )
        .await
        .map_err(|_| {
            RPCError::Unreachable(Unreachable::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "raft RPC unavailable",
            )))
        })?;
        decode_raft_rpc(&response, "vote_response").map_err(|_| {
            RPCError::Network(openraft::error::NetworkError::new(&io::Error::new(
                io::ErrorKind::InvalidData,
                "raft RPC response malformed",
            )))
        })
    }
}

/// Compile-only signature mirroring the OpenRaft construction boundary.
///
/// Keeping this function generic means it performs no I/O and cannot be used
/// to claim that election or persistence is active.  Once the SQLx adapters
/// land, calling `openraft::Raft::new` from the lifecycle code can use this
/// exact bound without changing the public command/state-machine types.
pub fn assert_runtime_adapters<T: RaftRuntimeAdapters>() {}

/// Construct an OpenRaft instance with the durable SQLx adapters and
/// authenticated network factory. Calling this starts OpenRaft's runtime;
/// lifecycle code must therefore invoke it only after transport/listener
/// readiness and retain the returned handle for shutdown.
pub async fn construct_raft(
    pool: DbPool,
    node_name: impl Into<String>,
    auth_secret: impl AsRef<[u8]>,
) -> Result<openraft::Raft<BearustRaftConfig>, String> {
    let storage = SqlxRaftStorage::new(pool, node_name).map_err(|e| e.to_string())?;
    let node_id = storage.raft_id().await.map_err(|e| e.to_string())?;
    let network = AuthenticatedRaftNetworkFactory::new(auth_secret)
        .ok_or_else(|| "raft auth secret must not be empty".to_string())?;
    let config = openraft::Config::build(&["bearust"]).map_err(|e| e.to_string())?;
    openraft::Raft::new(node_id, Arc::new(config), network, storage.clone(), storage)
        .await
        .map_err(|e| e.to_string())
}

/// Compute a cluster-wide stable numeric identity from the configured
/// membership. Every node must use the same sorted membership list.
pub fn deterministic_raft_id(local: &str, peers: &[String]) -> Result<u64, String> {
    let mut members = peers.to_vec();
    members.push(local.to_owned());
    members.sort();
    members.dedup();
    let position = members
        .iter()
        .position(|member| member == local)
        .ok_or_else(|| "local node is absent from cluster membership".to_string())?;
    u64::try_from(position + 1).map_err(|_| "cluster membership exceeds raft id range".into())
}

pub async fn construct_raft_with_id(
    pool: DbPool,
    node_name: impl Into<String>,
    auth_secret: impl AsRef<[u8]>,
    raft_id: u64,
) -> Result<openraft::Raft<BearustRaftConfig>, String> {
    if raft_id == 0 {
        return Err("raft id must be positive".into());
    }
    let storage = SqlxRaftStorage::new(pool, node_name).map_err(|e| e.to_string())?;
    let network = AuthenticatedRaftNetworkFactory::new(auth_secret)
        .ok_or_else(|| "raft auth secret must not be empty".to_string())?;
    let config = openraft::Config::build(&["bearust"]).map_err(|e| e.to_string())?;
    openraft::Raft::new(raft_id, Arc::new(config), network, storage.clone(), storage)
        .await
        .map_err(|e| e.to_string())
}
