//! Compile-time contract for the OpenRaft runtime integration.
//!
//! This module intentionally does not provide placeholder storage or network
//! implementations.  OpenRaft 0.9's `storage-v2` API requires durable log,
//! vote, commit, state-machine, snapshot, and all RPC transport operations;
//! silently returning defaults here would make a node appear healthy while
//! losing committed data.  The contract below keeps the dependency/API
//! integration checked while the SQLx-backed adapters are implemented.

use crate::cluster_raft::BearustRaftConfig;
use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use std::io;

/// The complete set of adapters required by `openraft::Raft::new`.
pub trait RaftRuntimeAdapters:
    openraft::storage::RaftLogStorage<BearustRaftConfig>
    + openraft::storage::RaftStateMachine<BearustRaftConfig>
    + openraft::RaftNetworkFactory<BearustRaftConfig>
{
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
    target: u64,
    endpoint: String,
    secret: Vec<u8>,
}

#[allow(clippy::result_large_err)]
fn unavailable<T>() -> Result<T, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
    let error = io::Error::new(io::ErrorKind::NotConnected, "raft transport not started");
    Err(RPCError::Unreachable(Unreachable::new(&error)))
}

impl RaftNetworkFactory<BearustRaftConfig> for AuthenticatedRaftNetworkFactory {
    type Network = AuthenticatedRaftNetwork;

    async fn new_client(&mut self, target: u64, node: &openraft::BasicNode) -> Self::Network {
        AuthenticatedRaftNetwork {
            target,
            endpoint: node.addr.clone(),
            secret: self.secret.clone(),
        }
    }
}

impl RaftNetwork<BearustRaftConfig> for AuthenticatedRaftNetwork {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<BearustRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        let _ = (&self.target, &self.endpoint, &self.secret);
        unavailable()
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<BearustRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, openraft::BasicNode, RaftError<u64, openraft::error::InstallSnapshotError>>,
    > {
        let _ = (&self.target, &self.endpoint, &self.secret);
        let error = io::Error::new(io::ErrorKind::NotConnected, "raft transport not started");
        Err(RPCError::Unreachable(Unreachable::new(&error)))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
        let _ = (&self.target, &self.endpoint, &self.secret);
        unavailable()
    }
}

/// Compile-only signature mirroring the OpenRaft construction boundary.
///
/// Keeping this function generic means it performs no I/O and cannot be used
/// to claim that election or persistence is active.  Once the SQLx adapters
/// land, calling `openraft::Raft::new` from the lifecycle code can use this
/// exact bound without changing the public command/state-machine types.
pub fn assert_runtime_adapters<T: RaftRuntimeAdapters>() {}
