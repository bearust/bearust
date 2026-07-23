//! Compile-time contract for the OpenRaft runtime integration.
//!
//! This module intentionally does not provide placeholder storage or network
//! implementations.  OpenRaft 0.9's `storage-v2` API requires durable log,
//! vote, commit, state-machine, snapshot, and all RPC transport operations;
//! silently returning defaults here would make a node appear healthy while
//! losing committed data.  The contract below keeps the dependency/API
//! integration checked while the SQLx-backed adapters are implemented.

use crate::cluster_raft::BearustRaftConfig;

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

/// Compile-only signature mirroring the OpenRaft construction boundary.
///
/// Keeping this function generic means it performs no I/O and cannot be used
/// to claim that election or persistence is active.  Once the SQLx adapters
/// land, calling `openraft::Raft::new` from the lifecycle code can use this
/// exact bound without changing the public command/state-machine types.
pub fn assert_runtime_adapters<T: RaftRuntimeAdapters>() {}
