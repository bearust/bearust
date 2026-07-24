//! Typed boundary for replicated configuration writes.
//!
//! API handlers validate authorization before constructing a command. This
//! gateway then ensures a command is offered to OpenRaft only by a local
//! leader with quorum; it never calls repository mutation helpers directly.

use crate::cluster::{ClusterService, RaftRole};
use crate::cluster_raft::{BearustRaftConfig, ConfigCommand};
use openraft::error::{ClientWriteError, RaftError};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandActor {
    pub user_id: i64,
    pub email: String,
    pub role: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub command_id: Uuid,
    pub leader_id: u64,
    pub commit_index: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClusterWriteError {
    #[error("raft leader is unknown")]
    LeaderUnknown,
    #[error("raft quorum is unavailable")]
    QuorumUnavailable,
    #[error("forwarded raft command timed out")]
    ForwardTimeout,
    #[error("forwarded raft command authentication failed")]
    ForwardAuthentication,
    #[error("configuration command is invalid")]
    InvalidCommand,
    #[error("command is not accepted by the replicated configuration gateway")]
    NotReplicatedCommand,
}

pub struct ConfigCommandGateway {
    raft: Arc<openraft::Raft<BearustRaftConfig>>,
    cluster: Arc<ClusterService>,
}

impl ConfigCommandGateway {
    pub fn new(raft: Arc<openraft::Raft<BearustRaftConfig>>, cluster: Arc<ClusterService>) -> Self {
        Self { raft, cluster }
    }

    /// Submit one already-authorized configuration command for Raft commit.
    ///
    /// Multi-node followers intentionally stop at the leader boundary here;
    /// authenticated forwarding is added by the next lifecycle task.
    pub async fn submit(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        let _ = actor;
        command
            .validate()
            .map_err(|_| ClusterWriteError::InvalidCommand)?;
        if matches!(command, ConfigCommand::Noop { .. }) {
            return Err(ClusterWriteError::NotReplicatedCommand);
        }

        let write_state = self.cluster.raft_write_state();
        match write_state.role {
            RaftRole::Standalone => {}
            RaftRole::Leader => {
                if !write_state.quorum_available {
                    return Err(ClusterWriteError::QuorumUnavailable);
                }
            }
            RaftRole::Follower | RaftRole::Candidate | RaftRole::Unknown => {
                return Err(ClusterWriteError::LeaderUnknown);
            }
        }

        let command_id = command.command_id();
        let response = self
            .raft
            .client_write(command)
            .await
            .map_err(map_client_write_error)?;
        let leader_id = self
            .raft
            .metrics()
            .borrow()
            .current_leader
            .ok_or(ClusterWriteError::LeaderUnknown)?;

        Ok(CommitReceipt {
            command_id,
            leader_id,
            commit_index: response.log_id.index,
        })
    }
}

fn map_client_write_error(
    error: RaftError<u64, ClientWriteError<u64, openraft::BasicNode>>,
) -> ClusterWriteError {
    match error {
        RaftError::APIError(ClientWriteError::ForwardToLeader(_)) => {
            ClusterWriteError::LeaderUnknown
        }
        RaftError::APIError(ClientWriteError::ChangeMembershipError(_)) | RaftError::Fatal(_) => {
            ClusterWriteError::QuorumUnavailable
        }
    }
}
