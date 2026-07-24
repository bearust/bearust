//! Typed boundary for replicated configuration writes.
//!
//! API handlers validate authorization before constructing a command. This
//! gateway then ensures a command is offered to OpenRaft only by a local
//! leader with quorum; it never calls repository mutation helpers directly.

use crate::cluster::ClusterService;
use crate::cluster_raft::{BearustRaftConfig, ConfigCommand};
use openraft::error::{ClientWriteError, RaftError};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_QUORUM_ACK_AGE_MILLIS: u64 = 1_000;

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
    /// `Raft::client_write` exceeded its local deadline after the command was
    /// submitted. The command may still commit; retry the same `command_id`.
    #[error("raft command commit outcome is unknown; retry the same command_id")]
    CommitOutcomeUnknown,
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
    ///
    /// A [`ClusterWriteError::CommitOutcomeUnknown`] result means the local
    /// `client_write` wait timed out after submission. The command may commit
    /// later, so callers must retry the same command with its original
    /// `command_id`.
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

        self.require_live_write_quorum()?;

        let command_id = command.command_id();
        let response = tokio::time::timeout(CLIENT_WRITE_TIMEOUT, self.raft.client_write(command))
            .await
            .map_err(|_| map_client_write_timeout())?
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

    fn require_live_write_quorum(&self) -> Result<(), ClusterWriteError> {
        let metrics = self.raft.metrics();
        let metrics = metrics.borrow();
        if !metrics.state.is_leader() || metrics.current_leader != Some(metrics.id) {
            return Err(ClusterWriteError::LeaderUnknown);
        }

        let single_voter_membership =
            metrics.membership_config.membership().voter_ids().count() == 1;
        if self.cluster.is_single_node() && single_voter_membership {
            return Ok(());
        }

        match metrics.millis_since_quorum_ack {
            Some(age) if age <= MAX_QUORUM_ACK_AGE_MILLIS => Ok(()),
            _ => Err(ClusterWriteError::QuorumUnavailable),
        }
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

fn map_client_write_timeout() -> ClusterWriteError {
    ClusterWriteError::CommitOutcomeUnknown
}

#[cfg(test)]
mod tests {
    use super::{map_client_write_timeout, ClusterWriteError};

    #[test]
    fn client_write_timeout_reports_unknown_commit_outcome() {
        assert_eq!(
            map_client_write_timeout(),
            ClusterWriteError::CommitOutcomeUnknown
        );
    }
}
