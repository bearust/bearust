//! Typed boundary for replicated configuration writes.
//!
//! API handlers validate authorization before constructing a command. This
//! gateway then ensures a command is offered to OpenRaft only by a local
//! leader with quorum; it never calls repository mutation helpers directly.

use crate::cluster::ClusterService;
use crate::cluster_raft::{BearustRaftConfig, ConfigCommand};
use crate::cluster_raft_runtime::{
    decode_raft_rpc, encode_raft_rpc, send_authenticated_rpc_with_identity, InternalCommandHandler,
    RpcTransportError,
};
use async_trait::async_trait;
use openraft::error::{ClientWriteError, RaftError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const LEADER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const LEADER_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_QUORUM_ACK_AGE_MILLIS: u64 = 1_000;
const FORWARDED_COMMAND_PROTOCOL_VERSION: u8 = 1;
const MAX_ACTOR_EMAIL_BYTES: usize = 320;
const MAX_NODE_ID_BYTES: usize = 255;
const MAX_CACHED_RECEIPTS: usize = 1_024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandActor {
    pub user_id: i64,
    pub email: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForwardedCommandEnvelope {
    protocol_version: u8,
    origin_node_id: String,
    command_id: Uuid,
    command: ConfigCommand,
    actor: CommandActor,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
enum ForwardedCommandResponse {
    Receipt { receipt: CommitReceipt },
    Error { code: String },
}

/// Encode the internal command body before it is placed in the authenticated
/// RPC frame. The HMAC frame authenticates this body in transit; this helper
/// validates its self-consistency so accidental or malicious field swapping
/// is rejected at the receiver as well.
pub fn encode_forwarded_command(
    origin_node_id: &str,
    command: ConfigCommand,
    actor: CommandActor,
) -> Result<serde_json::Value, ClusterWriteError> {
    validate_command_and_actor(&command, &actor)?;
    if origin_node_id.is_empty() || origin_node_id.len() > MAX_NODE_ID_BYTES {
        return Err(ClusterWriteError::ForwardAuthentication);
    }
    let envelope = ForwardedCommandEnvelope {
        protocol_version: FORWARDED_COMMAND_PROTOCOL_VERSION,
        origin_node_id: origin_node_id.to_string(),
        command_id: command.command_id(),
        command,
        actor,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_| ClusterWriteError::InvalidCommand)?;
    if encoded.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
        return Err(ClusterWriteError::InvalidCommand);
    }
    serde_json::to_value(envelope).map_err(|_| ClusterWriteError::InvalidCommand)
}

/// Decode and revalidate an untrusted internal command body. Transport
/// authentication is performed by the caller before this function is used.
pub fn decode_forwarded_command(
    payload: &serde_json::Value,
) -> Result<(String, ConfigCommand, CommandActor), ClusterWriteError> {
    let encoded =
        serde_json::to_vec(payload).map_err(|_| ClusterWriteError::ForwardAuthentication)?;
    if encoded.len() > crate::cluster_raft::MAX_RPC_FRAME_BYTES {
        return Err(ClusterWriteError::InvalidCommand);
    }
    let envelope: ForwardedCommandEnvelope = serde_json::from_value(payload.clone())
        .map_err(|_| ClusterWriteError::ForwardAuthentication)?;
    if envelope.protocol_version != FORWARDED_COMMAND_PROTOCOL_VERSION
        || envelope.origin_node_id.is_empty()
        || envelope.origin_node_id.len() > MAX_NODE_ID_BYTES
        || envelope.command_id != envelope.command.command_id()
    {
        return Err(ClusterWriteError::ForwardAuthentication);
    }
    validate_command_and_actor(&envelope.command, &envelope.actor)?;
    Ok((envelope.origin_node_id, envelope.command, envelope.actor))
}

fn validate_command_and_actor(
    command: &ConfigCommand,
    actor: &CommandActor,
) -> Result<(), ClusterWriteError> {
    command
        .validate()
        .map_err(|_| ClusterWriteError::InvalidCommand)?;
    if matches!(command, ConfigCommand::Noop { .. }) {
        return Err(ClusterWriteError::NotReplicatedCommand);
    }
    if actor.user_id <= 0
        || actor.email.is_empty()
        || actor.email.len() > MAX_ACTOR_EMAIL_BYTES
        || actor.role != "admin"
    {
        return Err(ClusterWriteError::ForwardAuthentication);
    }
    Ok(())
}

impl ClusterWriteError {
    fn code(&self) -> &'static str {
        match self {
            Self::LeaderUnknown => "leader_unknown",
            Self::QuorumUnavailable => "quorum_unavailable",
            Self::CommitOutcomeUnknown => "commit_outcome_unknown",
            Self::ForwardTimeout => "forward_timeout",
            Self::ForwardAuthentication => "forward_authentication",
            Self::InvalidCommand => "invalid_command",
            Self::NotReplicatedCommand => "not_replicated_command",
        }
    }

    fn from_code(code: &str) -> Self {
        match code {
            "leader_unknown" => Self::LeaderUnknown,
            "quorum_unavailable" => Self::QuorumUnavailable,
            "commit_outcome_unknown" => Self::CommitOutcomeUnknown,
            "forward_timeout" => Self::ForwardTimeout,
            "forward_authentication" => Self::ForwardAuthentication,
            "invalid_command" => Self::InvalidCommand,
            "not_replicated_command" => Self::NotReplicatedCommand,
            _ => Self::ForwardAuthentication,
        }
    }
}

#[derive(Clone)]
pub struct ConfigCommandGateway {
    raft: Arc<openraft::Raft<BearustRaftConfig>>,
    cluster: Arc<ClusterService>,
    receipts: Arc<Mutex<std::collections::BTreeMap<Uuid, CommitReceipt>>>,
}

impl ConfigCommandGateway {
    pub fn new(raft: Arc<openraft::Raft<BearustRaftConfig>>, cluster: Arc<ClusterService>) -> Self {
        Self {
            raft,
            cluster,
            receipts: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    /// Submit one already-authorized configuration command for Raft commit.
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
        validate_command_and_actor(&command, &actor)?;

        let metrics = self.raft.metrics();
        let metrics = metrics.borrow();
        let is_local_leader =
            metrics.state.is_leader() && metrics.current_leader == Some(metrics.id);
        drop(metrics);

        if !is_local_leader {
            return self
                .forward_to_leader(self.wait_for_leader_endpoint().await?, command, actor)
                .await;
        }

        self.submit_local(command).await
    }

    async fn wait_for_leader_endpoint(&self) -> Result<String, ClusterWriteError> {
        let status_request = encode_raft_rpc("status", &serde_json::json!({}))
            .map_err(|_| ClusterWriteError::LeaderUnknown)?;
        let secret = self.cluster.rpc_secret();
        tokio::time::timeout(CLIENT_WRITE_TIMEOUT, async {
            loop {
                let metrics = self.raft.metrics();
                let metrics = metrics.borrow();
                let endpoint = metrics.current_leader.and_then(|leader_id| {
                    metrics
                        .membership_config
                        .membership()
                        .get_node(&leader_id)
                        .map(|node| node.addr.clone())
                });
                drop(metrics);
                if let Some(endpoint) = endpoint {
                    return endpoint;
                }

                for peer in self.cluster.peers() {
                    let response = send_authenticated_rpc_with_identity(
                        &peer.address.to_string(),
                        self.cluster.node_id(),
                        &status_request,
                        &secret,
                        LEADER_PROBE_TIMEOUT,
                    )
                    .await;
                    let Ok(response) = response else {
                        continue;
                    };
                    let Ok(status) = decode_raft_rpc::<serde_json::Value>(&response, "status")
                    else {
                        continue;
                    };
                    if status["node_id"] == peer.node_id && status["is_leader"] == true {
                        return peer.address.to_string();
                    }
                }
                tokio::time::sleep(LEADER_POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| ClusterWriteError::LeaderUnknown)
    }

    async fn submit_local(
        &self,
        command: ConfigCommand,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        let command_id = command.command_id();
        let mut receipts = self.receipts.lock().await;
        if let Some(receipt) = receipts.get(&command_id) {
            return Ok(receipt.clone());
        }

        self.require_live_write_quorum()?;
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

        let receipt = CommitReceipt {
            command_id,
            leader_id,
            commit_index: response.log_id.index,
        };
        if receipts.len() >= MAX_CACHED_RECEIPTS {
            let oldest = *receipts.keys().next().expect("non-empty receipt cache");
            receipts.remove(&oldest);
        }
        receipts.insert(command_id, receipt.clone());
        Ok(receipt)
    }

    async fn forward_to_leader(
        &self,
        endpoint: String,
        command: ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        let envelope = encode_forwarded_command(self.cluster.node_id(), command, actor)?;
        let payload = encode_raft_rpc("config_command", &envelope)
            .map_err(|_| ClusterWriteError::InvalidCommand)?;
        let secret = self.cluster.rpc_secret();
        let response = send_authenticated_rpc_with_identity(
            &endpoint,
            self.cluster.node_id(),
            &payload,
            &secret,
            CLIENT_WRITE_TIMEOUT,
        )
        .await
        .map_err(map_forward_transport_error)?;
        let response: ForwardedCommandResponse =
            decode_raft_rpc(&response, "config_command_response")
                .map_err(|_| ClusterWriteError::ForwardAuthentication)?;
        match response {
            ForwardedCommandResponse::Receipt { receipt } => Ok(receipt),
            ForwardedCommandResponse::Error { code } => Err(ClusterWriteError::from_code(&code)),
        }
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

#[async_trait]
impl InternalCommandHandler for ConfigCommandGateway {
    async fn handle_config_command(
        &self,
        payload: &[u8],
        authenticated_node_id: &str,
    ) -> Result<Vec<u8>, RpcTransportError> {
        let envelope: serde_json::Value = decode_raft_rpc(payload, "config_command")?;
        let response = match decode_forwarded_command(&envelope) {
            Ok((origin, command, _actor)) if origin == authenticated_node_id => {
                match self.submit_local(command).await {
                    Ok(receipt) => ForwardedCommandResponse::Receipt { receipt },
                    Err(error) => ForwardedCommandResponse::Error {
                        code: error.code().to_string(),
                    },
                }
            }
            Ok(_) => ForwardedCommandResponse::Error {
                code: ClusterWriteError::ForwardAuthentication.code().to_string(),
            },
            Err(error) => ForwardedCommandResponse::Error {
                code: error.code().to_string(),
            },
        };
        encode_raft_rpc("config_command_response", &response)
    }
}

fn map_forward_transport_error(error: RpcTransportError) -> ClusterWriteError {
    match error {
        RpcTransportError::Timeout => ClusterWriteError::ForwardTimeout,
        RpcTransportError::AuthenticationFailed => ClusterWriteError::ForwardAuthentication,
        RpcTransportError::PayloadTooLarge => ClusterWriteError::InvalidCommand,
        RpcTransportError::Unavailable | RpcTransportError::Malformed => {
            ClusterWriteError::LeaderUnknown
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
