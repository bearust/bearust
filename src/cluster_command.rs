//! Typed boundary for replicated configuration writes.
//!
//! API handlers validate authorization before constructing a command. This
//! gateway then ensures a command is offered to OpenRaft only by a local
//! leader with quorum; it never calls repository mutation helpers directly.

use crate::cluster::ClusterService;
use crate::cluster_raft::{BearustRaftConfig, CommandResult, ConfigCommand};
use crate::cluster_raft_runtime::{
    decode_raft_rpc, encode_raft_rpc, send_authenticated_rpc_with_identity, InternalCommandHandler,
    RpcTransportError,
};
use crate::control_plane::rbac::Permission;
use crate::control_plane::repository::{self, DbPool};
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
const MAX_ACTOR_ROLE_BYTES: usize = 64;
const MAX_NODE_ID_BYTES: usize = 255;
const MAX_CACHED_RECEIPTS: usize = 1_024;
const SYSTEM_ACTOR_EMAIL: &str = "system";
const SYSTEM_ACTOR_ROLE: &str = "system";

/// Return the existing public invalidation kind for a committed replicated
/// command. Internal log markers never invalidate a control-plane view.
pub fn committed_event_kind(command: &ConfigCommand) -> Option<&'static str> {
    match command {
        ConfigCommand::CreateProxyHost { .. }
        | ConfigCommand::UpdateProxyHost { .. }
        | ConfigCommand::DeleteProxyHost { .. } => Some("proxy_hosts.changed"),
        ConfigCommand::UpdateRuntimePolicy { .. } => Some("rate_limit.changed"),
        ConfigCommand::Noop { .. } => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandActor {
    pub user_id: i64,
    pub email: String,
    pub role: String,
}

impl CommandActor {
    pub fn system() -> Self {
        Self {
            user_id: 0,
            email: SYSTEM_ACTOR_EMAIL.into(),
            role: SYSTEM_ACTOR_ROLE.into(),
        }
    }

    fn is_system(&self) -> bool {
        self.user_id == 0 && self.email == SYSTEM_ACTOR_EMAIL && self.role == SYSTEM_ACTOR_ROLE
    }
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
    #[error("cluster configuration gateway is unavailable")]
    ClusterUnavailable,
    /// `Raft::client_write` exceeded its local deadline after the command was
    /// submitted. The command may still commit; retry the same `command_id`.
    #[error("raft command commit outcome is unknown; retry the same command_id")]
    CommitOutcomeUnknown,
    #[error("forwarded raft command timed out")]
    ForwardTimeout,
    #[error("configuration command committed but local application is pending")]
    LocalApplyPending { receipt: CommitReceipt },
    #[error("forwarded raft command authentication failed")]
    ForwardAuthentication,
    #[error("configuration command is invalid")]
    InvalidCommand,
    #[error("command is not accepted by the replicated configuration gateway")]
    NotReplicatedCommand,
    #[error("proxy host domain already exists")]
    DuplicateDomain,
    #[error("proxy host identifier already exists")]
    IdCollision,
    #[error("proxy host does not exist")]
    NotFound,
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
    if actor.is_system() {
        return if matches!(command, ConfigCommand::UpdateRuntimePolicy { .. }) {
            Ok(())
        } else {
            Err(ClusterWriteError::ForwardAuthentication)
        };
    }
    if actor.user_id <= 0
        || actor.email.is_empty()
        || actor.email.len() > MAX_ACTOR_EMAIL_BYTES
        || actor.role.is_empty()
        || actor.role.len() > MAX_ACTOR_ROLE_BYTES
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
            Self::ClusterUnavailable => "cluster_unavailable",
            Self::CommitOutcomeUnknown => "commit_outcome_unknown",
            Self::ForwardTimeout => "forward_timeout",
            Self::LocalApplyPending { .. } => "local_apply_pending",
            Self::ForwardAuthentication => "forward_authentication",
            Self::InvalidCommand => "invalid_command",
            Self::NotReplicatedCommand => "not_replicated_command",
            Self::DuplicateDomain => "duplicate_domain",
            Self::IdCollision => "id_collision",
            Self::NotFound => "not_found",
        }
    }

    fn from_code(code: &str) -> Self {
        match code {
            "leader_unknown" => Self::LeaderUnknown,
            "quorum_unavailable" => Self::QuorumUnavailable,
            "cluster_unavailable" => Self::ClusterUnavailable,
            "commit_outcome_unknown" => Self::CommitOutcomeUnknown,
            "forward_timeout" => Self::ForwardTimeout,
            // A pending result is produced only by the receiving follower
            // after it has decoded a concrete receipt.
            "local_apply_pending" => Self::ForwardAuthentication,
            "forward_authentication" => Self::ForwardAuthentication,
            "invalid_command" => Self::InvalidCommand,
            "not_replicated_command" => Self::NotReplicatedCommand,
            "duplicate_domain" => Self::DuplicateDomain,
            "id_collision" => Self::IdCollision,
            "not_found" => Self::NotFound,
            _ => Self::ForwardAuthentication,
        }
    }
}

#[derive(Clone)]
pub struct ConfigCommandGateway {
    raft: Arc<openraft::Raft<BearustRaftConfig>>,
    cluster: Arc<ClusterService>,
    db: DbPool,
    receipts: Arc<Mutex<std::collections::BTreeMap<Uuid, CommittedCommandOutcome>>>,
    submission_gate: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedCommandOutcome {
    receipt: CommitReceipt,
    result: CommandResult,
}

impl ConfigCommandGateway {
    pub fn new(
        raft: Arc<openraft::Raft<BearustRaftConfig>>,
        cluster: Arc<ClusterService>,
        db: DbPool,
    ) -> Self {
        Self {
            raft,
            cluster,
            db,
            receipts: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            submission_gate: Arc::new(Mutex::new(())),
        }
    }

    /// Whether OpenRaft has an explicit voter membership. An auth token alone
    /// starts the transport but does not opt a standalone deployment into
    /// replicated writes.
    pub fn has_initialized_membership(&self) -> bool {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .next()
            .is_some()
    }

    /// True only while this local Raft node is the elected leader.
    pub fn is_confirmed_local_leader(&self) -> bool {
        let metrics = self.raft.metrics();
        let metrics = metrics.borrow();
        metrics.state.is_leader() && metrics.current_leader == Some(metrics.id)
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
        let _submission = self.submission_gate.lock().await;
        self.submit_inner(command, actor, false).await
    }

    /// Submit only if this node is still the elected leader. Scheduled
    /// system-actor work uses this path so a deposed scheduler never forwards
    /// its stale decision to a replacement leader.
    pub async fn submit_leader_only(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        let _submission = self.submission_gate.lock().await;
        self.submit_inner(command, actor, true).await
    }

    /// Preserve standalone behavior before explicit membership exists while
    /// keeping the topology decision and mutation inside the gateway. The
    /// shared topology gate prevents membership activation from overlapping
    /// the local transaction; a known local outcome can be durably promoted
    /// by retrying the same command ID through Raft after membership activates.
    pub async fn submit_with_standalone_fallback(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        self.submit_with_standalone_fallback_inner(command, actor, false)
            .await
    }

    /// Standalone-compatible form of [`Self::submit_leader_only`].
    pub async fn submit_leader_only_with_standalone_fallback(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        self.submit_with_standalone_fallback_inner(command, actor, true)
            .await
    }

    async fn submit_with_standalone_fallback_inner(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
        leader_only: bool,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        let _submission = self.submission_gate.lock().await;
        if !self.cluster.is_single_node() {
            return self.submit_inner(command, actor, leader_only).await;
        }
        let topology = self.cluster.lock_standalone_submission().await;
        if self.has_initialized_membership() {
            drop(topology);
            return self.submit_inner(command, actor, leader_only).await;
        }
        validate_command_and_actor(&command, &actor)?;
        self.validate_authoritative_actor(&command, &actor).await?;
        let result = repository::apply_raft_command(&self.db, &command)
            .await
            .map_err(|_| ClusterWriteError::QuorumUnavailable)?;
        command_result(result)?;
        Ok(CommitReceipt {
            command_id: command.command_id(),
            leader_id: 0,
            commit_index: 0,
        })
    }

    async fn submit_inner(
        &self,
        command: ConfigCommand,
        actor: CommandActor,
        leader_only: bool,
    ) -> Result<CommitReceipt, ClusterWriteError> {
        validate_command_and_actor(&command, &actor)?;
        self.validate_authoritative_actor(&command, &actor).await?;

        let is_local_leader = {
            let metrics = self.raft.metrics();
            let metrics = metrics.borrow();
            metrics.state.is_leader() && metrics.current_leader == Some(metrics.id)
        };

        if !is_local_leader {
            if leader_only {
                return Err(ClusterWriteError::LeaderUnknown);
            }
            let receipt = self
                .forward_to_leader(self.wait_for_leader_endpoint().await?, command, actor)
                .await?;
            return match self.wait_for_local_apply(&receipt).await {
                Ok(()) => Ok(receipt),
                Err(_) => Err(ClusterWriteError::LocalApplyPending { receipt }),
            };
        }

        self.submit_local(command).await
    }

    async fn wait_for_local_apply(&self, receipt: &CommitReceipt) -> Result<(), ClusterWriteError> {
        tokio::time::timeout(CLIENT_WRITE_TIMEOUT, async {
            loop {
                let local = repository::load_raft_command_receipt(
                    &self.db,
                    &receipt.command_id.to_string(),
                )
                .await
                .map_err(|_| ClusterWriteError::QuorumUnavailable)?;
                if local.is_some_and(|local| {
                    u64::try_from(local.leader_id) == Ok(receipt.leader_id)
                        && u64::try_from(local.log_index) == Ok(receipt.commit_index)
                }) {
                    return Ok(());
                }
                tokio::time::sleep(LEADER_POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| ClusterWriteError::ForwardTimeout)?
    }

    async fn wait_for_leader_endpoint(&self) -> Result<String, ClusterWriteError> {
        let status_request = encode_raft_rpc("status", &serde_json::json!({}))
            .map_err(|_| ClusterWriteError::LeaderUnknown)?;
        let secret = self.cluster.rpc_secret();
        tokio::time::timeout(CLIENT_WRITE_TIMEOUT, async {
            loop {
                let endpoint = {
                    let metrics = self.raft.metrics();
                    let metrics = metrics.borrow();
                    metrics.current_leader.and_then(|leader_id| {
                        metrics
                            .membership_config
                            .membership()
                            .get_node(&leader_id)
                            .map(|node| node.addr.clone())
                    })
                };
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
        if let Some(outcome) = receipts.get(&command_id) {
            return committed_outcome(outcome.clone());
        }
        if let Some(outcome) = self.load_committed_outcome(command_id).await? {
            cache_receipt(&mut receipts, outcome.clone());
            return committed_outcome(outcome);
        }

        self.require_live_write_quorum()?;
        let response = tokio::time::timeout(CLIENT_WRITE_TIMEOUT, self.raft.client_write(command))
            .await
            .map_err(|_| map_client_write_timeout())?
            .map_err(map_client_write_error)?;
        let outcome =
            resolve_post_write_outcome(&self.db, command_id, response.data, response.log_id)
                .await?;
        cache_receipt(&mut receipts, outcome.clone());
        committed_outcome(outcome)
    }

    async fn load_committed_outcome(
        &self,
        command_id: Uuid,
    ) -> Result<Option<CommittedCommandOutcome>, ClusterWriteError> {
        let receipt = repository::load_raft_command_receipt(&self.db, &command_id.to_string())
            .await
            .map_err(|_| ClusterWriteError::QuorumUnavailable)?;
        receipt
            .map(|receipt| {
                Ok(CommittedCommandOutcome {
                    receipt: CommitReceipt {
                        command_id,
                        leader_id: u64::try_from(receipt.leader_id)
                            .map_err(|_| ClusterWriteError::QuorumUnavailable)?,
                        commit_index: u64::try_from(receipt.log_index)
                            .map_err(|_| ClusterWriteError::QuorumUnavailable)?,
                    },
                    result: CommandResult::from_code(&receipt.result_code)
                        .ok_or(ClusterWriteError::QuorumUnavailable)?,
                })
            })
            .transpose()
    }

    async fn validate_authoritative_actor(
        &self,
        command: &ConfigCommand,
        actor: &CommandActor,
    ) -> Result<(), ClusterWriteError> {
        if actor.is_system() {
            return if matches!(command, ConfigCommand::UpdateRuntimePolicy { .. }) {
                Ok(())
            } else {
                Err(ClusterWriteError::ForwardAuthentication)
            };
        }
        let persisted = repository::find_user(&self.db, &actor.email)
            .await
            .map_err(|_| ClusterWriteError::ForwardAuthentication)?
            .map(|(user, _)| user)
            .ok_or(ClusterWriteError::ForwardAuthentication)?;
        if persisted.id != actor.user_id
            || persisted.email != actor.email
            || persisted.role != actor.role
            || persisted.disabled
        {
            return Err(ClusterWriteError::ForwardAuthentication);
        }

        let (permission, scope) = match command {
            ConfigCommand::CreateProxyHost { .. } => (Permission::ProxyHostsWrite, None),
            ConfigCommand::UpdateProxyHost { host_id, .. }
            | ConfigCommand::DeleteProxyHost { host_id, .. } => {
                (Permission::ProxyHostsWrite, Some(("proxy_host", *host_id)))
            }
            ConfigCommand::UpdateRuntimePolicy { .. } => (Permission::SystemSettingsManage, None),
            ConfigCommand::Noop { .. } => return Err(ClusterWriteError::NotReplicatedCommand),
        };
        match repository::user_has_permission(&self.db, actor.user_id, permission.key(), scope)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(ClusterWriteError::ForwardAuthentication),
        }
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
            Ok((origin, command, actor)) if origin == authenticated_node_id => {
                match self.validate_authoritative_actor(&command, &actor).await {
                    Ok(()) => match self.submit_local(command).await {
                        Ok(receipt) => ForwardedCommandResponse::Receipt { receipt },
                        Err(error) => ForwardedCommandResponse::Error {
                            code: error.code().to_string(),
                        },
                    },
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

async fn resolve_post_write_outcome(
    db: &DbPool,
    command_id: Uuid,
    result: CommandResult,
    log_id: openraft::LogId<u64>,
) -> Result<CommittedCommandOutcome, ClusterWriteError> {
    let durable = repository::load_raft_command_receipt(db, &command_id.to_string())
        .await
        .map_err(|_| ClusterWriteError::QuorumUnavailable)?;
    if let Some(durable) = durable {
        return Ok(CommittedCommandOutcome {
            receipt: CommitReceipt {
                command_id,
                leader_id: u64::try_from(durable.leader_id)
                    .map_err(|_| ClusterWriteError::QuorumUnavailable)?,
                commit_index: u64::try_from(durable.log_index)
                    .map_err(|_| ClusterWriteError::QuorumUnavailable)?,
            },
            result: CommandResult::from_code(&durable.result_code)
                .ok_or(ClusterWriteError::QuorumUnavailable)?,
        });
    }
    if result == CommandResult::Duplicate {
        return Err(ClusterWriteError::QuorumUnavailable);
    }
    Ok(CommittedCommandOutcome {
        receipt: CommitReceipt {
            command_id,
            leader_id: log_id.leader_id.node_id,
            commit_index: log_id.index,
        },
        result,
    })
}

fn cache_receipt(
    receipts: &mut std::collections::BTreeMap<Uuid, CommittedCommandOutcome>,
    outcome: CommittedCommandOutcome,
) {
    if receipts.len() >= MAX_CACHED_RECEIPTS {
        let oldest = *receipts.keys().next().expect("non-empty receipt cache");
        receipts.remove(&oldest);
    }
    receipts.insert(outcome.receipt.command_id, outcome);
}

fn command_result(result: CommandResult) -> Result<(), ClusterWriteError> {
    match result {
        CommandResult::Applied | CommandResult::Duplicate => Ok(()),
        CommandResult::DuplicateDomain => Err(ClusterWriteError::DuplicateDomain),
        CommandResult::IdCollision => Err(ClusterWriteError::IdCollision),
        CommandResult::NotFound => Err(ClusterWriteError::NotFound),
    }
}

fn committed_outcome(outcome: CommittedCommandOutcome) -> Result<CommitReceipt, ClusterWriteError> {
    command_result(outcome.result)?;
    Ok(outcome.receipt)
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
    use super::{
        map_client_write_timeout, resolve_post_write_outcome, ClusterWriteError, CommitReceipt,
    };
    use crate::cluster_raft::{CommandResult, ConfigCommand};
    use crate::control_plane::models::ProxyHost;
    use crate::control_plane::repository;
    use openraft::LogId;
    use uuid::Uuid;

    #[test]
    fn client_write_timeout_reports_unknown_commit_outcome() {
        assert_eq!(
            map_client_write_timeout(),
            ClusterWriteError::CommitOutcomeUnknown
        );
    }

    #[tokio::test]
    async fn duplicate_after_precheck_returns_receipt_that_became_durable() {
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let command_id = Uuid::new_v4();
        let command = ConfigCommand::CreateProxyHost {
            command_id,
            host: ProxyHost {
                id: 91,
                name: "late-commit".into(),
                domain: "late-commit.example.test".into(),
                upstream_host: "127.0.0.1".into(),
                upstream_port: 8080,
                tls_mode: "disabled".into(),
                certificate_id: None,
                enabled: true,
            },
        };
        assert!(
            repository::load_raft_command_receipt(&pool, &command_id.to_string())
                .await
                .unwrap()
                .is_none(),
            "the retry pre-check must run before the earlier commit becomes visible"
        );
        repository::apply_raft_command_with_receipt(&pool, &command, 7, 2)
            .await
            .unwrap();

        let resolved = resolve_post_write_outcome(
            &pool,
            command_id,
            CommandResult::Duplicate,
            LogId::new(openraft::CommittedLeaderId::new(4, 3), 8),
        )
        .await
        .unwrap();

        assert_eq!(
            resolved.receipt,
            CommitReceipt {
                command_id,
                leader_id: 2,
                commit_index: 7,
            }
        );
        assert_eq!(resolved.result, CommandResult::Applied);
    }

    #[tokio::test]
    async fn duplicate_without_original_provenance_is_not_synthesized() {
        let pool = repository::connect("sqlite::memory:").await.unwrap();
        repository::migrate(&pool).await.unwrap();
        let command_id = Uuid::new_v4();
        let command = ConfigCommand::CreateProxyHost {
            command_id,
            host: ProxyHost {
                id: 92,
                name: "legacy-command".into(),
                domain: "legacy-command.example.test".into(),
                upstream_host: "127.0.0.1".into(),
                upstream_port: 8080,
                tls_mode: "disabled".into(),
                certificate_id: None,
                enabled: true,
            },
        };
        assert!(
            repository::record_raft_command_id(&pool, &command_id.to_string())
                .await
                .unwrap()
        );
        assert_eq!(
            repository::apply_raft_command_with_receipt(&pool, &command, 8, 3)
                .await
                .unwrap(),
            CommandResult::Duplicate
        );
        assert!(
            repository::load_raft_command_receipt(&pool, &command_id.to_string())
                .await
                .unwrap()
                .is_none(),
            "a later duplicate cannot prove the original receipt provenance"
        );

        assert_eq!(
            resolve_post_write_outcome(
                &pool,
                command_id,
                CommandResult::Duplicate,
                LogId::new(openraft::CommittedLeaderId::new(4, 3), 8),
            )
            .await,
            Err(ClusterWriteError::QuorumUnavailable)
        );
    }
}
