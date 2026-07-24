//! Typed, bounded configuration commands used by the Phase 10B Raft layer.
//!
//! Commands intentionally contain only declarative configuration. They never
//! carry passwords, certificate private keys, request bodies, or database
//! errors, and their `Debug` representation omits mutation payloads.

use crate::control_plane::models::ProxyHost;
use crate::rate_limit::RateLimitPolicy;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_COMMAND_BYTES: usize = 256 * 1024;
pub const MAX_RPC_FRAME_BYTES: usize = MAX_COMMAND_BYTES;
/// JSON serializes each snapshot byte as up to three digits plus a separator.
/// This chunk size leaves room for that expansion and the InstallSnapshot RPC
/// metadata inside one authenticated transport frame.
pub const MAX_SNAPSHOT_CHUNK_BYTES: usize = 48 * 1024;
pub const RPC_TAG_BYTES: usize = 32;
const RPC_MAGIC: &[u8; 7] = b"BRRAFT1";
const MAX_NAME_BYTES: usize = 128;
const MAX_HOSTNAME_BYTES: usize = 253;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommandResult {
    Applied,
    Duplicate,
}

openraft::declare_raft_types!(
    pub BearustRaftConfig:
        D = ConfigCommand,
        R = CommandResult,
        NodeId = u64,
        Node = openraft::BasicNode,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

#[derive(Clone, Serialize, Deserialize)]
pub enum ConfigCommand {
    /// Internal log marker used to durably represent OpenRaft blank or
    /// membership entries in the command-oriented SQL log.
    Noop {
        command_id: Uuid,
    },
    CreateProxyHost {
        command_id: Uuid,
        host: ProxyHost,
    },
    UpdateProxyHost {
        command_id: Uuid,
        host_id: i64,
        host: ProxyHost,
    },
    DeleteProxyHost {
        command_id: Uuid,
        host_id: i64,
    },
    UpdateRuntimePolicy {
        command_id: Uuid,
        host_id: i64,
        policy: RateLimitPolicy,
    },
}

impl fmt::Debug for ConfigCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, id, host_id) = match self {
            Self::Noop { command_id } => ("Noop", command_id, None),
            Self::CreateProxyHost { command_id, host } => {
                ("CreateProxyHost", command_id, Some(host.id))
            }
            Self::UpdateProxyHost {
                command_id,
                host_id,
                ..
            } => ("UpdateProxyHost", command_id, Some(*host_id)),
            Self::DeleteProxyHost {
                command_id,
                host_id,
            } => ("DeleteProxyHost", command_id, Some(*host_id)),
            Self::UpdateRuntimePolicy {
                command_id,
                host_id,
                ..
            } => ("UpdateRuntimePolicy", command_id, Some(*host_id)),
        };
        formatter
            .debug_struct(name)
            .field("command_id", id)
            .field("host_id", &host_id)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("raft command payload exceeds configured limit")]
    PayloadTooLarge,
    #[error("raft command payload is malformed")]
    MalformedPayload,
    #[error("raft RPC authentication failed")]
    AuthenticationFailed,
    #[error("raft command is invalid: {0}")]
    Invalid(String),
}

type RpcMac = Hmac<Sha256>;

/// Encode a bounded Raft RPC payload with a detached HMAC-SHA256 tag.
pub fn encode_rpc_frame(payload: &[u8], secret: &[u8]) -> Result<Vec<u8>, CommandError> {
    if payload.len() > MAX_RPC_FRAME_BYTES {
        return Err(CommandError::PayloadTooLarge);
    }
    if secret.is_empty() {
        return Err(CommandError::AuthenticationFailed);
    }
    let length = u32::try_from(payload.len()).map_err(|_| CommandError::PayloadTooLarge)?;
    let mut mac = RpcMac::new_from_slice(secret).map_err(|_| CommandError::AuthenticationFailed)?;
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    let mut frame = Vec::with_capacity(RPC_MAGIC.len() + 4 + payload.len() + RPC_TAG_BYTES);
    frame.extend_from_slice(RPC_MAGIC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&tag);
    Ok(frame)
}

/// Decode and authenticate one complete Raft RPC frame without leaking the
/// secret or payload in the returned error.
pub fn decode_rpc_frame<'a>(frame: &'a [u8], secret: &[u8]) -> Result<&'a [u8], CommandError> {
    if secret.is_empty() || frame.len() < RPC_MAGIC.len() + 4 + RPC_TAG_BYTES {
        return Err(CommandError::MalformedPayload);
    }
    if &frame[..RPC_MAGIC.len()] != RPC_MAGIC {
        return Err(CommandError::MalformedPayload);
    }
    let length_start = RPC_MAGIC.len();
    let length_end = length_start + 4;
    let declared = u32::from_be_bytes(
        frame[length_start..length_end]
            .try_into()
            .map_err(|_| CommandError::MalformedPayload)?,
    ) as usize;
    if declared > MAX_RPC_FRAME_BYTES
        || frame.len() != RPC_MAGIC.len() + 4 + declared + RPC_TAG_BYTES
    {
        return Err(CommandError::MalformedPayload);
    }
    let payload_start = length_end;
    let payload_end = payload_start + declared;
    let payload = &frame[payload_start..payload_end];
    let tag = &frame[payload_end..];
    let mut mac = RpcMac::new_from_slice(secret).map_err(|_| CommandError::AuthenticationFailed)?;
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| CommandError::AuthenticationFailed)?;
    Ok(payload)
}

impl ConfigCommand {
    pub fn command_id(&self) -> Uuid {
        match self {
            Self::Noop { command_id }
            | Self::CreateProxyHost { command_id, .. }
            | Self::UpdateProxyHost { command_id, .. }
            | Self::DeleteProxyHost { command_id, .. }
            | Self::UpdateRuntimePolicy { command_id, .. } => *command_id,
        }
    }

    pub fn validate(&self) -> Result<(), CommandError> {
        if self.command_id().is_nil() {
            return Err(CommandError::Invalid("command_id must not be nil".into()));
        }
        match self {
            Self::Noop { .. } => {}
            Self::CreateProxyHost { host, .. } => {
                validate_host(host)?;
            }
            Self::UpdateProxyHost { host_id, host, .. } => {
                validate_host(host)?;
                if *host_id != host.id {
                    return Err(CommandError::Invalid(
                        "host_id must match host.id for updates".into(),
                    ));
                }
            }
            Self::DeleteProxyHost { host_id, .. } | Self::UpdateRuntimePolicy { host_id, .. }
                if *host_id <= 0 =>
            {
                return Err(CommandError::Invalid("host_id must be positive".into()));
            }
            Self::UpdateRuntimePolicy { policy, .. } => policy
                .validate()
                .map_err(|error| CommandError::Invalid(error.to_string()))?,
            _ => {}
        }
        Ok(())
    }

    pub fn to_payload(&self) -> Result<Vec<u8>, CommandError> {
        self.validate()?;
        let payload = serde_json::to_vec(self).map_err(|_| CommandError::MalformedPayload)?;
        if payload.len() > MAX_COMMAND_BYTES {
            return Err(CommandError::PayloadTooLarge);
        }
        Ok(payload)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, CommandError> {
        if payload.len() > MAX_COMMAND_BYTES {
            return Err(CommandError::PayloadTooLarge);
        }
        let command: Self =
            serde_json::from_slice(payload).map_err(|_| CommandError::MalformedPayload)?;
        command.validate()?;
        Ok(command)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReplicatedConfig {
    proxy_hosts: BTreeMap<i64, ProxyHost>,
    runtime_policies: BTreeMap<i64, RateLimitPolicy>,
    applied_commands: BTreeSet<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct ConfigSnapshot {
    proxy_hosts: BTreeMap<i64, ProxyHost>,
    runtime_policies: BTreeMap<i64, RateLimitPolicy>,
    applied_commands: BTreeSet<Uuid>,
}

impl ReplicatedConfig {
    pub fn proxy_hosts(&self) -> &BTreeMap<i64, ProxyHost> {
        &self.proxy_hosts
    }

    pub fn has_applied(&self, command_id: Uuid) -> bool {
        self.applied_commands.contains(&command_id)
    }

    /// Apply one committed command. Replaying a command ID is a no-op.
    pub fn apply(&mut self, command: &ConfigCommand) -> Result<bool, CommandError> {
        command.validate()?;
        if !self.applied_commands.insert(command.command_id()) {
            return Ok(false);
        }
        match command {
            ConfigCommand::Noop { .. } => {}
            ConfigCommand::CreateProxyHost { host, .. }
            | ConfigCommand::UpdateProxyHost { host, .. } => {
                self.proxy_hosts.insert(host.id, host.clone());
            }
            ConfigCommand::DeleteProxyHost { host_id, .. } => {
                self.proxy_hosts.remove(host_id);
                self.runtime_policies.remove(host_id);
            }
            ConfigCommand::UpdateRuntimePolicy {
                host_id, policy, ..
            } => {
                self.runtime_policies.insert(*host_id, policy.clone());
            }
        }
        Ok(true)
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, CommandError> {
        let snapshot = ConfigSnapshot {
            proxy_hosts: self.proxy_hosts.clone(),
            runtime_policies: self.runtime_policies.clone(),
            applied_commands: self.applied_commands.clone(),
        };
        let payload = serde_json::to_vec(&snapshot).map_err(|_| CommandError::MalformedPayload)?;
        if payload.len() > MAX_COMMAND_BYTES {
            return Err(CommandError::PayloadTooLarge);
        }
        Ok(payload)
    }

    pub fn from_snapshot(payload: &[u8]) -> Result<Self, CommandError> {
        if payload.len() > MAX_COMMAND_BYTES {
            return Err(CommandError::PayloadTooLarge);
        }
        let snapshot: ConfigSnapshot =
            serde_json::from_slice(payload).map_err(|_| CommandError::MalformedPayload)?;
        Ok(Self {
            proxy_hosts: snapshot.proxy_hosts,
            runtime_policies: snapshot.runtime_policies,
            applied_commands: snapshot.applied_commands,
        })
    }
}

fn validate_host(host: &ProxyHost) -> Result<(), CommandError> {
    if host.id <= 0 {
        return Err(CommandError::Invalid("host id must be positive".into()));
    }
    if host.name.trim().is_empty() || host.name.len() > MAX_NAME_BYTES {
        return Err(CommandError::Invalid("host name is invalid".into()));
    }
    for (label, value) in [
        ("domain", host.domain.as_str()),
        ("upstream_host", host.upstream_host.as_str()),
        ("tls_mode", host.tls_mode.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_HOSTNAME_BYTES {
            return Err(CommandError::Invalid(format!("{label} is invalid")));
        }
    }
    if host.upstream_port == 0 {
        return Err(CommandError::Invalid(
            "upstream_port must be positive".into(),
        ));
    }
    Ok(())
}
