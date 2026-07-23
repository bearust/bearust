//! Typed, bounded configuration commands used by the Phase 10B Raft layer.
//!
//! Commands intentionally contain only declarative configuration. They never
//! carry passwords, certificate private keys, request bodies, or database
//! errors, and their `Debug` representation omits mutation payloads.

use crate::control_plane::models::ProxyHost;
use crate::rate_limit::RateLimitPolicy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_COMMAND_BYTES: usize = 256 * 1024;
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
    #[error("raft command is invalid: {0}")]
    Invalid(String),
}

impl ConfigCommand {
    pub fn command_id(&self) -> Uuid {
        match self {
            Self::CreateProxyHost { command_id, .. }
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
            Self::CreateProxyHost { host, .. } | Self::UpdateProxyHost { host, .. } => {
                validate_host(host)?;
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
