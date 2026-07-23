//! SQLx-backed persistence boundary for OpenRaft storage adapters.
//!
//! This type deliberately exposes durable primitives without implementing the
//! sealed OpenRaft storage-v2 traits yet.  Keeping the SQLx boundary concrete
//! lets lifecycle work adopt the traits incrementally without returning fake
//! defaults or silently losing committed data.

use crate::cluster_raft::ConfigCommand;
use crate::control_plane::repository::{
    self, DbPool, RaftHardState, RaftLogRecord, RaftSnapshotRecord,
};
use base64::Engine as _;
use sqlx::Error;

#[derive(Clone)]
pub struct SqlxRaftStorage {
    pool: DbPool,
    node_id: String,
}

impl SqlxRaftStorage {
    pub fn new(pool: DbPool, node_id: impl Into<String>) -> Result<Self, Error> {
        let node_id = node_id.into();
        if node_id.trim().is_empty() {
            return Err(Error::Protocol("raft node id must not be empty".into()));
        }
        Ok(Self { pool, node_id })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Return the stable numeric identity OpenRaft requires for this node.
    pub async fn raft_id(&self) -> Result<u64, Error> {
        let identity = repository::register_raft_node(&self.pool, &self.node_id).await?;
        u64::try_from(identity.raft_id)
            .map_err(|_| Error::Protocol("persisted raft node id is out of range".into()))
    }

    pub async fn save_vote(&self, term: i64, voted_for: Option<&str>) -> Result<(), Error> {
        repository::save_raft_hard_state(&self.pool, &self.node_id, term, voted_for).await
    }

    pub async fn load_vote(&self) -> Result<Option<RaftHardState>, Error> {
        repository::load_raft_hard_state(&self.pool, &self.node_id).await
    }

    pub async fn append_command(
        &self,
        index: i64,
        term: i64,
        command: &ConfigCommand,
    ) -> Result<(), Error> {
        let payload = command
            .to_payload()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let payload = String::from_utf8(payload)
            .map_err(|_| Error::Protocol("raft command payload is not utf-8".into()))?;
        repository::append_raft_log_entry(
            &self.pool,
            &self.node_id,
            index,
            term,
            &command.command_id().to_string(),
            &payload,
        )
        .await
    }

    pub async fn load_entries(&self, from_index: i64) -> Result<Vec<RaftLogRecord>, Error> {
        repository::load_raft_log_entries(&self.pool, &self.node_id, from_index).await
    }

    pub async fn truncate(&self, from_index: i64) -> Result<(), Error> {
        repository::truncate_raft_log(&self.pool, &self.node_id, from_index).await
    }

    pub async fn purge(&self, through_index: i64) -> Result<(), Error> {
        repository::purge_raft_log(&self.pool, &self.node_id, through_index).await
    }

    pub async fn save_snapshot(&self, index: i64, term: i64, payload: &[u8]) -> Result<(), Error> {
        repository::save_raft_snapshot(&self.pool, &self.node_id, index, term, payload).await
    }

    pub async fn load_snapshot(&self) -> Result<Option<RaftSnapshotRecord>, Error> {
        repository::load_raft_snapshot(&self.pool, &self.node_id).await
    }

    pub async fn decode_command(record: &RaftLogRecord) -> Result<ConfigCommand, Error> {
        ConfigCommand::from_payload(record.payload.as_bytes())
            .map_err(|error| Error::Protocol(error.to_string()))
    }

    pub fn encode_snapshot(payload: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(payload)
    }
}
