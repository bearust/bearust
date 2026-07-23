//! SQLx-backed persistence boundary for OpenRaft storage adapters.
//!
//! This type exposes durable SQLx primitives and the OpenRaft storage-v2 log
//! adapter. State-machine and network adapters remain separate concerns.

use crate::cluster_raft::ConfigCommand;
use crate::control_plane::repository::{
    self, DbPool, RaftHardState, RaftLogRecord, RaftSnapshotRecord,
};
use base64::Engine as _;
use openraft::storage::{LogFlushed, RaftLogReader, RaftLogStorage};
use openraft::{Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, StorageError, Vote};
use sqlx::Error;
use std::fmt::Debug;
use std::ops::Bound;

#[derive(Clone)]
pub struct SqlxRaftStorage {
    pool: DbPool,
    node_id: String,
}

type StorageResult<T> = Result<T, StorageError<u64>>;

fn storage_error(
    subject: ErrorSubject<u64>,
    verb: ErrorVerb,
    error: impl std::fmt::Display,
) -> StorageError<u64> {
    StorageError::from_io_error(subject, verb, std::io::Error::other(error.to_string()))
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

    pub async fn save_committed(
        &self,
        log_index: i64,
        term: i64,
        leader_id: u64,
    ) -> Result<(), Error> {
        let leader_id = i64::try_from(leader_id)
            .map_err(|_| Error::Protocol("raft leader id is out of range".into()))?;
        repository::save_raft_committed_state(&self.pool, &self.node_id, log_index, term, leader_id)
            .await
    }

    pub async fn load_committed(&self) -> Result<Option<repository::RaftCommittedState>, Error> {
        repository::load_raft_committed_state(&self.pool, &self.node_id).await
    }

    pub async fn append_command(
        &self,
        index: i64,
        term: i64,
        leader_id: u64,
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
            i64::try_from(leader_id)
                .map_err(|_| Error::Protocol("raft leader id is out of range".into()))?,
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

impl RaftLogReader<crate::cluster_raft::BearustRaftConfig> for SqlxRaftStorage {
    async fn try_get_log_entries<
        RB: std::ops::RangeBounds<u64> + Clone + Debug + openraft::OptionalSend,
    >(
        &mut self,
        range: RB,
    ) -> StorageResult<Vec<Entry<crate::cluster_raft::BearustRaftConfig>>> {
        let start = match range.start_bound() {
            Bound::Included(value) => *value,
            Bound::Excluded(value) => value.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(value) => value.saturating_add(1),
            Bound::Excluded(value) => *value,
            Bound::Unbounded => u64::MAX,
        };
        if start >= end {
            return Ok(Vec::new());
        }
        let records = self
            .load_entries(
                i64::try_from(start)
                    .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))?,
            )
            .await
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))?;
        let mut result = Vec::new();
        for record in records
            .into_iter()
            .filter(|r| u64::try_from(r.log_index).is_ok_and(|i| i < end))
        {
            let index = u64::try_from(record.log_index).map_err(|e| {
                storage_error(
                    ErrorSubject::LogIndex(record.log_index.max(0) as u64),
                    ErrorVerb::Read,
                    e,
                )
            })?;
            let term = u64::try_from(record.term)
                .map_err(|e| storage_error(ErrorSubject::LogIndex(index), ErrorVerb::Read, e))?;
            let command = Self::decode_command(&record)
                .await
                .map_err(|e| storage_error(ErrorSubject::LogIndex(index), ErrorVerb::Read, e))?;
            let leader_id = u64::try_from(record.leader_id)
                .map_err(|e| storage_error(ErrorSubject::LogIndex(index), ErrorVerb::Read, e))?;
            result.push(Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(term, leader_id), index),
                payload: EntryPayload::Normal(command),
            });
        }
        Ok(result)
    }
}

impl RaftLogStorage<crate::cluster_raft::BearustRaftConfig> for SqlxRaftStorage {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> StorageResult<LogState<crate::cluster_raft::BearustRaftConfig>> {
        let records = self
            .load_entries(0)
            .await
            .map_err(|e| storage_error(ErrorSubject::Logs, ErrorVerb::Read, e))?;
        let last_log_id = records.last().and_then(|r| {
            Some(LogId::new(
                openraft::CommittedLeaderId::new(
                    u64::try_from(r.term).ok()?,
                    u64::try_from(r.leader_id).ok()?,
                ),
                u64::try_from(r.log_index).ok()?,
            ))
        });
        Ok(LogState {
            last_purged_log_id: None,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> StorageResult<()> {
        // Hard-state stores the stable numeric Raft identity, not the external
        // application node name. This keeps vote recovery lossless.
        let voted_for = vote.leader_id.voted_for().map(|id| id.to_string());
        SqlxRaftStorage::save_vote(self, vote.leader_id.term as i64, voted_for.as_deref())
            .await
            .map_err(|e| storage_error(ErrorSubject::Vote, ErrorVerb::Write, e))
    }

    async fn read_vote(&mut self) -> StorageResult<Option<Vote<u64>>> {
        let state = self
            .load_vote()
            .await
            .map_err(|e| storage_error(ErrorSubject::Vote, ErrorVerb::Read, e))?;
        let Some(state) = state else {
            return Ok(None);
        };
        let term = u64::try_from(state.current_term)
            .map_err(|e| storage_error(ErrorSubject::Vote, ErrorVerb::Read, e))?;
        let node = match state.voted_for {
            Some(id) => id
                .parse::<u64>()
                .map_err(|e| storage_error(ErrorSubject::Vote, ErrorVerb::Read, e))?,
            None => 0,
        };
        Ok(Some(Vote {
            leader_id: openraft::LeaderId::new(term, node),
            committed: false,
        }))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<crate::cluster_raft::BearustRaftConfig>,
    ) -> StorageResult<()>
    where
        I: IntoIterator<Item = Entry<crate::cluster_raft::BearustRaftConfig>>
            + openraft::OptionalSend,
        I::IntoIter: openraft::OptionalSend,
    {
        for entry in entries {
            let EntryPayload::Normal(command) = entry.payload else {
                return Err(storage_error(
                    ErrorSubject::Log(entry.log_id),
                    ErrorVerb::Write,
                    "unsupported non-normal raft entry",
                ));
            };
            self.append_command(
                entry.log_id.index as i64,
                entry.log_id.leader_id.term as i64,
                entry.log_id.leader_id.node_id,
                &command,
            )
            .await
            .map_err(|e| storage_error(ErrorSubject::Log(entry.log_id), ErrorVerb::Write, e))?;
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> StorageResult<()> {
        SqlxRaftStorage::truncate(self, log_id.index as i64)
            .await
            .map_err(|e| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, e))
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> StorageResult<()> {
        SqlxRaftStorage::purge(self, log_id.index as i64)
            .await
            .map_err(|e| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, e))
    }
}
