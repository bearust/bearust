//! SQLx-backed persistence boundary for OpenRaft storage adapters.
//!
//! This type exposes durable SQLx primitives and the OpenRaft storage-v2 log
//! adapter. State-machine and network adapters remain separate concerns.

use crate::cluster_raft::ConfigCommand;
use crate::control_plane::repository::{
    self, DbPool, RaftHardState, RaftLogRecord, RaftSnapshotRecord,
};
use base64::Engine as _;
use openraft::storage::{LogFlushed, RaftLogReader, RaftLogStorage, RaftStateMachine};
use openraft::{
    Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, Snapshot, SnapshotMeta,
    StorageError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use sqlx::Error;
use std::fmt::Debug;
use std::io::{Cursor, Read};
use std::ops::Bound;

#[derive(Clone)]
pub struct SqlxRaftStorage {
    pool: DbPool,
    node_id: String,
}

type StorageResult<T> = Result<T, StorageError<u64>>;
#[derive(Clone)]
pub struct SqlxSnapshotBuilder {
    storage: SqlxRaftStorage,
}

/// Snapshots retain at most this newest receipt window. The database receipt
/// ledger remains durable and unbounded; only snapshot transfer provenance is
/// truncated, with an additional serialized-byte budget applied below.
pub const MAX_SNAPSHOT_COMMAND_RECEIPTS: usize = 1_024;

const MAX_SNAPSHOT_PAYLOAD_BYTES: usize =
    if repository::MAX_RAFT_PAYLOAD_BYTES < crate::cluster_raft::MAX_RPC_FRAME_BYTES {
        repository::MAX_RAFT_PAYLOAD_BYTES
    } else {
        crate::cluster_raft::MAX_RPC_FRAME_BYTES
    };

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotEnvelope {
    proxy_hosts: Vec<crate::control_plane::models::ProxyHost>,
    host_rate_limits: Vec<(i64, crate::control_plane::models::RateLimitConfig)>,
    #[serde(default)]
    runtime_config: Option<crate::config::Config>,
    #[serde(default)]
    command_receipts: Vec<repository::RaftCommandReceipt>,
}

fn storage_error(
    subject: ErrorSubject<u64>,
    verb: ErrorVerb,
    error: impl std::fmt::Display,
) -> StorageError<u64> {
    StorageError::from_io_error(subject, verb, std::io::Error::other(error.to_string()))
}

fn encode_bounded_snapshot(
    mut envelope: SnapshotEnvelope,
    newest_receipts: Vec<repository::RaftCommandReceipt>,
) -> Result<Vec<u8>, std::io::Error> {
    let empty_encoded = serde_json::to_vec(&envelope)
        .map_err(|_| std::io::Error::other("snapshot serialization failed"))?;
    if empty_encoded.len() > MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Err(std::io::Error::other(
            "replicated configuration exceeds snapshot payload limit",
        ));
    }

    let mut remaining = MAX_SNAPSHOT_PAYLOAD_BYTES - empty_encoded.len();
    for receipt in newest_receipts {
        let receipt_bytes = serde_json::to_vec(&receipt)
            .map_err(|_| std::io::Error::other("snapshot serialization failed"))?;
        let required = receipt_bytes.len() + usize::from(!envelope.command_receipts.is_empty());
        if required > remaining {
            break;
        }
        remaining -= required;
        envelope.command_receipts.push(receipt);
    }
    envelope.command_receipts.reverse();

    let encoded = serde_json::to_vec(&envelope)
        .map_err(|_| std::io::Error::other("snapshot serialization failed"))?;
    if encoded.len() > MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Err(std::io::Error::other("snapshot exceeds configured limit"));
    }
    Ok(encoded)
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
            let command = match entry.payload {
                EntryPayload::Normal(command) => command,
                EntryPayload::Blank | EntryPayload::Membership(_) => {
                    crate::cluster_raft::ConfigCommand::Noop {
                        command_id: uuid::Uuid::new_v4(),
                    }
                }
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

impl openraft::RaftSnapshotBuilder<crate::cluster_raft::BearustRaftConfig> for SqlxSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> StorageResult<Snapshot<crate::cluster_raft::BearustRaftConfig>> {
        let (last_log, _) = self.storage.clone().applied_state().await?;
        let log_id = last_log.ok_or_else(|| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Read,
                "no applied log",
            )
        })?;
        let envelope = SnapshotEnvelope {
            proxy_hosts: repository::list_hosts(&self.storage.pool)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?,
            host_rate_limits: repository::list_host_rate_limit_configs(&self.storage.pool)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?,
            runtime_config: repository::get_runtime_config(&self.storage.pool)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?,
            command_receipts: Vec::new(),
        };
        let newest_receipts = repository::list_recent_raft_command_receipts(
            &self.storage.pool,
            MAX_SNAPSHOT_COMMAND_RECEIPTS,
        )
        .await
        .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        let encoded = encode_bounded_snapshot(envelope, newest_receipts)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        self.storage
            .save_snapshot(log_id.index as i64, log_id.leader_id.term as i64, &encoded)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        let index = log_id.index;
        let term = log_id.leader_id.term;
        let raft_id = self
            .storage
            .raft_id()
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id: Some(LogId::new(
                    openraft::CommittedLeaderId::new(term, raft_id),
                    index,
                )),
                last_membership: StoredMembership::default(),
                snapshot_id: format!("{}-{}", term, index),
            },
            snapshot: Box::new(Cursor::new(encoded)),
        })
    }
}

impl openraft::storage::RaftStateMachine<crate::cluster_raft::BearustRaftConfig>
    for SqlxRaftStorage
{
    type SnapshotBuilder = SqlxSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<u64>>,
            StoredMembership<u64, openraft::BasicNode>,
        ),
        StorageError<u64>,
    > {
        let state = repository::load_raft_committed_state(&self.pool, &self.node_id)
            .await
            .map_err(|e| storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, e))?;
        let log_id = state.and_then(|s| {
            Some(LogId::new(
                openraft::CommittedLeaderId::new(
                    u64::try_from(s.term).ok()?,
                    u64::try_from(s.leader_id).ok()?,
                ),
                u64::try_from(s.log_index).ok()?,
            ))
        });
        Ok((log_id, StoredMembership::default()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> StorageResult<Vec<crate::cluster_raft::CommandResult>>
    where
        I: IntoIterator<Item = Entry<crate::cluster_raft::BearustRaftConfig>>
            + openraft::OptionalSend,
        I::IntoIter: openraft::OptionalSend,
    {
        let mut results = Vec::new();
        for entry in entries {
            if let EntryPayload::Normal(command) = entry.payload {
                let result = if matches!(command, ConfigCommand::Noop { .. }) {
                    repository::apply_raft_command(&self.pool, &command).await
                } else {
                    repository::apply_raft_command_with_receipt(
                        &self.pool,
                        &command,
                        entry.log_id.index as i64,
                        entry.log_id.leader_id.node_id as i64,
                    )
                    .await
                }
                .map_err(|e| {
                    storage_error(ErrorSubject::Apply(entry.log_id), ErrorVerb::Write, e)
                })?;
                repository::save_raft_committed_state(
                    &self.pool,
                    &self.node_id,
                    entry.log_id.index as i64,
                    entry.log_id.leader_id.term as i64,
                    entry.log_id.leader_id.node_id as i64,
                )
                .await
                .map_err(|e| {
                    storage_error(ErrorSubject::Apply(entry.log_id), ErrorVerb::Write, e)
                })?;
                results.push(result);
            }
        }
        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SqlxSnapshotBuilder {
            storage: self.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> StorageResult<()> {
        let mut bytes = Vec::new();
        snapshot
            .take((repository::MAX_RAFT_PAYLOAD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        if bytes.len() > repository::MAX_RAFT_PAYLOAD_BYTES {
            return Err(storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                "snapshot exceeds configured limit",
            ));
        }
        let envelope: SnapshotEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        let log_id = meta.last_log_id.ok_or_else(|| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                "snapshot missing last log id",
            )
        })?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM proxy_hosts")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM host_rate_limit_configs")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM runtime_config WHERE id=1")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM raft_command_receipts")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM raft_command_results")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        sqlx::query("DELETE FROM raft_command_ids")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        let now = chrono::Utc::now().to_rfc3339();
        for host in &envelope.proxy_hosts {
            sqlx::query("INSERT INTO proxy_hosts(id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(host.id).bind(&host.name).bind(&host.domain).bind(&host.upstream_host).bind(host.upstream_port as i64).bind(&host.tls_mode).bind(host.certificate_id).bind(host.enabled as i64).bind(&now).bind(&now).execute(&mut *tx).await.map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        }
        for (host_id, config) in &envelope.host_rate_limits {
            sqlx::query("INSERT INTO host_rate_limit_configs(host_id,capacity,refill_per_second,updated_at) VALUES(?,?,?,?)").bind(host_id).bind(config.capacity as i64).bind(config.refill_per_second).bind(&config.updated_at).execute(&mut *tx).await.map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        }
        for receipt in &envelope.command_receipts {
            if uuid::Uuid::parse_str(&receipt.command_id).is_err()
                || receipt.log_index < 0
                || receipt.leader_id <= 0
            {
                return Err(storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    "snapshot contains invalid command receipt provenance",
                ));
            }
            sqlx::query("INSERT INTO raft_command_ids(command_id,applied_at) VALUES(?,?)")
                .bind(&receipt.command_id)
                .bind(&receipt.applied_at)
                .execute(&mut *tx)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
            if crate::cluster_raft::CommandResult::from_code(&receipt.result_code).is_none() {
                return Err(storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    "snapshot contains invalid command result",
                ));
            }
            sqlx::query("INSERT INTO raft_command_results(command_id,result_code) VALUES(?,?)")
                .bind(&receipt.command_id)
                .bind(&receipt.result_code)
                .execute(&mut *tx)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
            sqlx::query(
                "INSERT INTO raft_command_receipts(command_id,log_index,leader_id,applied_at)
                 VALUES(?,?,?,?)",
            )
            .bind(&receipt.command_id)
            .bind(receipt.log_index)
            .bind(receipt.leader_id)
            .bind(&receipt.applied_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        }
        if let Some(config) = &envelope.runtime_config {
            let payload = toml::to_string(config)
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
            sqlx::query("INSERT INTO runtime_config(id,payload,updated_at) VALUES(1,?,?)")
                .bind(payload)
                .bind(chrono::Utc::now().to_rfc3339())
                .execute(&mut *tx)
                .await
                .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        }
        tx.commit()
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        repository::save_raft_committed_state(
            &self.pool,
            &self.node_id,
            log_id.index as i64,
            log_id.leader_id.term as i64,
            0,
        )
        .await
        .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))?;
        self.save_snapshot(log_id.index as i64, log_id.leader_id.term as i64, &encoded)
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e))
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> StorageResult<Option<Snapshot<crate::cluster_raft::BearustRaftConfig>>> {
        let record = self
            .load_snapshot()
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let envelope: SnapshotEnvelope = serde_json::from_slice(&record.payload)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        let index = u64::try_from(record.snapshot_index)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        let term = u64::try_from(record.snapshot_term)
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        let raft_id = self
            .raft_id()
            .await
            .map_err(|e| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e))?;
        Ok(Some(Snapshot {
            meta: SnapshotMeta {
                last_log_id: Some(LogId::new(
                    openraft::CommittedLeaderId::new(term, raft_id),
                    index,
                )),
                last_membership: StoredMembership::default(),
                snapshot_id: format!("{}-{}", term, index),
            },
            snapshot: Box::new(Cursor::new(serde_json::to_vec(&envelope).map_err(|e| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, e)
            })?)),
        }))
    }
}
