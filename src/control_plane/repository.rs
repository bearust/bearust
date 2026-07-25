use crate::bot_protection::{
    BotConfig, BotMode, BotRule, MAX_FIELD_BYTES, MAX_RULES, MAX_TRUSTED_RULES, MAX_TTL_SECONDS,
};
use crate::cluster_raft::{CommandResult, ConfigCommand};
use crate::control_plane::models::{
    AcmeChallenge, AcmeEnvironment, AcmeRequest, AcmeStatus, AdvisorJobPage, AdvisorJobRecord,
    AuditLogItem, AuditLogPage, AuditLogQuery, CertificateMetadata, ProxyHost, RateLimitConfig,
    RoleDetail, RolePermissionScope, User, WafAction, WafConfig, WafMode, WafRule,
};
use crate::control_plane::rbac::Role;
use crate::rate_limit::{RateLimitAction, RateLimitKeyScope, RateLimitPolicy};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sqlx::{any::AnyPoolOptions, Row};
use std::hash::{Hash, Hasher};
use std::sync::Once;
use uuid::Uuid;

pub const MAX_ADVISOR_PERSISTED_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct NewAdvisorJob {
    pub job_id: crate::ai_advisor::AdvisorJobId,
    pub owner_id: i64,
    pub workflow: crate::ai_advisor::AdvisorWorkflow,
    pub redacted_input: String,
    pub provider_model: String,
    pub config_version: String,
    pub config_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Database pool type used by the control plane once all repositories have
/// been migrated to SQLx's backend-agnostic driver.
pub type DbPool = sqlx::AnyPool;

/// Maximum serialized command/snapshot payload persisted by the Raft layer.
/// Keeping this bounded prevents an accidental or hostile proposal from
/// turning the control-plane database into an unbounded blob store.
pub const MAX_RAFT_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftHardState {
    pub node_id: String,
    pub current_term: i64,
    pub voted_for: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftNodeIdentity {
    pub node_id: String,
    pub raft_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftLogRecord {
    pub node_id: String,
    pub log_index: i64,
    pub term: i64,
    pub leader_id: i64,
    pub command_id: Option<String>,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftCommittedState {
    pub node_id: String,
    pub log_index: i64,
    pub term: i64,
    pub leader_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftCommandReceipt {
    pub command_id: String,
    pub log_index: i64,
    pub leader_id: i64,
    pub applied_at: String,
    pub result_code: String,
}

/// Register a stable numeric OpenRaft identity for an application node name.
/// IDs are allocated once and never derived from a hash, avoiding collisions.
pub async fn register_raft_node(
    pool: &DbPool,
    node_id: &str,
) -> Result<RaftNodeIdentity, sqlx::Error> {
    if node_id.trim().is_empty() {
        return Err(sqlx::Error::Protocol(
            "raft node id must not be empty".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    if let Some(row) = sqlx::query("SELECT node_id,raft_id FROM raft_node_ids WHERE node_id=?")
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await?
    {
        tx.commit().await?;
        return Ok(RaftNodeIdentity {
            node_id: row.get("node_id"),
            raft_id: row.get("raft_id"),
        });
    }
    let next_id: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(raft_id),0)+1 FROM raft_node_ids")
        .fetch_one(&mut *tx)
        .await?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO raft_node_ids(node_id,raft_id,created_at) VALUES(?,?,?)")
        .bind(node_id)
        .bind(next_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(RaftNodeIdentity {
        node_id: node_id.to_owned(),
        raft_id: next_id,
    })
}

pub async fn load_raft_node_by_id(
    pool: &DbPool,
    raft_id: i64,
) -> Result<Option<RaftNodeIdentity>, sqlx::Error> {
    let row = sqlx::query("SELECT node_id,raft_id FROM raft_node_ids WHERE raft_id=?")
        .bind(raft_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| RaftNodeIdentity {
        node_id: row.get("node_id"),
        raft_id: row.get("raft_id"),
    }))
}

pub async fn save_raft_committed_state(
    pool: &DbPool,
    node_id: &str,
    log_index: i64,
    term: i64,
    leader_id: i64,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM raft_committed_state WHERE node_id=?")
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO raft_committed_state(node_id,log_index,term,leader_id,updated_at) VALUES(?,?,?,?,?)")
        .bind(node_id)
        .bind(log_index)
        .bind(term)
        .bind(leader_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

pub async fn load_raft_committed_state(
    pool: &DbPool,
    node_id: &str,
) -> Result<Option<RaftCommittedState>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT node_id,log_index,term,leader_id FROM raft_committed_state WHERE node_id=?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| RaftCommittedState {
        node_id: row.get("node_id"),
        log_index: row.get("log_index"),
        term: row.get("term"),
        leader_id: row.get("leader_id"),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftSnapshotRecord {
    pub node_id: String,
    pub snapshot_index: i64,
    pub snapshot_term: i64,
    pub payload: Vec<u8>,
}

static ANY_DRIVERS: Once = Once::new();

/// Validate a database URL without including credentials in the resulting
/// error.  Only the backends supported by the application are accepted.
pub fn validate_database_url(url: &str) -> Result<(), sqlx::Error> {
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .or_else(|| url.split_once(':').map(|(scheme, _)| scheme))
        .unwrap_or("");
    if url.is_empty()
        || !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "sqlite" | "postgres" | "postgresql" | "mysql"
        )
    {
        return Err(sqlx::Error::Configuration(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported database URL",
        ))));
    }
    Ok(())
}

pub async fn connect(url: &str) -> Result<DbPool, sqlx::Error> {
    validate_database_url(url)?;
    ANY_DRIVERS.call_once(sqlx::any::install_default_drivers);
    let max_connections = if is_in_memory_sqlite(url) { 1 } else { 8 };
    AnyPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
}

fn is_in_memory_sqlite(url: &str) -> bool {
    let normalized = url.trim().to_ascii_lowercase();
    normalized.starts_with("sqlite:")
        && (normalized.contains(":memory:") || normalized.contains("mode=memory"))
}
pub async fn migrate(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    seed_builtin_waf_rules(pool).await?;

    // Keep this outside the migration SQL so legacy databases that already
    // have the index can be upgraded safely on every supported backend.
    match sqlx::query("CREATE INDEX idx_role_permissions_scope ON role_permissions(scope_type, scope_id, role_id, permission_id)").execute(pool).await {
        Ok(_) => {}
        Err(error) if error.to_string().to_ascii_lowercase().contains("already exists") || error.to_string().to_ascii_lowercase().contains("duplicate") => {}
        Err(error) => return Err(error),
    }

    // The first release created these columns inline. Add them for those
    // databases without dropping or rewriting existing rows. Each backend
    // reports a duplicate-column error differently, so only that error is
    // ignored; all other failures abort startup.
    for statement in [
        "ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN preferred_locale VARCHAR(8)",
        "ALTER TABLE acme_certificates ADD COLUMN secret_ref TEXT",
    ] {
        match sqlx::query(statement).execute(pool).await {
            Ok(_) => {}
            Err(error) if is_duplicate_column(&error) => {}
            Err(error) => return Err(error),
        }
    }
    // Normalize legacy partial-NULL scope rows without rowid/ctid syntax.
    // Delete all nullable variants for each role/permission, then restore one
    // portable global sentinel when no global grant already exists.
    let nullable_pairs = sqlx::query("SELECT DISTINCT role_id,permission_id FROM role_permissions WHERE scope_type IS NULL OR scope_id IS NULL").fetch_all(pool).await?;
    for pair in nullable_pairs {
        let role_id: i64 = pair.get("role_id");
        let permission_id: i64 = pair.get("permission_id");
        sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND permission_id=? AND (scope_type IS NULL OR scope_id IS NULL)").bind(role_id).bind(permission_id).execute(pool).await?;
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,?,'',0 WHERE NOT EXISTS (SELECT 1 FROM role_permissions WHERE role_id=? AND permission_id=? AND scope_type='' AND scope_id=0)").bind(role_id).bind(permission_id).bind(role_id).bind(permission_id).execute(pool).await?;
    }

    let permissions = [
        "proxy_hosts.read",
        "proxy_hosts.write",
        "certificates.read",
        "certificates.write",
        "users.manage",
        "roles.manage",
        "audit_logs.read",
        "audit_logs.export",
        "system.settings.manage",
        "sessions.revoke",
        "bot_protection.manage",
        "ai_advisor.read",
        "ai_advisor.request",
        "ai_advisor.approve",
    ];
    for key in permissions {
        sqlx::query(
                "INSERT INTO permissions(id,key) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key=?)",
            )
        .bind(seed_id(pool, "permissions", "key", key, deterministic_id(key)).await?)
        .bind(key)
        .bind(key)
        .execute(pool)
        .await?;
    }

    let now = chrono::Utc::now().to_rfc3339();
    for (slug, name) in [
        ("admin", "Administrator"),
        ("operator", "Operator"),
        ("viewer", "Viewer"),
    ] {
        sqlx::query(
            "INSERT INTO roles(id,slug,name,system_managed,created_at,updated_at) SELECT ?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug=?)",
        )
        .bind(seed_id(pool, "roles", "slug", slug, deterministic_id(slug)).await?)
        .bind(slug)
        .bind(name)
        .bind(1_i64)
        .bind(&now)
        .bind(&now)
        .bind(slug)
        .execute(pool)
        .await?;
    }

    let assignments: [(&str, &[&str]); 3] = [
        ("admin", &permissions),
        (
            "operator",
            &[
                "proxy_hosts.read",
                "proxy_hosts.write",
                "certificates.read",
                "certificates.write",
                "audit_logs.read",
                "ai_advisor.read",
                "ai_advisor.request",
            ],
        ),
        (
            "viewer",
            &[
                "proxy_hosts.read",
                "certificates.read",
                "audit_logs.read",
                "ai_advisor.read",
            ],
        ),
    ];
    for (slug, keys) in assignments {
        for key in keys {
            sqlx::query(
                "INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT r.id,p.id,'',0 FROM roles r,permissions p WHERE r.slug=? AND p.key=? AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id=r.id AND rp.permission_id=p.id AND rp.scope_type='' AND rp.scope_id=0)",
            )
            .bind(slug)
            .bind(*key)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub async fn save_raft_hard_state(
    pool: &DbPool,
    node_id: &str,
    current_term: i64,
    voted_for: Option<&str>,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM raft_hard_state WHERE node_id=?")
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO raft_hard_state(node_id,current_term,voted_for,updated_at) VALUES(?,?,?,?)",
    )
    .bind(node_id)
    .bind(current_term)
    .bind(voted_for)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

pub async fn load_raft_hard_state(
    pool: &DbPool,
    node_id: &str,
) -> Result<Option<RaftHardState>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT node_id,current_term,voted_for,updated_at FROM raft_hard_state WHERE node_id=?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| RaftHardState {
        node_id: row.get("node_id"),
        current_term: row.get("current_term"),
        voted_for: row.get("voted_for"),
        updated_at: row.get("updated_at"),
    }))
}

pub async fn append_raft_log_entry(
    pool: &DbPool,
    node_id: &str,
    log_index: i64,
    term: i64,
    leader_id: i64,
    command_id: &str,
    payload: &str,
) -> Result<(), sqlx::Error> {
    if payload.len() > MAX_RAFT_PAYLOAD_BYTES {
        return Err(sqlx::Error::Protocol(
            "raft payload exceeds configured limit".into(),
        ));
    }
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO raft_log_entries(node_id,log_index,term,leader_id,payload,command_id,created_at) VALUES(?,?,?,?,?,?,?)")
        .bind(node_id)
        .bind(log_index)
    .bind(term)
    .bind(leader_id)
        .bind(payload)
        .bind(command_id)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_raft_log_entries(
    pool: &DbPool,
    node_id: &str,
    from_index: i64,
) -> Result<Vec<RaftLogRecord>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT node_id,log_index,term,leader_id,payload,command_id FROM raft_log_entries WHERE node_id=? AND log_index>=? ORDER BY log_index ASC",
    )
    .bind(node_id)
    .bind(from_index)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RaftLogRecord {
            node_id: row.get("node_id"),
            log_index: row.get("log_index"),
            term: row.get("term"),
            leader_id: row.get("leader_id"),
            payload: row.get("payload"),
            command_id: row.get("command_id"),
        })
        .collect())
}

/// Load receipt provenance recorded atomically by the Raft state machine.
///
/// Receipt rows are independent of the purgeable Raft log, so retries keep
/// returning the first applied index and leader after compaction or restart.
pub async fn load_raft_command_receipt(
    pool: &DbPool,
    command_id: &str,
) -> Result<Option<RaftCommandReceipt>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT receipt.command_id,receipt.log_index,receipt.leader_id,receipt.applied_at,
                result.result_code
         FROM raft_command_receipts receipt
         JOIN raft_command_results result ON result.command_id=receipt.command_id
         WHERE receipt.command_id=?",
    )
    .bind(command_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| RaftCommandReceipt {
        command_id: row.get("command_id"),
        log_index: row.get("log_index"),
        leader_id: row.get("leader_id"),
        applied_at: row.get("applied_at"),
        result_code: row.get("result_code"),
    }))
}

pub async fn list_raft_command_receipts(
    pool: &DbPool,
) -> Result<Vec<RaftCommandReceipt>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT receipt.command_id,receipt.log_index,receipt.leader_id,receipt.applied_at,
                result.result_code
         FROM raft_command_receipts receipt
         JOIN raft_command_results result ON result.command_id=receipt.command_id
         ORDER BY receipt.log_index,receipt.command_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RaftCommandReceipt {
            command_id: row.get("command_id"),
            log_index: row.get("log_index"),
            leader_id: row.get("leader_id"),
            applied_at: row.get("applied_at"),
            result_code: row.get("result_code"),
        })
        .collect())
}

/// Load a bounded newest-first receipt window for Raft snapshot provenance.
///
/// The durable receipt ledger itself is never pruned by this read.
pub async fn list_recent_raft_command_receipts(
    pool: &DbPool,
    limit: usize,
) -> Result<Vec<RaftCommandReceipt>, sqlx::Error> {
    let limit = i64::try_from(limit)
        .map_err(|_| sqlx::Error::Protocol("raft receipt limit is out of range".into()))?;
    let rows = sqlx::query(
        "SELECT receipt.command_id,receipt.log_index,receipt.leader_id,receipt.applied_at,
                result.result_code
         FROM raft_command_receipts receipt
         JOIN raft_command_results result ON result.command_id=receipt.command_id
         ORDER BY receipt.log_index DESC,receipt.command_id DESC
         LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RaftCommandReceipt {
            command_id: row.get("command_id"),
            log_index: row.get("log_index"),
            leader_id: row.get("leader_id"),
            applied_at: row.get("applied_at"),
            result_code: row.get("result_code"),
        })
        .collect())
}

pub async fn truncate_raft_log(
    pool: &DbPool,
    node_id: &str,
    from_index: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM raft_log_entries WHERE node_id=? AND log_index>=?")
        .bind(node_id)
        .bind(from_index)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn purge_raft_log(
    pool: &DbPool,
    node_id: &str,
    through_index: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM raft_log_entries WHERE node_id=? AND log_index<=?")
        .bind(node_id)
        .bind(through_index)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn save_raft_snapshot(
    pool: &DbPool,
    node_id: &str,
    snapshot_index: i64,
    snapshot_term: i64,
    payload: &[u8],
) -> Result<(), sqlx::Error> {
    if payload.len() > MAX_RAFT_PAYLOAD_BYTES {
        return Err(sqlx::Error::Protocol(
            "raft snapshot exceeds configured limit".into(),
        ));
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("DELETE FROM raft_snapshots WHERE node_id=?")
        .bind(node_id)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO raft_snapshots(node_id,snapshot_index,snapshot_term,payload,created_at) VALUES(?,?,?,?,?)")
        .bind(node_id)
        .bind(snapshot_index)
        .bind(snapshot_term)
        .bind(encoded)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_raft_snapshot(
    pool: &DbPool,
    node_id: &str,
) -> Result<Option<RaftSnapshotRecord>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT node_id,snapshot_index,snapshot_term,payload FROM raft_snapshots WHERE node_id=?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        let encoded: String = row.get("payload");
        let payload = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| sqlx::Error::Protocol("invalid raft snapshot encoding".into()))?;
        Ok(RaftSnapshotRecord {
            node_id: row.get("node_id"),
            snapshot_index: row.get("snapshot_index"),
            snapshot_term: row.get("snapshot_term"),
            payload,
        })
    })
    .transpose()
}

pub async fn record_raft_command_id(pool: &DbPool, command_id: &str) -> Result<bool, sqlx::Error> {
    if sqlx::query("SELECT 1 FROM raft_command_ids WHERE command_id=?")
        .bind(command_id)
        .fetch_optional(pool)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO raft_command_ids(command_id,applied_at) VALUES(?,?)")
        .bind(command_id)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(true)
}

/// Apply a committed configuration command in one database transaction.
/// The command ID is recorded in the same transaction as the mutation, so a
/// replay after a crash is a no-op and cannot produce a divergent resource.
pub async fn apply_raft_command(
    pool: &DbPool,
    command: &ConfigCommand,
) -> Result<CommandResult, sqlx::Error> {
    apply_raft_command_inner(pool, command, None).await
}

/// Apply a committed command and persist its immutable receipt provenance in
/// the same transaction as the replicated mutation and command ID.
pub async fn apply_raft_command_with_receipt(
    pool: &DbPool,
    command: &ConfigCommand,
    log_index: i64,
    leader_id: i64,
) -> Result<CommandResult, sqlx::Error> {
    if log_index < 0 || leader_id <= 0 {
        return Err(sqlx::Error::Protocol(
            "invalid raft command receipt provenance".into(),
        ));
    }
    apply_raft_command_inner(pool, command, Some((log_index, leader_id))).await
}

async fn apply_raft_command_inner(
    pool: &DbPool,
    command: &ConfigCommand,
    receipt: Option<(i64, i64)>,
) -> Result<CommandResult, sqlx::Error> {
    command
        .validate()
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let command_id = command.command_id().to_string();
    let mut tx = pool.begin().await?;
    if sqlx::query("SELECT 1 FROM raft_command_ids WHERE command_id=?")
        .bind(&command_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
    {
        let known_result: Option<String> =
            sqlx::query_scalar("SELECT result_code FROM raft_command_results WHERE command_id=?")
                .bind(&command_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let (Some((log_index, leader_id)), Some(result_code)) = (receipt, known_result.as_ref())
        {
            let applied_at = chrono::Utc::now().to_rfc3339();
            sqlx::query(
                "INSERT INTO raft_command_receipts(command_id,log_index,leader_id,applied_at)
                 VALUES(?,?,?,?)
                 ON CONFLICT(command_id) DO NOTHING",
            )
            .bind(&command_id)
            .bind(log_index)
            .bind(leader_id)
            .bind(applied_at)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            CommandResult::from_code(result_code)
                .ok_or_else(|| sqlx::Error::Protocol("invalid raft command result".into()))?;
            return Ok(CommandResult::Duplicate);
        }
        // Legacy command-ID-only rows do not carry enough information to
        // recover the original business result.
        tx.rollback().await?;
        return Ok(CommandResult::Duplicate);
    }

    let result = match command {
        ConfigCommand::Noop { .. } => CommandResult::Applied,
        ConfigCommand::CreateProxyHost { host, .. } => {
            if sqlx::query("SELECT 1 FROM proxy_hosts WHERE id=?")
                .bind(host.id)
                .fetch_optional(&mut *tx)
                .await?
                .is_some()
            {
                CommandResult::IdCollision
            } else if sqlx::query("SELECT 1 FROM proxy_hosts WHERE domain=?")
                .bind(&host.domain)
                .fetch_optional(&mut *tx)
                .await?
                .is_some()
            {
                CommandResult::DuplicateDomain
            } else {
                let now = chrono::Utc::now().to_rfc3339();
                sqlx::query("INSERT INTO proxy_hosts(id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                    .bind(host.id)
                    .bind(&host.name)
                    .bind(&host.domain)
                    .bind(&host.upstream_host)
                    .bind(host.upstream_port as i64)
                    .bind(&host.tls_mode)
                    .bind(host.certificate_id)
                    .bind(host.enabled as i64)
                    .bind(&now)
                    .bind(&now)
                    .execute(&mut *tx)
                    .await?;
                CommandResult::Applied
            }
        }
        ConfigCommand::UpdateProxyHost { host, .. } => {
            if sqlx::query("SELECT 1 FROM proxy_hosts WHERE id=?")
                .bind(host.id)
                .fetch_optional(&mut *tx)
                .await?
                .is_none()
            {
                CommandResult::NotFound
            } else if sqlx::query("SELECT 1 FROM proxy_hosts WHERE domain=? AND id<>?")
                .bind(&host.domain)
                .bind(host.id)
                .fetch_optional(&mut *tx)
                .await?
                .is_some()
            {
                CommandResult::DuplicateDomain
            } else {
                let now = chrono::Utc::now().to_rfc3339();
                sqlx::query("UPDATE proxy_hosts SET name=?,domain=?,upstream_host=?,upstream_port=?,tls_mode=?,certificate_id=?,enabled=?,updated_at=? WHERE id=?")
                    .bind(&host.name)
                    .bind(&host.domain)
                    .bind(&host.upstream_host)
                    .bind(host.upstream_port as i64)
                    .bind(&host.tls_mode)
                    .bind(host.certificate_id)
                    .bind(host.enabled as i64)
                    .bind(&now)
                    .bind(host.id)
                    .execute(&mut *tx)
                    .await?;
                CommandResult::Applied
            }
        }
        ConfigCommand::DeleteProxyHost { host_id, .. } => {
            let deleted = sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
                .bind(host_id)
                .execute(&mut *tx)
                .await?;
            if deleted.rows_affected() == 0 {
                CommandResult::NotFound
            } else {
                sqlx::query(
                    "DELETE FROM role_permissions WHERE scope_type='proxy_host' AND scope_id=?",
                )
                .bind(host_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM host_rate_limit_configs WHERE host_id=?")
                    .bind(host_id)
                    .execute(&mut *tx)
                    .await?;
                CommandResult::Applied
            }
        }
        ConfigCommand::UpdateRuntimePolicy {
            host_id, policy, ..
        } => {
            let now = chrono::Utc::now().to_rfc3339();
            sqlx::query("DELETE FROM host_rate_limit_configs WHERE host_id=?")
                .bind(host_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO host_rate_limit_configs(host_id,capacity,refill_per_second,updated_at) VALUES(?,?,?,?)")
                .bind(host_id)
                .bind(policy.capacity as i64)
                .bind(policy.refill_per_second)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            CommandResult::Applied
        }
    };

    let applied_at = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO raft_command_ids(command_id,applied_at) VALUES(?,?)")
        .bind(&command_id)
        .bind(&applied_at)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO raft_command_results(command_id,result_code) VALUES(?,?)")
        .bind(&command_id)
        .bind(result.code())
        .execute(&mut *tx)
        .await?;
    if let Some((log_index, leader_id)) = receipt {
        sqlx::query(
            "INSERT INTO raft_command_receipts(command_id,log_index,leader_id,applied_at)
             VALUES(?,?,?,?)",
        )
        .bind(command_id)
        .bind(log_index)
        .bind(leader_id)
        .bind(applied_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(result)
}

fn deterministic_id(value: &str) -> i64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    ((hasher.finish() as i64) & i64::MAX).max(1)
}

async fn seed_id(
    pool: &DbPool,
    table: &str,
    key_column: &str,
    key: &str,
    preferred: i64,
) -> Result<i64, sqlx::Error> {
    if sqlx::query("SELECT 1").fetch_optional(pool).await.is_err() {
        return Ok(preferred);
    }
    if sqlx::query(&format!("SELECT id FROM {table} WHERE {key_column}=?"))
        .bind(key)
        .fetch_optional(pool)
        .await?
        .is_some()
    {
        return Ok(preferred);
    }
    if sqlx::query(&format!("SELECT 1 FROM {table} WHERE id=?"))
        .bind(preferred)
        .fetch_optional(pool)
        .await?
        .is_some()
    {
        for _ in 0..32 {
            let candidate = generated_id();
            if sqlx::query(&format!("SELECT 1 FROM {table} WHERE id=?"))
                .bind(candidate)
                .fetch_optional(pool)
                .await?
                .is_none()
            {
                return Ok(candidate);
            }
        }
        return Err(sqlx::Error::Protocol("unable to allocate seed ID".into()));
    }
    Ok(preferred)
}

fn generated_id() -> i64 {
    let bytes = *Uuid::new_v4().as_bytes();
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[..8]);
    (i64::from_be_bytes(raw) & i64::MAX).max(1)
}

pub fn new_proxy_host_id() -> i64 {
    generated_id()
}

fn waf_mode_value(mode: WafMode) -> &'static str {
    match mode {
        WafMode::MonitorOnly => "monitor-only",
        WafMode::Block => "block",
    }
}
fn parse_waf_mode(value: &str) -> WafMode {
    if value == "block" {
        WafMode::Block
    } else {
        WafMode::MonitorOnly
    }
}
fn waf_action_value(action: WafAction) -> &'static str {
    match action {
        WafAction::Inherit => "inherit",
        WafAction::Allow => "allow",
        WafAction::Log => "log",
        WafAction::Block => "block",
    }
}
fn parse_waf_action(value: &str) -> WafAction {
    match value {
        "allow" => WafAction::Allow,
        "log" => WafAction::Log,
        "block" => WafAction::Block,
        _ => WafAction::Inherit,
    }
}
fn rate_limit_action_value(a: RateLimitAction) -> &'static str {
    if matches!(a, RateLimitAction::Block) {
        "block"
    } else {
        "monitor"
    }
}
fn parse_rate_limit_action(v: &str) -> RateLimitAction {
    if v == "block" {
        RateLimitAction::Block
    } else {
        RateLimitAction::Monitor
    }
}
fn parse_rate_limit_scope(v: &str) -> Option<RateLimitKeyScope> {
    (v == "proxy_host_ip").then_some(RateLimitKeyScope::ProxyHostIp)
}
fn validate_rate_limit_config(c: &RateLimitConfig) -> Result<(), sqlx::Error> {
    RateLimitPolicy {
        enabled: c.enabled,
        action: c.action,
        capacity: c.capacity,
        refill_per_second: c.refill_per_second,
        key_scope: c.key_scope,
    }
    .validate()
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))
}
pub async fn get_rate_limit_config(pool: &DbPool) -> Result<RateLimitConfig, sqlx::Error> {
    let row=sqlx::query("SELECT enabled,action,capacity,refill_per_second,key_scope,updated_at FROM rate_limit_config WHERE id=1").fetch_one(pool).await?;
    let scope = parse_rate_limit_scope(&row.get::<String, _>("key_scope"))
        .ok_or_else(|| sqlx::Error::Protocol("invalid rate limit key scope".into()))?;
    let c = RateLimitConfig {
        enabled: row.get::<i64, _>("enabled") != 0,
        action: parse_rate_limit_action(&row.get::<String, _>("action")),
        capacity: row.get::<i64, _>("capacity") as u32,
        refill_per_second: row.get::<f64, _>("refill_per_second"),
        key_scope: scope,
        updated_at: row.get("updated_at"),
    };
    validate_rate_limit_config(&c)?;
    Ok(c)
}
pub async fn update_rate_limit_config(
    pool: &DbPool,
    c: &RateLimitConfig,
) -> Result<u64, sqlx::Error> {
    validate_rate_limit_config(c)?;
    Ok(sqlx::query("UPDATE rate_limit_config SET enabled=?,action=?,capacity=?,refill_per_second=?,key_scope=?,updated_at=? WHERE id=1").bind(c.enabled as i64).bind(rate_limit_action_value(c.action)).bind(c.capacity as i64).bind(c.refill_per_second).bind("proxy_host_ip").bind(chrono::Utc::now().to_rfc3339()).execute(pool).await?.rows_affected())
}

fn bot_mode_value(mode: BotMode) -> &'static str {
    match mode {
        BotMode::Monitor => "monitor",
        BotMode::Challenge => "challenge",
        BotMode::Block => "block",
    }
}
fn parse_bot_mode(value: &str) -> Result<BotMode, sqlx::Error> {
    match value {
        "monitor" => Ok(BotMode::Monitor),
        "challenge" => Ok(BotMode::Challenge),
        "block" => Ok(BotMode::Block),
        _ => Err(sqlx::Error::Protocol("invalid bot mode".into())),
    }
}
fn bot_validation(message: &str) -> sqlx::Error {
    sqlx::Error::Protocol(message.into())
}
fn validate_bot_config(config: &BotConfig) -> Result<(), sqlx::Error> {
    if config.threshold == 0 || config.threshold > 100 {
        return Err(bot_validation("invalid bot threshold"));
    }
    if config.ttl_seconds == 0 || config.ttl_seconds > MAX_TTL_SECONDS {
        return Err(bot_validation("invalid bot ttl"));
    }
    if config.fingerprint_key.is_empty() || config.fingerprint_key.len() > MAX_FIELD_BYTES {
        return Err(bot_validation("invalid bot fingerprint key"));
    }
    Ok(())
}
fn normalize_bot_rule(rule: &BotRule) -> Result<BotRule, sqlx::Error> {
    let category = rule.category.trim().to_ascii_lowercase();
    if category.is_empty() || category.len() > MAX_FIELD_BYTES || rule.weight > 100 {
        return Err(bot_validation("invalid bot rule"));
    }
    let ua = rule
        .trusted_user_agent
        .as_ref()
        .map(|v| v.trim().to_string());
    let domain = rule
        .trusted_domain
        .as_ref()
        .map(|v| v.trim().to_ascii_lowercase());
    if ua
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > MAX_FIELD_BYTES)
        || domain
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > MAX_FIELD_BYTES)
    {
        return Err(bot_validation("invalid bot rule predicate"));
    }
    if category == "trusted_crawler" && (ua.is_none() || domain.is_none()) {
        return Err(bot_validation("trusted crawler requires predicates"));
    }
    Ok(BotRule {
        category,
        weight: rule.weight,
        trusted_user_agent: ua,
        trusted_domain: domain,
        enabled: rule.enabled,
    })
}

pub async fn get_bot_config(pool: &DbPool) -> Result<BotConfig, sqlx::Error> {
    let row =
        sqlx::query("SELECT mode,threshold,ttl_seconds,fingerprint_key FROM bot_config WHERE id=1")
            .fetch_one(pool)
            .await?;
    let key: String = row.get("fingerprint_key");
    let key = if key.is_empty() {
        let mut generated = Vec::with_capacity(32);
        generated.extend_from_slice(Uuid::new_v4().as_bytes());
        generated.extend_from_slice(Uuid::new_v4().as_bytes());
        let encoded = hex::encode(&generated);
        sqlx::query("UPDATE bot_config SET fingerprint_key=?,updated_at=? WHERE id=1 AND fingerprint_key=''")
            .bind(encoded).bind(chrono::Utc::now().to_rfc3339()).execute(pool).await?;
        let stored: String =
            sqlx::query_scalar("SELECT fingerprint_key FROM bot_config WHERE id=1")
                .fetch_one(pool)
                .await?;
        hex::decode(stored).map_err(|_| bot_validation("invalid stored fingerprint key"))?
    } else {
        hex::decode(key).map_err(|_| bot_validation("invalid stored fingerprint key"))?
    };
    let config = BotConfig {
        mode: parse_bot_mode(&row.get::<String, _>("mode"))?,
        threshold: row.get::<i64, _>("threshold") as u16,
        ttl_seconds: row.get::<i64, _>("ttl_seconds") as u64,
        fingerprint_key: key,
    };
    validate_bot_config(&config)?;
    Ok(config)
}
pub async fn update_bot_config(pool: &DbPool, config: &BotConfig) -> Result<u64, sqlx::Error> {
    validate_bot_config(config)?;
    Ok(sqlx::query("UPDATE bot_config SET mode=?,threshold=?,ttl_seconds=?,fingerprint_key=?,updated_at=? WHERE id=1").bind(bot_mode_value(config.mode)).bind(config.threshold as i64).bind(config.ttl_seconds as i64).bind(hex::encode(&config.fingerprint_key)).bind(chrono::Utc::now().to_rfc3339()).execute(pool).await?.rows_affected())
}
fn bot_rule_from_row(row: &sqlx::any::AnyRow) -> BotRule {
    BotRule {
        category: row.get("category"),
        weight: row.get::<i64, _>("weight") as u16,
        trusted_user_agent: row.get("trusted_user_agent"),
        trusted_domain: row.get("trusted_domain"),
        enabled: row.get::<i64, _>("enabled") != 0,
    }
}
pub async fn list_bot_rules(pool: &DbPool) -> Result<Vec<BotRule>, sqlx::Error> {
    let rows = sqlx::query("SELECT category,weight,trusted_user_agent,trusted_domain,enabled FROM bot_rules ORDER BY id LIMIT ?")
        .bind(MAX_RULES as i64 + 1).fetch_all(pool).await?;
    if rows.len() > MAX_RULES {
        return Err(bot_validation("too many bot rules"));
    }
    Ok(rows.iter().map(bot_rule_from_row).collect())
}
pub async fn list_bot_rule_records(pool: &DbPool) -> Result<Vec<(i64, BotRule)>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,category,weight,trusted_user_agent,trusted_domain,enabled FROM bot_rules ORDER BY id LIMIT ?")
        .bind(MAX_RULES as i64 + 1).fetch_all(pool).await?;
    if rows.len() > MAX_RULES {
        return Err(bot_validation("too many bot rules"));
    }
    Ok(rows
        .iter()
        .map(|row| (row.get("id"), bot_rule_from_row(row)))
        .collect())
}
pub async fn insert_bot_rule(pool: &DbPool, rule: &BotRule) -> Result<i64, sqlx::Error> {
    let rule = normalize_bot_rule(rule)?;
    let mut tx = pool.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bot_rules")
        .fetch_one(&mut *tx)
        .await?;
    if count as usize >= MAX_RULES {
        return Err(bot_validation("too many bot rules"));
    }
    let trusted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bot_rules WHERE enabled=1 AND (trusted_user_agent IS NOT NULL OR trusted_domain IS NOT NULL)").fetch_one(&mut *tx).await?;
    if rule.enabled
        && (rule.trusted_user_agent.is_some() || rule.trusted_domain.is_some())
        && trusted as usize >= MAX_TRUSTED_RULES
    {
        return Err(bot_validation("too many trusted bot rules"));
    }
    let id = generated_id();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO bot_rules(id,category,weight,trusted_user_agent,trusted_domain,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(&rule.category).bind(rule.weight as i64).bind(&rule.trusted_user_agent).bind(&rule.trusted_domain).bind(rule.enabled as i64).bind(&now).bind(&now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}
pub async fn update_bot_rule(pool: &DbPool, id: i64, rule: &BotRule) -> Result<u64, sqlx::Error> {
    let rule = normalize_bot_rule(rule)?;
    let mut tx = pool.begin().await?;
    if rule.enabled && (rule.trusted_user_agent.is_some() || rule.trusted_domain.is_some()) {
        let trusted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bot_rules WHERE id<>? AND enabled=1 AND (trusted_user_agent IS NOT NULL OR trusted_domain IS NOT NULL)").bind(id).fetch_one(&mut *tx).await?;
        if trusted as usize >= MAX_TRUSTED_RULES {
            return Err(bot_validation("too many trusted bot rules"));
        }
    }
    let changed = sqlx::query("UPDATE bot_rules SET category=?,weight=?,trusted_user_agent=?,trusted_domain=?,enabled=?,updated_at=? WHERE id=?").bind(&rule.category).bind(rule.weight as i64).bind(&rule.trusted_user_agent).bind(&rule.trusted_domain).bind(rule.enabled as i64).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(changed)
}
pub async fn delete_bot_rule(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM bot_rules WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected())
}
pub async fn restore_bot_rule(pool: &DbPool, id: i64, rule: &BotRule) -> Result<(), sqlx::Error> {
    let rule = normalize_bot_rule(rule)?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO bot_rules(id,category,weight,trusted_user_agent,trusted_domain,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(rule.category).bind(rule.weight as i64).bind(rule.trusted_user_agent).bind(rule.trusted_domain).bind(rule.enabled as i64).bind(&now).bind(&now).execute(pool).await?;
    Ok(())
}

/// Replace the persisted bot policy in one transaction. All validation is
/// performed before opening the transaction so malformed imports cannot leave
/// a partially applied policy behind.
pub async fn replace_bot_policy(
    pool: &DbPool,
    config: &BotConfig,
    rules: &[BotRule],
) -> Result<(), sqlx::Error> {
    validate_bot_config(config)?;
    if rules.len() > MAX_RULES
        || rules
            .iter()
            .filter(|r| r.enabled && (r.trusted_user_agent.is_some() || r.trusted_domain.is_some()))
            .count()
            > MAX_TRUSTED_RULES
    {
        return Err(bot_validation("too many bot rules"));
    }
    let normalized = rules
        .iter()
        .map(normalize_bot_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE bot_config SET mode=?,threshold=?,ttl_seconds=?,fingerprint_key=?,updated_at=? WHERE id=1")
        .bind(bot_mode_value(config.mode)).bind(config.threshold as i64).bind(config.ttl_seconds as i64).bind(hex::encode(&config.fingerprint_key)).bind(chrono::Utc::now().to_rfc3339()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM bot_rules")
        .execute(&mut *tx)
        .await?;
    for rule in normalized {
        let id = generated_id();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO bot_rules(id,category,weight,trusted_user_agent,trusted_domain,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(rule.category).bind(rule.weight as i64).bind(rule.trusted_user_agent).bind(rule.trusted_domain).bind(rule.enabled as i64).bind(&now).bind(&now).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

fn waf_rule_from_row(row: &sqlx::any::AnyRow) -> WafRule {
    WafRule {
        id: row.get("id"),
        name: row.get("name"),
        source: row.get("source"),
        category: row.get("category"),
        severity: row.get("severity"),
        enabled: row.get::<i64, _>("enabled") != 0,
        action: parse_waf_action(&row.get::<String, _>("action")),
        matcher_json: row.get("matcher_json"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

pub async fn get_waf_config(pool: &DbPool) -> Result<WafConfig, sqlx::Error> {
    let row = sqlx::query("SELECT mode,updated_at FROM waf_config WHERE id=1")
        .fetch_one(pool)
        .await?;
    Ok(WafConfig {
        mode: parse_waf_mode(&row.get::<String, _>("mode")),
        updated_at: row.get("updated_at"),
    })
}

pub async fn update_waf_mode(pool: &DbPool, mode: WafMode) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("UPDATE waf_config SET mode=?,updated_at=? WHERE id=1")
            .bind(waf_mode_value(mode))
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn list_waf_rules(pool: &DbPool) -> Result<Vec<WafRule>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,name,source,category,severity,enabled,action,matcher_json,created_at,updated_at FROM waf_rules ORDER BY id").fetch_all(pool).await?;
    Ok(rows.iter().map(waf_rule_from_row).collect())
}

pub async fn insert_waf_rule(pool: &DbPool, rule: &WafRule) -> Result<i64, sqlx::Error> {
    let id = if rule.id > 0 { rule.id } else { generated_id() };
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO waf_rules(id,name,source,category,severity,enabled,action,matcher_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(id).bind(&rule.name).bind(&rule.source).bind(&rule.category).bind(&rule.severity)
        .bind(rule.enabled as i64).bind(waf_action_value(rule.action)).bind(&rule.matcher_json).bind(&now).bind(&now).execute(pool).await?;
    Ok(id)
}

pub async fn update_waf_rule(pool: &DbPool, id: i64, rule: &WafRule) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE waf_rules SET name=?,category=?,severity=?,enabled=?,action=?,matcher_json=?,updated_at=? WHERE id=? AND source='custom'")
        .bind(&rule.name).bind(&rule.category).bind(&rule.severity).bind(rule.enabled as i64).bind(waf_action_value(rule.action)).bind(&rule.matcher_json).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(pool).await?.rows_affected())
}

pub async fn delete_waf_rule(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM waf_rules WHERE id=? AND source='custom'")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn seed_builtin_waf_rules(pool: &DbPool) -> Result<(), sqlx::Error> {
    let rules = [
        (
            "builtin-sqli",
            "SQL injection",
            "sqli",
            "high",
            r#"{"field":"any","builtin":"sqli"}"#,
        ),
        (
            "builtin-xss",
            "Cross-site scripting",
            "xss",
            "high",
            r#"{"field":"any","builtin":"xss"}"#,
        ),
        (
            "builtin-path-traversal",
            "Path traversal",
            "path_traversal",
            "high",
            r#"{"field":"path","builtin":"path_traversal"}"#,
        ),
        (
            "builtin-command-injection",
            "Command injection",
            "command_injection",
            "critical",
            r#"{"field":"any","builtin":"command_injection"}"#,
        ),
    ];
    for (key, name, category, severity, matcher) in rules {
        if sqlx::query("SELECT 1 FROM waf_rules WHERE builtin_key=?")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .is_some()
        {
            continue;
        }
        let id = generated_id();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO waf_rules(id,name,source,builtin_key,category,severity,enabled,action,matcher_json,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'inherit',?,?,?)")
            .bind(id).bind(name).bind("builtin").bind(key).bind(category).bind(severity).bind(matcher).bind(&now).bind(&now).execute(pool).await?;
    }
    Ok(())
}

fn is_duplicate_column(error: &sqlx::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("duplicate column")
        || message.contains("already exists")
        || message.contains("1060")
        || message.contains("42701")
}

pub async fn set_acme_secret_ref(
    pool: &DbPool,
    certificate_id: i64,
    secret_ref: &str,
) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("UPDATE acme_certificates SET secret_ref=? WHERE certificate_id=?")
            .bind(secret_ref)
            .bind(certificate_id)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
pub async fn acme_secret_ref(
    pool: &DbPool,
    certificate_id: i64,
) -> Result<Option<String>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT secret_ref FROM acme_certificates WHERE certificate_id=?")
            .bind(certificate_id)
            .fetch_optional(pool)
            .await?
            .and_then(|r| r.get::<Option<String>, _>("secret_ref")),
    )
}

fn acme_status_from_row(r: &sqlx::any::AnyRow) -> Result<AcmeStatus, sqlx::Error> {
    let environment = match r.get::<String, _>("environment").as_str() {
        "staging" => AcmeEnvironment::Staging,
        "production" => AcmeEnvironment::Production,
        value => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid ACME environment: {value}"
            )))
        }
    };
    let challenge = match r.get::<String, _>("challenge").as_str() {
        "http01" => AcmeChallenge::Http01,
        "cloudflare_dns01" => AcmeChallenge::CloudflareDns01,
        value => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid ACME challenge: {value}"
            )))
        }
    };
    let hostnames = serde_json::from_str(&r.get::<String, _>("hostnames"))
        .map_err(|e| sqlx::Error::Protocol(format!("invalid certificate hostnames: {e}")))?;
    Ok(AcmeStatus {
        certificate_id: r.get("certificate_id"),
        environment,
        challenge,
        hostnames,
        renewal_state: r.get("renewal_state"),
        next_renewal_at: r.get("next_renewal_at"),
        last_attempt_at: r.get("last_attempt_at"),
        last_error_code: r.get("last_error_code"),
    })
}

pub async fn insert_acme_certificate(
    pool: &DbPool,
    certificate_id: i64,
    request: &AcmeRequest,
) -> Result<AcmeStatus, sqlx::Error> {
    let request = request
        .clone()
        .normalized()
        .map_err(sqlx::Error::Protocol)?;
    let environment = match request.environment {
        AcmeEnvironment::Staging => "staging",
        AcmeEnvironment::Production => "production",
    };
    let challenge = match request.challenge {
        AcmeChallenge::Http01 => "http01",
        AcmeChallenge::CloudflareDns01 => "cloudflare_dns01",
    };
    let hosts = serde_json::to_string(&request.hostnames)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let mut tx = pool.begin().await?;
    let exists = sqlx::query("SELECT id FROM certificates WHERE id=?")
        .bind(certificate_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(sqlx::Error::RowNotFound);
    }
    sqlx::query("INSERT INTO acme_certificates(certificate_id,environment,challenge,renewal_state,next_renewal_at,last_attempt_at,last_error_code) VALUES(?,?,?, 'pending', NULL, NULL, NULL)")
        .bind(certificate_id).bind(environment).bind(challenge).execute(&mut *tx).await?;
    sqlx::query("UPDATE certificates SET covered_hostnames=? WHERE id=?")
        .bind(hosts)
        .bind(certificate_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    get_acme_status(pool, certificate_id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn update_acme_status(
    pool: &DbPool,
    certificate_id: i64,
    renewal_state: &str,
    next_renewal_at: Option<&str>,
    last_attempt_at: Option<&str>,
    last_error_code: Option<&str>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE acme_certificates SET renewal_state=?,next_renewal_at=?,last_attempt_at=?,last_error_code=? WHERE certificate_id=?")
        .bind(renewal_state).bind(next_renewal_at).bind(last_attempt_at).bind(last_error_code).bind(certificate_id).execute(pool).await?.rows_affected())
}

pub async fn get_acme_status(
    pool: &DbPool,
    certificate_id: i64,
) -> Result<Option<AcmeStatus>, sqlx::Error> {
    let row = sqlx::query("SELECT a.certificate_id,a.environment,a.challenge,c.covered_hostnames AS hostnames,a.renewal_state,a.next_renewal_at,a.last_attempt_at,a.last_error_code FROM acme_certificates a JOIN certificates c ON c.id=a.certificate_id WHERE a.certificate_id=?")
        .bind(certificate_id).fetch_optional(pool).await?;
    row.as_ref().map(acme_status_from_row).transpose()
}

pub async fn list_due_acme_certificates(
    pool: &DbPool,
    at: &str,
) -> Result<Vec<AcmeStatus>, sqlx::Error> {
    let rows = sqlx::query("SELECT a.certificate_id,a.environment,a.challenge,c.covered_hostnames AS hostnames,a.renewal_state,a.next_renewal_at,a.last_attempt_at,a.last_error_code FROM acme_certificates a JOIN certificates c ON c.id=a.certificate_id WHERE a.next_renewal_at IS NOT NULL AND a.next_renewal_at<=? ORDER BY a.next_renewal_at,a.certificate_id")
        .bind(at).fetch_all(pool).await?;
    rows.iter().map(acme_status_from_row).collect()
}
pub async fn user_count(pool: &DbPool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) c FROM users")
        .fetch_one(pool)
        .await?
        .get("c"))
}
pub async fn insert_user(
    pool: &DbPool,
    email: &str,
    hash: &str,
    role: &str,
) -> Result<User, sqlx::Error> {
    let role_name = role;
    if Role::parse(role_name).is_none()
        && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
            .bind(role_name)
            .fetch_optional(pool)
            .await?
            .is_none()
    {
        return Err(sqlx::Error::Protocol("invalid role".into()));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,role,created_at,disabled) VALUES(?,?,?,?,?,0)",
    )
    .bind(id)
    .bind(email)
    .bind(hash)
    .bind(role_name)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(User {
        id,
        email: email.into(),
        role: role_name.into(),
        created_at: now,
        disabled: false,
        preferred_locale: None,
    })
}

/// Create the first administrator while holding SQLite's write lock.
/// Returning `Ok(None)` means another request completed setup first.
pub async fn insert_initial_admin(
    pool: &DbPool,
    email: &str,
    hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    // Lock the single sentinel row. UPDATE obtains a row/write lock on
    // PostgreSQL, MySQL, and SQLite without backend-specific syntax.
    sqlx::query("UPDATE setup_lock SET id=id WHERE id=1")
        .execute(&mut *conn)
        .await?;
    let count = sqlx::query("SELECT COUNT(*) c FROM users")
        .fetch_one(&mut *conn)
        .await?
        .get::<i64, _>("c");
    if count != 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Ok(None);
    }
    let role = "admin";
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    let result = sqlx::query(
        "INSERT INTO users(id,email,password_hash,role,created_at,disabled) VALUES(?,?,?,?,?,0)",
    )
    .bind(id)
    .bind(email)
    .bind(hash)
    .bind(role)
    .bind(&now)
    .execute(&mut *conn)
    .await;
    match result {
        Ok(_) => {}
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(Some(User {
        id,
        email: email.into(),
        role: role.into(),
        created_at: now,
        disabled: false,
        preferred_locale: None,
    }))
}
pub async fn find_user(pool: &DbPool, email: &str) -> Result<Option<(User, String)>, sqlx::Error> {
    let r = sqlx::query("SELECT id,email,password_hash,role,created_at,disabled,preferred_locale FROM users WHERE email=? AND disabled=0")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(r.map(|x| {
        (
            User {
                id: x.get("id"),
                email: x.get("email"),
                role: x.get("role"),
                created_at: x.get("created_at"),
                disabled: x.get::<i64, _>("disabled") != 0,
                preferred_locale: x.get("preferred_locale"),
            },
            x.get("password_hash"),
        )
    }))
}
pub async fn find_user_by_session(pool: &DbPool, hash: &str) -> Result<Option<User>, sqlx::Error> {
    let r=sqlx::query("SELECT u.id,u.email,u.role,u.created_at,u.disabled,u.preferred_locale FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.disabled=0").bind(hash).bind(chrono::Utc::now().to_rfc3339()).fetch_optional(pool).await?;
    Ok(r.map(|x| User {
        id: x.get("id"),
        email: x.get("email"),
        role: x.get("role"),
        created_at: x.get("created_at"),
        disabled: x.get::<i64, _>("disabled") != 0,
        preferred_locale: x.get("preferred_locale"),
    }))
}

pub async fn list_users(pool: &DbPool) -> Result<Vec<User>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,email,role,created_at,disabled,preferred_locale FROM users ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|x| User {
            id: x.get("id"),
            email: x.get("email"),
            role: x.get("role"),
            created_at: x.get("created_at"),
            disabled: x.get::<i64, _>("disabled") != 0,
            preferred_locale: x.get("preferred_locale"),
        })
        .collect())
}

fn role_detail_from_row(
    row: &sqlx::any::AnyRow,
    permissions: Vec<String>,
    scopes: Vec<RolePermissionScope>,
) -> RoleDetail {
    RoleDetail {
        id: row.get("id"),
        slug: row.get("slug"),
        name: row.get("name"),
        description: row.get("description"),
        system_managed: row.get::<i64, _>("system_managed") != 0,
        permissions,
        scopes,
    }
}

async fn role_detail(pool: &DbPool, row: sqlx::any::AnyRow) -> Result<RoleDetail, sqlx::Error> {
    let permissions = role_permissions(pool, row.get("id")).await?;
    let scopes = role_permission_scopes(pool, row.get("id")).await?;
    Ok(role_detail_from_row(&row, permissions, scopes))
}

pub async fn role_permissions(pool: &DbPool, role_id: i64) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT p.key FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? AND rp.scope_type='' AND rp.scope_id=0 ORDER BY p.key").bind(role_id).fetch_all(pool).await
}

pub async fn role_permission_scopes(
    pool: &DbPool,
    role_id: i64,
) -> Result<Vec<RolePermissionScope>, sqlx::Error> {
    let rows = sqlx::query("SELECT p.key AS permission, rp.scope_id FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? AND rp.scope_type='proxy_host' ORDER BY p.key,rp.scope_id")
        .bind(role_id).fetch_all(pool).await?;
    let mut scopes: Vec<RolePermissionScope> = Vec::new();
    for row in rows {
        let permission: String = row.get("permission");
        let host_id: i64 = row.get("scope_id");
        if let Some(index) = scopes.iter().position(|s| s.permission == permission) {
            scopes[index].proxy_host_ids.push(host_id);
        } else {
            scopes.push(RolePermissionScope {
                permission,
                proxy_host_ids: vec![host_id],
            });
        }
    }
    Ok(scopes)
}

fn normalize_scopes(
    scopes: &[RolePermissionScope],
) -> Result<Vec<RolePermissionScope>, sqlx::Error> {
    let mut normalized = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !matches!(
            scope.permission.as_str(),
            "proxy_hosts.read" | "proxy_hosts.write"
        ) || scope.proxy_host_ids.is_empty()
        {
            return Err(sqlx::Error::Protocol(
                "invalid role scope permission".into(),
            ));
        }
        let mut ids = scope.proxy_host_ids.clone();
        ids.sort_unstable();
        ids.dedup();
        if ids.iter().any(|id| *id <= 0) {
            return Err(sqlx::Error::Protocol("invalid role scope host id".into()));
        }
        normalized.push(RolePermissionScope {
            permission: scope.permission.clone(),
            proxy_host_ids: ids,
        });
    }
    normalized.sort_by(|a, b| a.permission.cmp(&b.permission));
    if normalized
        .windows(2)
        .any(|pair| pair[0].permission == pair[1].permission)
    {
        return Err(sqlx::Error::Protocol(
            "duplicate role scope permission".into(),
        ));
    }
    Ok(normalized)
}

async fn replace_scopes_tx<'a>(
    tx: &mut sqlx::Transaction<'a, sqlx::Any>,
    role_id: i64,
    scopes: &[RolePermissionScope],
) -> Result<(), sqlx::Error> {
    let scopes = normalize_scopes(scopes)?;
    for scope in &scopes {
        for host_id in &scope.proxy_host_ids {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM proxy_hosts WHERE id=?")
                .bind(host_id)
                .fetch_optional(&mut **tx)
                .await?;
            if exists.is_none() {
                return Err(sqlx::Error::Protocol("unknown proxy host id".into()));
            }
            sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,id,'proxy_host',? FROM permissions WHERE key=?")
                .bind(role_id).bind(host_id).bind(&scope.permission).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub async fn replace_role_scopes(
    pool: &DbPool,
    role_id: i64,
    scopes: &[RolePermissionScope],
) -> Result<RoleDetail, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query("SELECT system_managed FROM roles WHERE id=?")
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    if row.get::<i64, _>("system_managed") != 0 {
        return Err(sqlx::Error::Protocol(
            "system-managed role cannot be mutated".into(),
        ));
    }
    normalize_scopes(scopes)?;
    sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='proxy_host'")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    replace_scopes_tx(&mut tx, role_id, scopes).await?;
    tx.commit().await?;
    get_role(pool, role_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn list_roles(pool: &DbPool) -> Result<Vec<RoleDetail>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,slug,name,description,system_managed FROM roles ORDER BY id")
        .fetch_all(pool)
        .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push(role_detail(pool, row).await?);
    }
    Ok(result)
}

pub async fn role_by_slug(pool: &DbPool, slug: &str) -> Result<Option<RoleDetail>, sqlx::Error> {
    match sqlx::query("SELECT id,slug,name,description,system_managed FROM roles WHERE slug=?")
        .bind(slug)
        .fetch_optional(pool)
        .await?
    {
        Some(row) => Ok(Some(role_detail(pool, row).await?)),
        None => Ok(None),
    }
}

pub async fn get_role(pool: &DbPool, id: i64) -> Result<Option<RoleDetail>, sqlx::Error> {
    match sqlx::query("SELECT id,slug,name,description,system_managed FROM roles WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
    {
        Some(row) => Ok(Some(role_detail(pool, row).await?)),
        None => Ok(None),
    }
}

pub async fn insert_role(
    pool: &DbPool,
    slug: &str,
    name: &str,
    description: &str,
) -> Result<RoleDetail, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query(
        "INSERT INTO roles(id,slug,name,description,created_at,updated_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(id)
    .bind(slug)
    .bind(name)
    .bind(description)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;
    get_role(pool, id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// Atomically creates a role and installs its global permissions.
pub async fn insert_role_with_permissions(
    pool: &DbPool,
    slug: &str,
    name: &str,
    description: &str,
    keys: &[&str],
) -> Result<RoleDetail, sqlx::Error> {
    insert_role_with_permissions_and_scopes(pool, slug, name, description, keys, &[]).await
}

pub async fn insert_role_with_permissions_and_scopes(
    pool: &DbPool,
    slug: &str,
    name: &str,
    description: &str,
    keys: &[&str],
    scopes: &[RolePermissionScope],
) -> Result<RoleDetail, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query(
        "INSERT INTO roles(id,slug,name,description,created_at,updated_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(id)
    .bind(slug)
    .bind(name)
    .bind(description)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    for key in keys {
        if sqlx::query("SELECT 1 FROM permissions WHERE key=?")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
        {
            return Err(sqlx::Error::Protocol("invalid permission".into()));
        }
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,id,'',0 FROM permissions WHERE key=?")
            .bind(id).bind(key).execute(&mut *tx).await?;
    }
    replace_scopes_tx(&mut tx, id, scopes).await?;
    tx.commit().await?;
    get_role(pool, id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// Atomically updates role metadata and replaces its global permissions.
pub async fn update_role_with_permissions(
    pool: &DbPool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    keys: Option<&[&str]>,
) -> Result<Option<RoleDetail>, sqlx::Error> {
    update_role_with_permissions_and_scopes(pool, id, name, description, keys, None).await
}

pub async fn update_role_with_permissions_and_scopes(
    pool: &DbPool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    keys: Option<&[&str]>,
    scopes: Option<&[RolePermissionScope]>,
) -> Result<Option<RoleDetail>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(current) = current else {
        tx.rollback().await?;
        return Ok(None);
    };
    if current.get::<i64, _>("system_managed") != 0 {
        tx.rollback().await?;
        return Err(sqlx::Error::Protocol(
            "system-managed role cannot be mutated".into(),
        ));
    }
    sqlx::query("UPDATE roles SET name=COALESCE(?,name),description=COALESCE(?,description),updated_at=? WHERE id=?")
        .bind(name).bind(description).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(&mut *tx).await?;
    if let Some(keys) = keys {
        for key in keys {
            if sqlx::query("SELECT 1 FROM permissions WHERE key=?")
                .bind(key)
                .fetch_optional(&mut *tx)
                .await?
                .is_none()
            {
                return Err(sqlx::Error::Protocol("invalid permission".into()));
            }
        }
        sqlx::query(
            "DELETE FROM role_permissions WHERE role_id=? AND scope_type='' AND scope_id=0",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        for key in keys {
            sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,id,'',0 FROM permissions WHERE key=?").bind(id).bind(key).execute(&mut *tx).await?;
        }
    }
    if let Some(scopes) = scopes {
        normalize_scopes(scopes)?;
        sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='proxy_host'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        replace_scopes_tx(&mut tx, id, scopes).await?;
    }
    tx.commit().await?;
    get_role(pool, id).await
}

pub async fn update_role(
    pool: &DbPool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<Option<RoleDetail>, sqlx::Error> {
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(current) = current else {
        return Ok(None);
    };
    if current.get::<i64, _>("system_managed") != 0 {
        return Err(sqlx::Error::Protocol(
            "system-managed role cannot be mutated".into(),
        ));
    }
    sqlx::query("UPDATE roles SET name=COALESCE(?,name),description=COALESCE(?,description),updated_at=? WHERE id=?").bind(name).bind(description).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(pool).await?;
    get_role(pool, id).await
}

pub async fn set_role_permissions(
    pool: &DbPool,
    role_id: i64,
    keys: &[&str],
) -> Result<RoleDetail, sqlx::Error> {
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?")
        .bind(role_id)
        .fetch_optional(pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    if current.get::<i64, _>("system_managed") != 0 {
        return Err(sqlx::Error::Protocol(
            "system-managed role cannot be mutated".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    for key in keys {
        if sqlx::query("SELECT 1 FROM permissions WHERE key=?")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
        {
            return Err(sqlx::Error::Protocol(format!("invalid permission: {key}")));
        }
    }
    sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='' AND scope_id=0")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    for key in keys {
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,id,'',0 FROM permissions WHERE key=?").bind(role_id).bind(key).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    get_role(pool, role_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn delete_role(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;

    let row = match sqlx::query("SELECT slug,system_managed FROM roles WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(row) => row,
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    let Some(row) = row else {
        if let Err(error) = sqlx::query("COMMIT").execute(&mut *conn).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
        return Ok(0);
    };
    if row.get::<i64, _>("system_managed") != 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(sqlx::Error::Protocol(
            "system-managed role cannot be deleted".into(),
        ));
    }
    let slug: String = row.get("slug");
    let assigned = match sqlx::query("SELECT 1 FROM users WHERE role=? LIMIT 1")
        .bind(&slug)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(row) => row.is_some(),
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    if assigned {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(sqlx::Error::Protocol("role is assigned to users".into()));
    }
    let changed = match sqlx::query("DELETE FROM roles WHERE id=?")
        .bind(id)
        .execute(&mut *conn)
        .await
    {
        Ok(result) => result.rows_affected(),
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    if let Err(error) = sqlx::query("COMMIT").execute(&mut *conn).await {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(error);
    }
    Ok(changed)
}

pub async fn user_has_permission(
    pool: &DbPool,
    user_id: i64,
    key: &str,
    scope: Option<(&str, i64)>,
) -> Result<bool, sqlx::Error> {
    let allowed = match scope {
        None => sqlx::query(
            "SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND rp.scope_type='' AND rp.scope_id=0 LIMIT 1",
        )
        .bind(user_id)
        .bind(key)
        .fetch_optional(pool)
        .await?
        .is_some(),
        Some(("proxy_host", host_id)) => sqlx::query(
            "SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND ((rp.scope_type='' AND rp.scope_id=0) OR (rp.scope_type=? AND rp.scope_id=?)) LIMIT 1",
        )
        .bind(user_id)
        .bind(key)
        .bind("proxy_host")
        .bind(host_id)
        .fetch_optional(pool)
        .await?
        .is_some(),
        // Scope types are an allow-list. Unknown values must never broaden access.
        Some(_) => false,
    };
    Ok(allowed)
}

pub async fn user_has_scoped_permission(
    pool: &DbPool,
    user_id: i64,
    key: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND rp.scope_type='proxy_host' AND rp.scope_id IS NOT NULL LIMIT 1")
        .bind(user_id).bind(key).fetch_optional(pool).await?.is_some())
}

enum AuditFilter {
    Text(String),
    Actor(i64),
}

fn sensitive_audit_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace(['-', ' '], "_");
    [
        "password",
        "token",
        "secret",
        "private_key",
        "privatekey",
        "credential",
        "request_body",
        "requestbody",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if sensitive_audit_key(key) {
                    *value = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        _ => {}
    }
}

/// Sanitize legacy/free-form audit details at the read boundary. Audit rows
/// may have been written by older callers, so API serialization must remain
/// safe even when storage contains credentials or request bodies.
pub fn sanitize_audit_details(details: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(details) {
        redact_json(&mut value);
        return serde_json::to_string(&value).unwrap_or_else(|_| "[REDACTED]".into());
    }
    let mut output = details.to_owned();
    let lower = output.to_ascii_lowercase();
    let mut replacements = Vec::new();
    for key in [
        "password",
        "token",
        "secret",
        "private_key",
        "private-key",
        "credential",
        "request_body",
        "request-body",
    ] {
        let mut start = 0;
        while let Some(relative) = lower[start..].find(key) {
            let key_start = start + relative;
            let after_key = key_start + key.len();
            let bytes = lower.as_bytes();
            if after_key < bytes.len() && (bytes[after_key] == b'=' || bytes[after_key] == b':') {
                let value_start = after_key + 1;
                let value_end = output[value_start..]
                    .find([';', '&', '\n', ',', '}'])
                    .map(|offset| value_start + offset)
                    .unwrap_or(output.len());
                replacements.push((value_start, value_end));
            }
            start = after_key;
            if start >= lower.len() {
                break;
            }
        }
    }
    // A value may itself contain another sensitive key (for example
    // `password=password=...`). Coalesce ranges first so reverse replacement
    // never attempts to edit an already-replaced/overlapping span.
    replacements.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::with_capacity(replacements.len());
    for (start, end) in replacements {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    for (start, end) in merged.into_iter().rev() {
        output.replace_range(start..end, "[REDACTED]");
    }
    output
}

fn audit_where(query: &AuditLogQuery) -> (String, Vec<AuditFilter>) {
    let mut predicates = Vec::new();
    let mut filters = Vec::new();
    if let Some(event) = query.event.as_deref() {
        predicates.push("a.event = ?");
        filters.push(AuditFilter::Text(event.to_owned()));
    }
    if let Some(actor_id) = query.actor_id {
        predicates.push("a.user_id = ?");
        filters.push(AuditFilter::Actor(actor_id));
    }
    if let Some(from) = query.from.as_deref() {
        predicates.push("a.created_at >= ?");
        filters.push(AuditFilter::Text(from.to_owned()));
    }
    if let Some(to) = query.to.as_deref() {
        predicates.push("a.created_at <= ?");
        filters.push(AuditFilter::Text(to.to_owned()));
    }
    if let Some(q) = query.q.as_deref() {
        predicates.push("(a.event LIKE ? OR a.details LIKE ?)");
        let pattern = format!("%{q}%");
        filters.push(AuditFilter::Text(pattern.clone()));
        filters.push(AuditFilter::Text(pattern));
    }
    let where_clause = if predicates.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", predicates.join(" AND "))
    };
    (where_clause, filters)
}

pub async fn list_audit_logs(
    pool: &DbPool,
    query: &AuditLogQuery,
) -> Result<AuditLogPage, sqlx::Error> {
    let (where_clause, filters) = audit_where(query);
    let count_sql = format!(
        "SELECT COUNT(*) AS c FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id{where_clause}"
    );
    let mut count = sqlx::query(&count_sql);
    for filter in &filters {
        count = match filter {
            AuditFilter::Text(value) => count.bind(value),
            AuditFilter::Actor(value) => count.bind(*value),
        };
    }
    let total = count.fetch_one(pool).await?.get::<i64, _>("c");

    let page = query.page.max(1);
    let page_size = query.page_size;
    let offset = (page as i64 - 1).saturating_mul(page_size as i64);
    let select_sql = format!(
        "SELECT a.id, COALESCE(u.email, CASE WHEN a.user_id IS NULL THEN 'system' ELSE 'deleted-user' END) AS actor, a.event, a.details, a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id{where_clause} ORDER BY a.created_at DESC, a.id DESC LIMIT ? OFFSET ?"
    );
    let mut select = sqlx::query(&select_sql);
    for filter in &filters {
        select = match filter {
            AuditFilter::Text(value) => select.bind(value),
            AuditFilter::Actor(value) => select.bind(*value),
        };
    }
    let rows = select
        .bind(page_size as i64)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    let items = rows
        .into_iter()
        .map(|row| AuditLogItem {
            id: row.get("id"),
            actor: row.get("actor"),
            event: row.get("event"),
            details: sanitize_audit_details(&row.get::<String, _>("details")),
            created_at: row.get("created_at"),
        })
        .collect();
    Ok(AuditLogPage {
        items,
        page,
        page_size,
        total,
    })
}

fn advisor_workflow(value: &str) -> Result<crate::ai_advisor::AdvisorWorkflow, sqlx::Error> {
    match value {
        "incident_explanation" => Ok(crate::ai_advisor::AdvisorWorkflow::IncidentExplanation),
        "security_summary" => Ok(crate::ai_advisor::AdvisorWorkflow::SecuritySummary),
        "rule_tuning" => Ok(crate::ai_advisor::AdvisorWorkflow::RuleTuning),
        "configuration_draft" => Ok(crate::ai_advisor::AdvisorWorkflow::ConfigurationDraft),
        _ => Err(sqlx::Error::Protocol("invalid advisor workflow".into())),
    }
}

fn advisor_status(value: &str) -> Result<crate::ai_advisor::AdvisorJobStatus, sqlx::Error> {
    use crate::ai_advisor::AdvisorJobStatus::*;
    match value {
        "queued" => Ok(Queued),
        "running" => Ok(Running),
        "completed" => Ok(Completed),
        "failed" => Ok(Failed),
        "approved" => Ok(Approved),
        "rejected" => Ok(Rejected),
        "expired" => Ok(Expired),
        _ => Err(sqlx::Error::Protocol("invalid advisor status".into())),
    }
}

fn advisor_error(
    value: Option<String>,
) -> Result<Option<crate::ai_advisor::AdvisorErrorCode>, sqlx::Error> {
    use crate::ai_advisor::AdvisorErrorCode::*;
    match value.as_deref() {
        None => Ok(None),
        Some("advisor_timeout") => Ok(Some(Timeout)),
        Some("advisor_provider_unavailable") => Ok(Some(ProviderUnavailable)),
        Some("advisor_invalid_response") => Ok(Some(InvalidResponse)),
        Some("advisor_response_too_large") => Ok(Some(ResponseTooLarge)),
        Some("advisor_circuit_open") => Ok(Some(CircuitOpen)),
        Some("advisor_expired") => Ok(Some(Expired)),
        _ => Err(sqlx::Error::Protocol("invalid advisor error".into())),
    }
}

fn advisor_record(row: &sqlx::any::AnyRow) -> Result<AdvisorJobRecord, sqlx::Error> {
    Ok(AdvisorJobRecord {
        job_id: crate::ai_advisor::AdvisorJobId(row.get("job_id")),
        owner_id: row.get("owner_id"),
        workflow: advisor_workflow(&row.get::<String, _>("workflow"))?,
        status: advisor_status(&row.get::<String, _>("status"))?,
        redacted_input: row.get("redacted_input"),
        redacted_result: row.get("redacted_result"),
        error_code: advisor_error(row.get("error_code"))?,
        provider_model: row.get("provider_model"),
        config_version: row.get("config_version"),
        config_hash: row.get("config_hash"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
    })
}

pub async fn insert_advisor_job(
    pool: &DbPool,
    job: &NewAdvisorJob,
) -> Result<AdvisorJobRecord, sqlx::Error> {
    if job.owner_id <= 0
        || job.job_id.0.len() > 64
        || job.redacted_input.len() > MAX_ADVISOR_PERSISTED_BYTES
        || job.provider_model.len() > 128
        || job.config_version.len() > 64
        || job.config_hash.len() > 128
    {
        return Err(sqlx::Error::Protocol("invalid bounded advisor job".into()));
    }
    let now = job.created_at.to_rfc3339();
    sqlx::query("INSERT INTO ai_advisor_jobs(job_id,owner_id,workflow,status,redacted_input,provider_model,config_version,config_hash,created_at,updated_at,expires_at) VALUES(?,?,?,'queued',?,?,?,?,?,?,?)")
        .bind(&job.job_id.0).bind(job.owner_id).bind(serde_json::to_value(&job.workflow).unwrap().as_str().unwrap()).bind(&job.redacted_input).bind(&job.provider_model).bind(&job.config_version).bind(&job.config_hash).bind(&now).bind(&now).bind(job.expires_at.to_rfc3339()).execute(pool).await?;
    get_advisor_job(pool, &job.job_id)
        .await?
        .ok_or_else(|| sqlx::Error::Protocol("advisor job missing after insert".into()))
}

pub async fn claim_advisor_job(
    pool: &DbPool,
    job_id: &crate::ai_advisor::AdvisorJobId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    let now = now.to_rfc3339();
    sqlx::query("UPDATE ai_advisor_jobs SET status='expired',updated_at=? WHERE job_id=? AND status='queued' AND expires_at<=?").bind(&now).bind(&job_id.0).bind(&now).execute(pool).await?;
    Ok(sqlx::query("UPDATE ai_advisor_jobs SET status='running',updated_at=? WHERE job_id=? AND status='queued' AND expires_at>?").bind(&now).bind(&job_id.0).bind(&now).execute(pool).await?.rows_affected() == 1)
}

pub async fn finish_advisor_job(
    pool: &DbPool,
    job_id: &crate::ai_advisor::AdvisorJobId,
    status: crate::ai_advisor::AdvisorJobStatus,
    result: Option<&str>,
    error: Option<crate::ai_advisor::AdvisorErrorCode>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    if !matches!(
        status,
        crate::ai_advisor::AdvisorJobStatus::Completed
            | crate::ai_advisor::AdvisorJobStatus::Failed
            | crate::ai_advisor::AdvisorJobStatus::Expired
    ) || result.is_some_and(|value| value.len() > MAX_ADVISOR_PERSISTED_BYTES)
    {
        return Err(sqlx::Error::Protocol("invalid advisor finish".into()));
    }
    let status = serde_json::to_value(status)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let error = error
        .and_then(|value| serde_json::to_value(value).ok())
        .and_then(|value| value.as_str().map(str::to_owned));
    Ok(sqlx::query("UPDATE ai_advisor_jobs SET status=?,redacted_result=?,error_code=?,updated_at=? WHERE job_id=? AND status='running'").bind(status).bind(result).bind(error).bind(now.to_rfc3339()).bind(&job_id.0).execute(pool).await?.rows_affected() == 1)
}

pub async fn mark_advisor_draft_decision(
    pool: &DbPool,
    job_id: &crate::ai_advisor::AdvisorJobId,
    approved: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    let status = if approved { "approved" } else { "rejected" };
    Ok(sqlx::query("UPDATE ai_advisor_jobs SET status=?,draft_decision=?,draft_decided_at=?,updated_at=? WHERE job_id=? AND workflow='configuration_draft' AND status='completed'").bind(status).bind(status).bind(now.to_rfc3339()).bind(now.to_rfc3339()).bind(&job_id.0).execute(pool).await?.rows_affected() == 1)
}

pub async fn get_advisor_job(
    pool: &DbPool,
    job_id: &crate::ai_advisor::AdvisorJobId,
) -> Result<Option<AdvisorJobRecord>, sqlx::Error> {
    sqlx::query("SELECT job_id,owner_id,workflow,status,redacted_input,redacted_result,error_code,provider_model,config_version,config_hash,created_at,updated_at,expires_at FROM ai_advisor_jobs WHERE job_id=?").bind(&job_id.0).fetch_optional(pool).await?.map(|row| advisor_record(&row)).transpose()
}

pub async fn list_advisor_jobs(
    pool: &DbPool,
    owner_id: i64,
    page_size: u32,
    page: u32,
) -> Result<AdvisorJobPage, sqlx::Error> {
    let page = page.max(1);
    let page_size = page_size.clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ai_advisor_jobs WHERE owner_id=?")
        .bind(owner_id)
        .fetch_one(pool)
        .await?;
    let rows = sqlx::query("SELECT job_id,owner_id,workflow,status,redacted_input,redacted_result,error_code,provider_model,config_version,config_hash,created_at,updated_at,expires_at FROM ai_advisor_jobs WHERE owner_id=? ORDER BY created_at DESC,job_id DESC LIMIT ? OFFSET ?").bind(owner_id).bind(page_size as i64).bind((page as i64 - 1) * page_size as i64).fetch_all(pool).await?;
    Ok(AdvisorJobPage {
        items: rows.iter().map(advisor_record).collect::<Result<_, _>>()?,
        page,
        page_size,
        total,
    })
}

pub async fn count_active_admins(pool: &DbPool) -> Result<i64, sqlx::Error> {
    Ok(
        sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
            .fetch_one(pool)
            .await?
            .get("c"),
    )
}

/// Atomically apply a user's role and disabled state.  The last-active-admin
/// invariant is checked while holding SQLite's write lock so a combined PATCH
/// can never leave a partially updated account behind.
pub async fn update_user(
    pool: &DbPool,
    id: i64,
    role: Option<&str>,
    disabled: Option<bool>,
) -> Result<Option<User>, sqlx::Error> {
    if let Some(value) = role {
        if Role::parse(value).is_none()
            && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
                .bind(value)
                .fetch_optional(pool)
                .await?
                .is_none()
        {
            return Err(sqlx::Error::Protocol("invalid role".into()));
        }
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    let current = sqlx::query(
        "SELECT id,email,role,created_at,disabled,preferred_locale FROM users WHERE id=?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(current) = current else {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Ok(None);
    };
    let current_role: String = current.get("role");
    let current_disabled: bool = current.get::<i64, _>("disabled") != 0;
    let next_role = role.unwrap_or(current_role.as_str());
    let next_disabled = disabled.unwrap_or(current_disabled);
    if current_role == "admin" && !current_disabled && (next_role != "admin" || next_disabled) {
        let admins: i64 =
            sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
                .fetch_one(&mut *conn)
                .await?
                .get("c");
        if admins <= 1 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(last_admin_error());
        }
    }
    sqlx::query("UPDATE users SET role=?,disabled=? WHERE id=?")
        .bind(next_role)
        .bind(next_disabled as i64)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    if next_disabled && !current_disabled {
        sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    let updated = sqlx::query(
        "SELECT id,email,role,created_at,disabled,preferred_locale FROM users WHERE id=?",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(Some(User {
        id: updated.get("id"),
        email: updated.get("email"),
        role: updated.get("role"),
        created_at: updated.get("created_at"),
        disabled: updated.get::<i64, _>("disabled") != 0,
        preferred_locale: updated.get("preferred_locale"),
    }))
}

pub async fn update_user_preferred_locale(
    pool: &DbPool,
    id: i64,
    preferred_locale: Option<crate::control_plane::locale::Locale>,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query("UPDATE users SET preferred_locale=? WHERE id=?")
        .bind(preferred_locale.map(crate::control_plane::locale::Locale::as_str))
        .bind(id)
        .execute(pool)
        .await?;
    let updated = sqlx::query(
        "SELECT id,email,role,created_at,disabled,preferred_locale FROM users WHERE id=?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(Some(User {
        id: updated.get("id"),
        email: updated.get("email"),
        role: updated.get("role"),
        created_at: updated.get("created_at"),
        disabled: updated.get::<i64, _>("disabled") != 0,
        preferred_locale: updated.get("preferred_locale"),
    }))
}

fn last_admin_error() -> sqlx::Error {
    sqlx::Error::Protocol("cannot remove the last active administrator".into())
}

pub async fn update_user_role(pool: &DbPool, id: i64, role: &str) -> Result<u64, sqlx::Error> {
    if Role::parse(role).is_none()
        && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
            .bind(role)
            .fetch_optional(pool)
            .await?
            .is_none()
    {
        return Err(sqlx::Error::Protocol("invalid role".into()));
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = current {
        let was_admin =
            row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0;
        if was_admin && role != "admin" {
            let admins: i64 =
                sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
                    .fetch_one(&mut *conn)
                    .await?
                    .get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    let changed = sqlx::query("UPDATE users SET role=? WHERE id=?")
        .bind(role)
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}

pub async fn revoke_user_sessions(pool: &DbPool, user_id: i64) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn set_user_disabled(pool: &DbPool, id: i64, disabled: bool) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = current {
        let was_active_admin =
            row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0;
        if disabled && was_active_admin {
            let admins: i64 =
                sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
                    .fetch_one(&mut *conn)
                    .await?
                    .get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    let changed = sqlx::query("UPDATE users SET disabled=? WHERE id=?")
        .bind(disabled as i64)
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if disabled && changed > 0 {
        sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}

pub async fn delete_user(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = current {
        if row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0 {
            let admins: i64 =
                sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
                    .fetch_one(&mut *conn)
                    .await?
                    .get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    sqlx::query("DELETE FROM sessions WHERE user_id=?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let changed = sqlx::query("DELETE FROM users WHERE id=?")
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}
pub async fn create_session(
    pool: &DbPool,
    user_id: i64,
    hash: &str,
    expires: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)")
        .bind(generated_id())
        .bind(user_id)
        .bind(hash)
        .bind(expires)
        .execute(pool)
        .await?;
    Ok(())
}
pub async fn revoke_session(pool: &DbPool, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at=? WHERE token_hash=?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}
pub async fn list_hosts(pool: &DbPool) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows=sqlx::query("SELECT id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled FROM proxy_hosts ORDER BY id").fetch_all(pool).await?;
    Ok(rows.into_iter().map(proxy_host_from_row).collect())
}

fn proxy_host_from_row(x: sqlx::any::AnyRow) -> ProxyHost {
    ProxyHost {
        id: x.get("id"),
        name: x.get("name"),
        domain: x.get("domain"),
        upstream_host: x.get("upstream_host"),
        upstream_port: x.get::<i64, _>("upstream_port") as u16,
        tls_mode: x.get("tls_mode"),
        certificate_id: x.get("certificate_id"),
        enabled: x.get::<i64, _>("enabled") != 0,
    }
}

/// Lists only hosts visible through a user's global or per-host read grants.
pub async fn list_hosts_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows = sqlx::query("SELECT DISTINCT h.id,h.name,h.domain,h.upstream_host,h.upstream_port,h.tls_mode,h.certificate_id,h.enabled FROM proxy_hosts h JOIN users u ON u.id=? JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.disabled=0 AND p.key='proxy_hosts.read' AND ((rp.scope_type='' AND rp.scope_id=0) OR (rp.scope_type='proxy_host' AND rp.scope_id=h.id)) ORDER BY h.id")
        .bind(user_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(proxy_host_from_row).collect())
}
pub async fn insert_host(pool: &DbPool, h: &ProxyHost) -> Result<ProxyHost, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let id = if h.id > 0 { h.id } else { generated_id() };
    sqlx::query("INSERT INTO proxy_hosts(id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(id).bind(&h.name).bind(&h.domain).bind(&h.upstream_host).bind(h.upstream_port as i64).bind(&h.tls_mode).bind(h.certificate_id).bind(h.enabled as i64).bind(&now).bind(&now).execute(pool).await?;
    let mut x = h.clone();
    x.id = id;
    Ok(x)
}
pub async fn delete_host(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Removes a proxy host and every per-host role assignment in one transaction.
/// Callers can safely restore the host if the transaction fails; no partial
/// cleanup is committed.
pub async fn delete_host_and_scopes(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    let result = async {
        let changed = sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
            .bind(id)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM role_permissions WHERE scope_type='proxy_host' AND scope_id=?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        Ok::<u64, sqlx::Error>(changed)
    }
    .await;
    match result {
        Ok(changed) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(changed)
        }
        Err(error) => {
            if let Err(rollback_error) = sqlx::query("ROLLBACK").execute(&mut *conn).await {
                eprintln!("proxy host deletion rollback failed: {rollback_error}");
            }
            Err(error)
        }
    }
}

pub async fn host_scope_rows(
    pool: &DbPool,
    id: i64,
) -> Result<Vec<(i64, i64, String)>, sqlx::Error> {
    let rows = sqlx::query("SELECT role_id,permission_id,scope_type FROM role_permissions WHERE scope_type='proxy_host' AND scope_id=?")
        .bind(id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("role_id"),
                row.get("permission_id"),
                row.get("scope_type"),
            )
        })
        .collect())
}

pub async fn restore_host_scopes(
    pool: &DbPool,
    id: i64,
    rows: &[(i64, i64, String)],
) -> Result<(), sqlx::Error> {
    for (role_id, permission_id, scope_type) in rows {
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM role_permissions WHERE role_id=? AND permission_id=? AND scope_type=? AND scope_id=?)")
            .bind(role_id).bind(permission_id).bind(scope_type).bind(id)
            .bind(role_id).bind(permission_id).bind(scope_type).bind(id)
            .execute(pool).await?;
    }
    Ok(())
}

pub async fn get_host(pool: &DbPool, id: i64) -> Result<Option<ProxyHost>, sqlx::Error> {
    let row = sqlx::query("SELECT id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled FROM proxy_hosts WHERE id=?")
        .bind(id).fetch_optional(pool).await?;
    Ok(row.map(|x| ProxyHost {
        id: x.get("id"),
        name: x.get("name"),
        domain: x.get("domain"),
        upstream_host: x.get("upstream_host"),
        upstream_port: x.get::<i64, _>("upstream_port") as u16,
        tls_mode: x.get("tls_mode"),
        certificate_id: x.get("certificate_id"),
        enabled: x.get::<i64, _>("enabled") != 0,
    }))
}

pub async fn update_host(pool: &DbPool, id: i64, h: &ProxyHost) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE proxy_hosts SET name=?,domain=?,upstream_host=?,upstream_port=?,tls_mode=?,certificate_id=?,enabled=?,updated_at=? WHERE id=?")
        .bind(&h.name).bind(&h.domain).bind(&h.upstream_host).bind(h.upstream_port as i64)
        .bind(&h.tls_mode).bind(h.certificate_id).bind(h.enabled as i64)
        .bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(pool).await?.rows_affected())
}
pub async fn insert_certificate(
    pool: &DbPool,
    name: &str,
    source: &str,
    hosts: &str,
    expiry: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<i64, sqlx::Error> {
    let id = generated_id();
    sqlx::query("INSERT INTO certificates(id,name,source,covered_hostnames,expiry,certificate_path,key_path,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(name).bind(source).bind(hosts).bind(expiry).bind(cert_path).bind(key_path).bind(chrono::Utc::now().to_rfc3339()).execute(pool).await?;
    Ok(id)
}

pub async fn list_certificates(pool: &DbPool) -> Result<Vec<CertificateMetadata>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,name,source,covered_hostnames,expiry,active FROM certificates ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| CertificateMetadata {
            id: r.get("id"),
            name: r.get("name"),
            source: r.get("source"),
            covered_hostnames: serde_json::from_str(&r.get::<String, _>("covered_hostnames"))
                .unwrap_or_default(),
            expiry: r.get("expiry"),
            active: r.get::<i64, _>("active") != 0,
        })
        .collect())
}

pub async fn certificate_name(pool: &DbPool, id: i64) -> Result<Option<String>, sqlx::Error> {
    Ok(sqlx::query("SELECT name FROM certificates WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .map(|r| r.get("name")))
}

/// Return the certificate storage paths for activation validation.
pub async fn certificate_paths(
    pool: &DbPool,
    id: i64,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT name,certificate_path,key_path FROM certificates WHERE id=?")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .map(|r| (r.get("name"), r.get("certificate_path"), r.get("key_path"))),
    )
}

pub async fn active_certificate_id(pool: &DbPool) -> Result<Option<i64>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT id FROM certificates WHERE active=1 ORDER BY id LIMIT 1")
            .fetch_optional(pool)
            .await?
            .map(|r| r.get("id")),
    )
}

/// Set exactly one active certificate (or none), in one transaction.
pub async fn set_active_certificate(pool: &DbPool, id: Option<i64>) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE certificates SET active=0")
        .execute(&mut *tx)
        .await?;
    let changed = if let Some(id) = id {
        sqlx::query("UPDATE certificates SET active=1 WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    } else {
        0
    };
    tx.commit().await?;
    Ok(changed)
}

pub async fn activate_certificate(pool: &DbPool, id: i64) -> Result<u64, sqlx::Error> {
    set_active_certificate(pool, Some(id)).await
}

pub async fn get_tuning_policy(
    pool: &DbPool,
    host_id: i64,
) -> Result<crate::adaptive_tuning::TuningPolicy, sqlx::Error> {
    let row = sqlx::query("SELECT mode, max_delta_percent, cooldown_seconds, min_confidence FROM adaptive_tuning_policies WHERE host_id=?")
        .bind(host_id)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let mode_str: String = row.get("mode");
        let mode = match mode_str.as_str() {
            "recommend" => crate::adaptive_tuning::TuningMode::Recommend,
            "enforce" => crate::adaptive_tuning::TuningMode::Enforce,
            _ => crate::adaptive_tuning::TuningMode::Monitor,
        };
        Ok(crate::adaptive_tuning::TuningPolicy {
            mode,
            max_delta_percent: row.get::<i64, _>("max_delta_percent") as u8,
            cooldown_seconds: row.get::<i64, _>("cooldown_seconds") as u64,
            min_confidence: row.get::<f64, _>("min_confidence"),
        })
    } else {
        Ok(crate::adaptive_tuning::TuningPolicy::default())
    }
}

pub async fn update_tuning_policy(
    pool: &DbPool,
    host_id: i64,
    policy: &crate::adaptive_tuning::TuningPolicy,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mode_str = match policy.mode {
        crate::adaptive_tuning::TuningMode::Monitor => "monitor",
        crate::adaptive_tuning::TuningMode::Recommend => "recommend",
        crate::adaptive_tuning::TuningMode::Enforce => "enforce",
    };

    sqlx::query("INSERT INTO adaptive_tuning_policies(host_id, mode, max_delta_percent, cooldown_seconds, min_confidence, updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET mode=?, max_delta_percent=?, cooldown_seconds=?, min_confidence=?, updated_at=?")
        .bind(host_id).bind(mode_str).bind(policy.max_delta_percent as i64).bind(policy.cooldown_seconds as i64).bind(policy.min_confidence).bind(&now)
        .bind(mode_str).bind(policy.max_delta_percent as i64).bind(policy.cooldown_seconds as i64).bind(policy.min_confidence).bind(&now)
        .execute(pool).await?;

    Ok(())
}

pub async fn get_emergency_disabled(pool: &DbPool) -> Result<bool, sqlx::Error> {
    let val: Option<i64> =
        sqlx::query_scalar("SELECT emergency_disabled FROM adaptive_tuning_global WHERE id=1")
            .fetch_optional(pool)
            .await?;
    Ok(val.unwrap_or(0) == 1)
}

pub async fn set_emergency_disabled(pool: &DbPool, disabled: bool) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let val = if disabled { 1i64 } else { 0i64 };
    sqlx::query("INSERT INTO adaptive_tuning_global(id, emergency_disabled, updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET emergency_disabled=?, updated_at=?")
        .bind(val).bind(&now).bind(val).bind(&now)
        .execute(pool).await?;
    Ok(())
}

pub async fn list_tuning_recommendations(
    pool: &DbPool,
) -> Result<Vec<crate::adaptive_tuning::PolicyRecommendation>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, host_id, patch_json, confidence, reason, created_at, applied, applied_at, previous_config_json FROM adaptive_tuning_recommendations ORDER BY id DESC LIMIT 100")
        .fetch_all(pool).await?;

    let mut list = Vec::new();
    for row in rows {
        let patch_json: String = row.get("patch_json");
        let patch = serde_json::from_str(&patch_json).unwrap_or_default();
        let created_at_str: String = row.get("created_at");
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        let applied_at = row.get::<Option<String>, _>("applied_at").and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
        });

        list.push(crate::adaptive_tuning::PolicyRecommendation {
            id: row.get("id"),
            host_id: row.get("host_id"),
            patch,
            confidence: row.get("confidence"),
            reason: row.get("reason"),
            created_at,
            applied: row.get::<i64, _>("applied") != 0,
            applied_at,
            previous_config_json: row.get("previous_config_json"),
        });
    }
    Ok(list)
}

pub async fn get_tuning_recommendation(
    pool: &DbPool,
    id: i64,
) -> Result<Option<crate::adaptive_tuning::PolicyRecommendation>, sqlx::Error> {
    let row = sqlx::query("SELECT id, host_id, patch_json, confidence, reason, created_at, applied, applied_at, previous_config_json FROM adaptive_tuning_recommendations WHERE id=?")
        .bind(id)
        .fetch_optional(pool).await?;

    if let Some(row) = row {
        let patch_json: String = row.get("patch_json");
        let patch = serde_json::from_str(&patch_json).unwrap_or_default();
        let created_at_str: String = row.get("created_at");
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        let applied_at = row.get::<Option<String>, _>("applied_at").and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
        });

        Ok(Some(crate::adaptive_tuning::PolicyRecommendation {
            id: row.get("id"),
            host_id: row.get("host_id"),
            patch,
            confidence: row.get("confidence"),
            reason: row.get("reason"),
            created_at,
            applied: row.get::<i64, _>("applied") != 0,
            applied_at,
            previous_config_json: row.get("previous_config_json"),
        }))
    } else {
        Ok(None)
    }
}

pub async fn insert_tuning_recommendation(
    pool: &DbPool,
    rec: &crate::adaptive_tuning::PolicyRecommendation,
) -> Result<i64, sqlx::Error> {
    let id = if rec.id > 0 { rec.id } else { generated_id() };
    let patch_json = serde_json::to_string(&rec.patch).unwrap_or_default();
    sqlx::query("INSERT INTO adaptive_tuning_recommendations (id, host_id, patch_json, confidence, reason, created_at, applied) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(rec.host_id)
        .bind(&patch_json)
        .bind(rec.confidence)
        .bind(&rec.reason)
        .bind(rec.created_at.to_rfc3339())
        .bind(if rec.applied { 1i64 } else { 0i64 })
        .execute(pool).await?;
    Ok(id)
}

pub async fn insert_tuning_recommendation_dedup(
    pool: &DbPool,
    rec: &crate::adaptive_tuning::PolicyRecommendation,
    cooldown_seconds: i64,
) -> Result<Option<i64>, sqlx::Error> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(cooldown_seconds)).to_rfc3339();

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM adaptive_tuning_recommendations WHERE host_id=? AND reason=? AND applied=0 AND created_at >= ?"
    )
    .bind(rec.host_id)
    .bind(&rec.reason)
    .bind(&cutoff)
    .fetch_one(pool).await?;

    if count > 0 {
        return Ok(None);
    }

    let id = insert_tuning_recommendation(pool, rec).await?;

    sqlx::query("DELETE FROM adaptive_tuning_recommendations WHERE id NOT IN (SELECT id FROM adaptive_tuning_recommendations ORDER BY id DESC LIMIT 1000)")
        .execute(pool).await?;

    Ok(Some(id))
}

pub async fn get_host_rate_limit_config(
    pool: &DbPool,
    host_id: i64,
) -> Result<super::models::RateLimitConfig, sqlx::Error> {
    let global = get_rate_limit_config(pool).await?;
    let row = sqlx::query(
        "SELECT capacity, refill_per_second FROM host_rate_limit_configs WHERE host_id=?",
    )
    .bind(host_id)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        let capacity: i64 = row.get("capacity");
        let refill_per_second: f64 = row.get("refill_per_second");
        Ok(super::models::RateLimitConfig {
            enabled: global.enabled,
            action: global.action,
            capacity: capacity as u32,
            refill_per_second,
            key_scope: global.key_scope,
            updated_at: global.updated_at,
        })
    } else {
        Ok(global)
    }
}

pub async fn list_host_rate_limit_configs(
    pool: &DbPool,
) -> Result<Vec<(i64, super::models::RateLimitConfig)>, sqlx::Error> {
    let global = get_rate_limit_config(pool).await?;
    let rows =
        sqlx::query("SELECT host_id, capacity, refill_per_second FROM host_rate_limit_configs")
            .fetch_all(pool)
            .await?;

    let mut list = Vec::new();
    for row in rows {
        let host_id: i64 = row.get("host_id");
        let capacity: i64 = row.get("capacity");
        let refill_per_second: f64 = row.get("refill_per_second");
        list.push((
            host_id,
            super::models::RateLimitConfig {
                enabled: global.enabled,
                action: global.action,
                capacity: capacity as u32,
                refill_per_second,
                key_scope: global.key_scope,
                updated_at: global.updated_at.clone(),
            },
        ));
    }
    Ok(list)
}

pub async fn mark_tuning_recommendation_applied(
    pool: &DbPool,
    rec_id: i64,
    previous_config_json: &str,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE adaptive_tuning_recommendations
         SET applied=1, applied_at=?, previous_config_json=?
         WHERE id=? AND applied=0",
    )
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(previous_config_json)
    .bind(rec_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(changed == 1)
}

pub async fn mark_tuning_recommendation_rolled_back(
    pool: &DbPool,
    rec_id: i64,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE adaptive_tuning_recommendations
         SET applied=0, applied_at=NULL
         WHERE id=? AND applied=1",
    )
    .bind(rec_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(changed == 1)
}

pub async fn apply_tuning_recommendation_tx(
    pool: &DbPool,
    rec_id: i64,
) -> Result<Option<(i64, super::models::RateLimitConfig)>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        "SELECT id, host_id, patch_json, applied FROM adaptive_tuning_recommendations WHERE id=?",
    )
    .bind(rec_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let applied: i64 = row.get("applied");
    if applied != 0 {
        return Ok(None);
    }

    let host_id: i64 = row.get("host_id");
    let patch_json: String = row.get("patch_json");
    let patch: crate::adaptive_tuning::PolicyPatch =
        serde_json::from_str(&patch_json).unwrap_or_default();

    let global_row = sqlx::query("SELECT enabled, action, capacity, refill_per_second, key_scope, updated_at FROM rate_limit_config WHERE id=1")
        .fetch_one(&mut *tx)
        .await?;

    let host_override = sqlx::query(
        "SELECT capacity, refill_per_second FROM host_rate_limit_configs WHERE host_id=?",
    )
    .bind(host_id)
    .fetch_optional(&mut *tx)
    .await?;

    let current_cap = host_override
        .as_ref()
        .map(|r| r.get::<i64, _>("capacity") as u32)
        .unwrap_or_else(|| global_row.get::<i64, _>("capacity") as u32);
    let current_refill = host_override
        .as_ref()
        .map(|r| r.get::<f64, _>("refill_per_second"))
        .unwrap_or_else(|| global_row.get::<f64, _>("refill_per_second"));

    let mut current_rl = super::models::RateLimitConfig {
        enabled: global_row.get::<i64, _>("enabled") != 0,
        action: if global_row.get::<String, _>("action") == "block" {
            crate::rate_limit::RateLimitAction::Block
        } else {
            crate::rate_limit::RateLimitAction::Monitor
        },
        capacity: current_cap,
        refill_per_second: current_refill,
        key_scope: crate::rate_limit::RateLimitKeyScope::ProxyHostIp,
        updated_at: global_row.get("updated_at"),
    };

    let prev_json = serde_json::to_string(&current_rl).unwrap_or_default();

    if let Some(cap) = patch.capacity {
        current_rl.capacity = cap;
    }
    if let Some(refill) = patch.refill_per_second {
        current_rl.refill_per_second = refill;
    }

    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO host_rate_limit_configs(host_id, capacity, refill_per_second, updated_at) VALUES(?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET capacity=?, refill_per_second=?, updated_at=?")
        .bind(host_id).bind(current_rl.capacity as i64).bind(current_rl.refill_per_second).bind(&now)
        .bind(current_rl.capacity as i64).bind(current_rl.refill_per_second).bind(&now)
        .execute(&mut *tx).await?;

    sqlx::query("UPDATE adaptive_tuning_recommendations SET applied=1, applied_at=?, previous_config_json=? WHERE id=?")
        .bind(&now)
        .bind(&prev_json)
        .bind(rec_id)
        .execute(&mut *tx).await?;

    tx.commit().await?;

    Ok(Some((host_id, current_rl)))
}

pub async fn rollback_tuning_recommendation_tx(
    pool: &DbPool,
    rec_id: i64,
) -> Result<Option<(i64, super::models::RateLimitConfig)>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query("SELECT id, host_id, applied, previous_config_json FROM adaptive_tuning_recommendations WHERE id=?")
        .bind(rec_id)
        .fetch_optional(&mut *tx)
        .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let applied: i64 = row.get("applied");
    if applied == 0 {
        return Ok(None);
    }

    let host_id: i64 = row.get("host_id");
    let prev_json: Option<String> = row.get("previous_config_json");
    let Some(prev_json) = prev_json else {
        return Ok(None);
    };

    let restored_rl: super::models::RateLimitConfig =
        serde_json::from_str(&prev_json).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO host_rate_limit_configs(host_id, capacity, refill_per_second, updated_at) VALUES(?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET capacity=?, refill_per_second=?, updated_at=?")
        .bind(host_id).bind(restored_rl.capacity as i64).bind(restored_rl.refill_per_second).bind(&now)
        .bind(restored_rl.capacity as i64).bind(restored_rl.refill_per_second).bind(&now)
        .execute(&mut *tx).await?;

    sqlx::query("UPDATE adaptive_tuning_recommendations SET applied=0, applied_at=NULL WHERE id=?")
        .bind(rec_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Some((host_id, restored_rl)))
}
