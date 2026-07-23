CREATE TABLE IF NOT EXISTS raft_hard_state (
    node_id TEXT PRIMARY KEY,
    current_term BIGINT NOT NULL DEFAULT 0,
    voted_for TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raft_log_entries (
    node_id TEXT NOT NULL,
    log_index BIGINT NOT NULL,
    term BIGINT NOT NULL,
    payload TEXT NOT NULL,
    command_id TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (node_id, log_index)
);

CREATE TABLE IF NOT EXISTS raft_snapshots (
    node_id TEXT PRIMARY KEY,
    snapshot_index BIGINT NOT NULL,
    snapshot_term BIGINT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raft_command_ids (
    command_id TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE INDEX idx_raft_log_entries_term_index
    ON raft_log_entries (term, log_index);

CREATE INDEX idx_raft_log_entries_command_id
    ON raft_log_entries (command_id);
