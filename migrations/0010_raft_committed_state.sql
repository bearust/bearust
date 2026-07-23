CREATE TABLE IF NOT EXISTS raft_committed_state (
    node_id TEXT PRIMARY KEY,
    log_index BIGINT NOT NULL,
    term BIGINT NOT NULL,
    leader_id BIGINT NOT NULL,
    updated_at TEXT NOT NULL
);
