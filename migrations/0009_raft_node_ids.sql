CREATE TABLE IF NOT EXISTS raft_node_ids (
    node_id TEXT PRIMARY KEY,
    raft_id BIGINT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_raft_node_ids_raft_id ON raft_node_ids (raft_id);
