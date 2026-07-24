CREATE TABLE IF NOT EXISTS raft_command_receipts (
    command_id TEXT PRIMARY KEY,
    log_index BIGINT NOT NULL,
    leader_id BIGINT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE INDEX idx_raft_command_receipts_log_index
    ON raft_command_receipts (log_index);

INSERT INTO raft_command_receipts(command_id, log_index, leader_id, applied_at)
SELECT a.command_id, l.log_index, l.leader_id, a.applied_at
FROM raft_command_ids a
JOIN raft_log_entries l
  ON l.command_id = a.command_id
JOIN raft_committed_state c
  ON c.node_id = l.node_id
 AND l.log_index <= c.log_index
WHERE NOT EXISTS (
    SELECT 1
    FROM raft_log_entries earlier
    JOIN raft_committed_state earlier_commit
      ON earlier_commit.node_id = earlier.node_id
     AND earlier.log_index <= earlier_commit.log_index
    WHERE earlier.command_id = a.command_id
      AND earlier.log_index < l.log_index
)
GROUP BY a.command_id, l.log_index, l.leader_id, a.applied_at;
