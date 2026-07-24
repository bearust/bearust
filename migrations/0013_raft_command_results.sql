CREATE TABLE IF NOT EXISTS raft_command_results (
    command_id TEXT PRIMARY KEY,
    result_code TEXT NOT NULL
);

INSERT INTO raft_command_results(command_id, result_code)
SELECT command_id, 'applied'
FROM raft_command_ids
WHERE NOT EXISTS (
    SELECT 1
    FROM raft_command_results result
    WHERE result.command_id = raft_command_ids.command_id
);
