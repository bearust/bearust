-- Machine credentials for a managing control plane (e.g. Bearust Cloud).
-- Only the SHA-256 hash of the token is stored; the token acts as user_id,
-- narrowed by scope ('read' or 'write').
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    scope VARCHAR(16) NOT NULL,
    user_id INTEGER NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    last_used_at VARCHAR(64),
    revoked_at VARCHAR(64),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Last generation applied through PUT /api/desired-state; older or equal
-- generations are refused so a delayed push cannot roll the node back.
CREATE TABLE IF NOT EXISTS desired_state (
    id INTEGER PRIMARY KEY,
    generation BIGINT NOT NULL,
    applied_at VARCHAR(64)
);

INSERT INTO desired_state(id, generation, applied_at)
SELECT 1, 0, NULL
WHERE NOT EXISTS (SELECT 1 FROM desired_state WHERE id = 1);
