CREATE TABLE IF NOT EXISTS bot_config (
    id INTEGER PRIMARY KEY,
    mode VARCHAR(16) NOT NULL DEFAULT 'monitor',
    threshold INTEGER NOT NULL DEFAULT 60,
    ttl_seconds INTEGER NOT NULL DEFAULT 900,
    fingerprint_key TEXT NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS bot_rules (
    id INTEGER PRIMARY KEY,
    category VARCHAR(64) NOT NULL,
    weight INTEGER NOT NULL DEFAULT 0,
    trusted_user_agent VARCHAR(256),
    trusted_domain VARCHAR(256),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    UNIQUE(category, trusted_user_agent, trusted_domain)
);
INSERT INTO bot_config(id,mode,threshold,ttl_seconds,fingerprint_key,updated_at)
SELECT 1,'monitor',60,900,'','1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM bot_config WHERE id=1);
