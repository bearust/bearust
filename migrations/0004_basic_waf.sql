CREATE TABLE IF NOT EXISTS waf_config (
    id INTEGER PRIMARY KEY,
    mode VARCHAR(32) NOT NULL DEFAULT 'monitor-only',
    updated_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS waf_rules (
    id INTEGER PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    source VARCHAR(16) NOT NULL,
    builtin_key VARCHAR(64),
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    action VARCHAR(16) NOT NULL DEFAULT 'inherit',
    matcher_json TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    UNIQUE (builtin_key)
);
INSERT INTO waf_config(id,mode,updated_at)
SELECT 1,'monitor-only','1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM waf_config WHERE id=1);
