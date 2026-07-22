CREATE TABLE IF NOT EXISTS rate_limit_config (
    id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    action VARCHAR(16) NOT NULL DEFAULT 'monitor',
    capacity INTEGER NOT NULL DEFAULT 100,
    refill_per_second REAL NOT NULL DEFAULT 10.0,
    key_scope VARCHAR(32) NOT NULL DEFAULT 'proxy_host_ip',
    updated_at VARCHAR(64) NOT NULL
);

INSERT INTO rate_limit_config(id, enabled, action, capacity, refill_per_second, key_scope, updated_at)
SELECT 1, 0, 'monitor', 100, 10.0, 'proxy_host_ip', '1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM rate_limit_config WHERE id=1);
