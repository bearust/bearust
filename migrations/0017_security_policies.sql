CREATE TABLE IF NOT EXISTS ip_security_rules (
    id INTEGER PRIMARY KEY,
    cidr VARCHAR(64) NOT NULL,
    action VARCHAR(16) NOT NULL DEFAULT 'monitor',
    score INTEGER NOT NULL DEFAULT 0,
    country_code VARCHAR(8),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_security_rules_enabled ON ip_security_rules(enabled);

CREATE TABLE IF NOT EXISTS proxy_host_auth (
    host_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    realm VARCHAR(128) NOT NULL DEFAULT 'BeaRust protected host',
    username VARCHAR(128) NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    updated_at VARCHAR(64) NOT NULL,
    FOREIGN KEY(host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS waf_feedback (
    id INTEGER PRIMARY KEY,
    reporter_id INTEGER,
    request_id VARCHAR(128),
    rule_id INTEGER,
    label VARCHAR(32) NOT NULL,
    note VARCHAR(1024) NOT NULL DEFAULT '',
    created_at VARCHAR(64) NOT NULL,
    FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_waf_feedback_created ON waf_feedback(created_at);
