-- Portable control-plane schema. IDs are supplied by the application. This is
-- required because INTEGER PRIMARY KEY has no implicit generator on PostgreSQL
-- or MySQL (while remaining compatible with SQLite legacy inserts).
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at VARCHAR(64) NOT NULL,
    revoked_at VARCHAR(64),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS proxy_hosts (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    upstream_host VARCHAR(255) NOT NULL,
    upstream_port INTEGER NOT NULL,
    tls_mode VARCHAR(32) NOT NULL,
    certificate_id INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    source VARCHAR(32) NOT NULL,
    covered_hostnames TEXT NOT NULL,
    expiry VARCHAR(64) NOT NULL,
    certificate_path TEXT NOT NULL,
    key_path TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_certificates (
    certificate_id INTEGER PRIMARY KEY,
    environment VARCHAR(32) NOT NULL,
    challenge VARCHAR(64) NOT NULL,
    renewal_state VARCHAR(32) NOT NULL,
    next_renewal_at VARCHAR(64),
    last_attempt_at VARCHAR(64),
    last_error_code VARCHAR(255),
    secret_ref TEXT,
    FOREIGN KEY(certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    event VARCHAR(255) NOT NULL,
    details TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    system_managed INTEGER NOT NULL DEFAULT 0,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY,
    key VARCHAR(128) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    scope_type VARCHAR(64) NOT NULL DEFAULT '',
    scope_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (role_id, permission_id, scope_type, scope_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
