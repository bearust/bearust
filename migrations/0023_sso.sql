-- External identity providers (OIDC and SAML). Provider secrets live in the
-- file-backed secret store, never in this table.
CREATE TABLE IF NOT EXISTS sso_providers (
    id INTEGER PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    kind VARCHAR(16) NOT NULL,
    name VARCHAR(128) NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);

-- Links a provider subject (OIDC `sub`, SAML NameID) to a local user.
CREATE TABLE IF NOT EXISTS sso_identities (
    provider_id INTEGER NOT NULL,
    subject VARCHAR(255) NOT NULL,
    user_id INTEGER NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (provider_id, subject),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Single-use, short-lived login attempts keyed by the hash of the state
-- (OIDC) or request id (SAML) value.
CREATE TABLE IF NOT EXISTS sso_login_states (
    state_hash VARCHAR(64) PRIMARY KEY,
    provider_id INTEGER NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    code_verifier VARCHAR(128) NOT NULL,
    expires_at VARCHAR(64) NOT NULL
);
