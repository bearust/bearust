CREATE TABLE IF NOT EXISTS adaptive_tuning_policies (
    host_id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'monitor',
    max_delta_percent INTEGER NOT NULL DEFAULT 50,
    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    min_confidence REAL NOT NULL DEFAULT 0.8,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adaptive_tuning_recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    patch_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    applied_at TEXT,
    previous_config_json TEXT
);

CREATE TABLE IF NOT EXISTS adaptive_tuning_global (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    emergency_disabled INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO adaptive_tuning_global (id, emergency_disabled, updated_at)
VALUES (1, 0, '2026-07-22T00:00:00Z');
