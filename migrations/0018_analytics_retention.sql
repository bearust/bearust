CREATE TABLE IF NOT EXISTS analytics_config (
    id INTEGER PRIMARY KEY,
    retention_minutes INTEGER NOT NULL DEFAULT 1440,
    updated_at VARCHAR(64) NOT NULL
);

INSERT INTO analytics_config(id, retention_minutes, updated_at)
SELECT 1, 1440, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM analytics_config WHERE id=1);
