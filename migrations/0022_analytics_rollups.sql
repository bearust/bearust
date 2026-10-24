CREATE TABLE IF NOT EXISTS analytics_rollups (
    granularity VARCHAR(8) NOT NULL,
    proxy_host_id INTEGER NOT NULL,
    bucket_timestamp VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (granularity, proxy_host_id, bucket_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_analytics_rollups_timestamp
    ON analytics_rollups(granularity, bucket_timestamp);
