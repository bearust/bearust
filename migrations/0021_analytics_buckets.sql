CREATE TABLE IF NOT EXISTS analytics_buckets (
    proxy_host_id INTEGER NOT NULL,
    bucket_timestamp VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (proxy_host_id, bucket_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_analytics_buckets_timestamp
    ON analytics_buckets(bucket_timestamp);
