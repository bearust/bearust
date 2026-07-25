CREATE TABLE IF NOT EXISTS ai_advisor_jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    workflow VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    redacted_input TEXT NOT NULL,
    redacted_result TEXT,
    error_code VARCHAR(64),
    provider_model VARCHAR(128) NOT NULL,
    config_version VARCHAR(64) NOT NULL,
    config_hash VARCHAR(128) NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL,
    expires_at VARCHAR(64) NOT NULL,
    draft_decision VARCHAR(16),
    draft_decided_at VARCHAR(64)
);

CREATE INDEX idx_ai_advisor_jobs_owner_status_created
    ON ai_advisor_jobs (owner_id, status, created_at);
CREATE INDEX idx_ai_advisor_jobs_owner_created
    ON ai_advisor_jobs (owner_id, created_at);
