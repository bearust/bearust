-- Feedback-driven WAF retraining. disabled_rule_ids holds SecLang/CRS rule
-- ids excluded by retraining (JSON array).
ALTER TABLE waf_seclang_config ADD COLUMN disabled_rule_ids VARCHAR(8192) NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS waf_retrain_config (
    id INTEGER PRIMARY KEY,
    mode VARCHAR(16) NOT NULL DEFAULT 'off',
    min_reports INTEGER NOT NULL DEFAULT 5,
    false_positive_percent INTEGER NOT NULL DEFAULT 80,
    window_days INTEGER NOT NULL DEFAULT 30,
    updated_at VARCHAR(64) NOT NULL
);

INSERT INTO waf_retrain_config(id,mode,min_reports,false_positive_percent,window_days,updated_at)
SELECT 1,'off',5,80,30,'1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM waf_retrain_config WHERE id=1);

-- One row per demoted rule, for review and revert.
CREATE TABLE IF NOT EXISTS waf_rule_tunings (
    rule_id INTEGER PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    previous_action VARCHAR(16),
    false_positives INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    source VARCHAR(16) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);
