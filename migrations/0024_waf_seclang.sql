-- OWASP CRS / SecLang settings. The CRS rules themselves are embedded in the
-- binary; only these bounded settings and custom rules are stored.
CREATE TABLE IF NOT EXISTS waf_seclang_config (
    id INTEGER PRIMARY KEY,
    crs_enabled INTEGER NOT NULL DEFAULT 0,
    paranoia_level INTEGER NOT NULL DEFAULT 1,
    inbound_threshold INTEGER NOT NULL DEFAULT 5,
    custom_rules TEXT NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);

INSERT INTO waf_seclang_config(id,crs_enabled,paranoia_level,inbound_threshold,custom_rules,updated_at)
SELECT 1,0,1,5,'','1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM waf_seclang_config WHERE id=1);
