-- CAPTCHA provider for bot challenges. The provider secret is kept in the
-- node-local secret store, not here.
CREATE TABLE IF NOT EXISTS bot_captcha_config (
    id INTEGER PRIMARY KEY,
    provider VARCHAR(16) NOT NULL DEFAULT 'none',
    site_key VARCHAR(256) NOT NULL DEFAULT '',
    updated_at VARCHAR(64) NOT NULL
);

INSERT INTO bot_captcha_config(id,provider,site_key,updated_at)
SELECT 1,'none','','1970-01-01T00:00:00Z'
WHERE NOT EXISTS (SELECT 1 FROM bot_captcha_config WHERE id=1);
