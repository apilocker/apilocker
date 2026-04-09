-- Migration: add OAuth2-style refresh token support to the tokens table.
-- All new columns are nullable so existing (static and legacy-rotating) tokens
-- continue to work unchanged. Newly issued rotating tokens will populate these.

ALTER TABLE tokens ADD COLUMN refresh_token_hash TEXT;
ALTER TABLE tokens ADD COLUMN previous_refresh_token_hash TEXT;
ALTER TABLE tokens ADD COLUMN refresh_token_family_id TEXT;
ALTER TABLE tokens ADD COLUMN last_refreshed_at TEXT;
ALTER TABLE tokens ADD COLUMN reuse_detected_at TEXT;

CREATE INDEX IF NOT EXISTS idx_tokens_refresh_hash ON tokens(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_prev_refresh_hash ON tokens(previous_refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_family ON tokens(refresh_token_family_id);
