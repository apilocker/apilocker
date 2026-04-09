-- Migration: rebuild tokens table to (a) add 'hourly' to the rotation_type
-- CHECK constraint and (b) add a paused_at column for pause/resume support.
--
-- SQLite can't alter CHECK constraints in place, so we recreate the table,
-- copy the rows, drop the old one, and recreate indexes.

CREATE TABLE tokens_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hashed_token TEXT NOT NULL,
  allowed_keys TEXT NOT NULL DEFAULT '[]',
  rotation_type TEXT NOT NULL DEFAULT 'static' CHECK (rotation_type IN ('static', 'hourly', 'daily', 'weekly', 'monthly')),
  current_token_expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  refresh_token_hash TEXT,
  previous_refresh_token_hash TEXT,
  refresh_token_family_id TEXT,
  last_refreshed_at TEXT,
  reuse_detected_at TEXT,
  paused_at TEXT,
  UNIQUE(user_id, name)
);

INSERT INTO tokens_new (
  id, user_id, name, hashed_token, allowed_keys, rotation_type,
  current_token_expires_at, created_at, revoked_at,
  refresh_token_hash, previous_refresh_token_hash, refresh_token_family_id,
  last_refreshed_at, reuse_detected_at, paused_at
)
SELECT
  id, user_id, name, hashed_token, allowed_keys, rotation_type,
  current_token_expires_at, created_at, revoked_at,
  refresh_token_hash, previous_refresh_token_hash, refresh_token_family_id,
  last_refreshed_at, reuse_detected_at, NULL
FROM tokens;

DROP TABLE tokens;
ALTER TABLE tokens_new RENAME TO tokens;

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_hashed_token ON tokens(hashed_token);
CREATE INDEX IF NOT EXISTS idx_tokens_refresh_hash ON tokens(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_prev_refresh_hash ON tokens(previous_refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_family ON tokens(refresh_token_family_id);
CREATE INDEX IF NOT EXISTS idx_tokens_paused ON tokens(paused_at);
