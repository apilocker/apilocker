-- Migration: add 'custom' to the auth_header_type CHECK constraint on keys_metadata
--
-- v1.0.0 introduced the 'custom' auth header type (used by ElevenLabs,
-- which sends 'xi-api-key' instead of any standard header). The original
-- schema constraint didn't include 'custom' so INSERTs of ElevenLabs
-- credentials fail with:
--   CHECK constraint failed: auth_header_type IN ('bearer', 'x-api-key', 'basic', 'query')
--
-- SQLite can't alter CHECK constraints in place, so we rebuild the table
-- using the same pattern as schema_migration_pause_and_hourly.sql:
--   1. Create a new table with the updated constraint
--   2. Copy all rows from the old table
--   3. Drop the old table
--   4. Rename the new table
--   5. Recreate indexes
--
-- All existing columns are preserved including the v1.0.0 additions:
--   rotated_at, credential_type, paused_at, previous_names.

CREATE TABLE keys_metadata_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  provider TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  base_url TEXT NOT NULL,
  auth_header_type TEXT NOT NULL DEFAULT 'bearer'
    CHECK (auth_header_type IN ('bearer', 'x-api-key', 'basic', 'query', 'custom')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_at TEXT,
  credential_type TEXT DEFAULT 'api_key',
  paused_at TEXT,
  previous_names TEXT DEFAULT '[]',
  UNIQUE(user_id, name)
);

INSERT INTO keys_metadata_new (
  id, user_id, name, provider, tags, base_url, auth_header_type,
  created_at, rotated_at, credential_type, paused_at, previous_names
)
SELECT
  id, user_id, name, provider, tags, base_url, auth_header_type,
  created_at, rotated_at, credential_type, paused_at,
  COALESCE(previous_names, '[]')
FROM keys_metadata;

DROP TABLE keys_metadata;
ALTER TABLE keys_metadata_new RENAME TO keys_metadata;

CREATE INDEX IF NOT EXISTS idx_keys_metadata_user_id ON keys_metadata(user_id);
CREATE INDEX IF NOT EXISTS idx_keys_metadata_credential_type ON keys_metadata(credential_type);
CREATE INDEX IF NOT EXISTS idx_keys_metadata_paused_at ON keys_metadata(paused_at);
