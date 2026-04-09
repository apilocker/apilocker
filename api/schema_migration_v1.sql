-- Migration: v1.0.0 "One vault, three types of credentials"
--
-- Adds the schema surface needed for:
--   1. OAuth credential storage (multi-field credentials)
--   2. Pause/resume on individual keys (not just tokens)
--   3. Vault-only credentials (base_url nullable, for keys that only
--      ever get injected as env vars via `apilocker run/get/env`)
--
-- Migration is fully backwards compatible:
--   - All existing rows have credential_type NULL which we treat as 'api_key'
--     (the only type that existed before v1.0.0).
--   - All existing rows have paused_at NULL which means "active".
--   - base_url is already NOT NULL in the current schema; SQLite doesn't
--     support dropping NOT NULL in place, so we work around it by leaving
--     the constraint on the old rows and only allowing NULL for new rows
--     via the application layer. This means: existing keys still have a
--     base_url populated (no harm), and new keys can be created with an
--     empty-string base_url (which the application treats as "not
--     configured for proxy access"). A full table rebuild to drop the
--     NOT NULL could be done later if it causes friction — for now the
--     empty-string convention works fine.

-- New columns
ALTER TABLE keys_metadata ADD COLUMN credential_type TEXT DEFAULT 'api_key';
ALTER TABLE keys_metadata ADD COLUMN paused_at TEXT;

-- Indexes for the new columns
CREATE INDEX IF NOT EXISTS idx_keys_metadata_credential_type ON keys_metadata(credential_type);
CREATE INDEX IF NOT EXISTS idx_keys_metadata_paused_at ON keys_metadata(paused_at);

-- Backfill: every existing row is an api_key
UPDATE keys_metadata SET credential_type = 'api_key' WHERE credential_type IS NULL;
