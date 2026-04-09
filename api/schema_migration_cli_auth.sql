-- Migration: CLI device authorization flow (v0.2.0)
--
-- Adds the tables and columns needed to replace the "paste a master token"
-- CLI registration flow with an RFC 8628 device authorization grant flow.
--
-- Summary:
--   1. New table `device_codes` holds in-flight CLI authorization grants
--      (device_code + human-readable user_code, 10-minute lifetime).
--   2. New columns on `devices` for per-device tokens, revocation, and
--      platform metadata. All nullable — existing rows stay valid.
--
-- Safe to re-run: uses IF NOT EXISTS and guards ALTER TABLE with error-on-
-- duplicate behavior. If re-applied, the ALTERs will error; that's fine,
-- D1 treats each statement independently when executed via `wrangler d1
-- execute --file`.

-- ---- device_codes ----

CREATE TABLE IF NOT EXISTS device_codes (
  device_code TEXT PRIMARY KEY,                -- opaque, 32 random bytes, sent only to the CLI
  user_code TEXT NOT NULL UNIQUE,              -- 8 chars, human-readable (ABCD-1234)
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','authorized','denied','expired','consumed')),
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,   -- filled on approve
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE, -- filled on approve
  client_metadata TEXT NOT NULL,               -- JSON: {hostname, platform, platform_version, cli_version, requested_name?}
  ip_address TEXT,                             -- captured at /start time for the auth card display
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,                    -- typically created_at + 10 minutes
  authorized_at TEXT,
  consumed_at TEXT,
  last_polled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status);

-- ---- devices (extend) ----
--
-- New columns:
--   token_hash        — per-device master token (SHA-256 base64). NULL for
--                       legacy devices registered via the 0.1.x pasted-token
--                       flow; those continue to auth against users.master_token_hash.
--   revoked_at        — soft-delete timestamp. Auth middleware filters out
--                       revoked devices.
--   hostname          — from os.hostname() at register time
--   platform          — 'darwin' / 'linux' / 'win32'
--   platform_version  — from os.release()
--   cli_version       — CLI package.json version at register time
--
-- All nullable — existing rows (legacy registrations) stay valid unchanged.

ALTER TABLE devices ADD COLUMN token_hash TEXT;
ALTER TABLE devices ADD COLUMN revoked_at TEXT;
ALTER TABLE devices ADD COLUMN hostname TEXT;
ALTER TABLE devices ADD COLUMN platform TEXT;
ALTER TABLE devices ADD COLUMN platform_version TEXT;
ALTER TABLE devices ADD COLUMN cli_version TEXT;

CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_devices_revoked_at ON devices(revoked_at);
