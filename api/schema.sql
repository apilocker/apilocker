-- API Locker D1 Schema

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  avatar_url TEXT,
  oauth_provider TEXT NOT NULL CHECK (oauth_provider IN ('github', 'google')),
  oauth_id TEXT NOT NULL,
  master_token_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(oauth_provider, oauth_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS keys_metadata (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  provider TEXT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  base_url TEXT NOT NULL,
  auth_header_type TEXT NOT NULL DEFAULT 'bearer' CHECK (auth_header_type IN ('bearer', 'x-api-key', 'basic', 'query')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_at TEXT,  -- set by POST /v1/keys/:keyId/rotate (v0.4.0+)
  UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_keys_metadata_user_id ON keys_metadata(user_id);

CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hashed_token TEXT NOT NULL,
  allowed_keys TEXT NOT NULL DEFAULT '[]',
  rotation_type TEXT NOT NULL DEFAULT 'static' CHECK (rotation_type IN ('static', 'daily', 'weekly', 'monthly')),
  current_token_expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  UNIQUE(user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_hashed_token ON tokens(hashed_token);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_id TEXT,
  key_id TEXT,
  provider TEXT,
  forward_path TEXT,
  source_ip TEXT,
  status_code INTEGER,
  latency_ms INTEGER,
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_key_id ON audit_logs(key_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_token_id ON audit_logs(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hardware_fingerprint_hash TEXT NOT NULL,
  registered_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
  -- Added in cli-auth migration (v0.2.0):
  token_hash TEXT,             -- per-device master token (SHA-256 base64). NULL for legacy 0.1.x registrations.
  revoked_at TEXT,             -- soft-delete; auth middleware filters out revoked devices
  hostname TEXT,               -- os.hostname() at register time
  platform TEXT,               -- 'darwin' / 'linux' / 'win32'
  platform_version TEXT,       -- os.release()
  cli_version TEXT             -- CLI package.json version at register time
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(hardware_fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_devices_revoked_at ON devices(revoked_at);

-- ---- Device codes: RFC 8628 device authorization grant state ----
-- Ephemeral table holding in-flight CLI authorization grants. Each row
-- represents one `apilocker register` invocation. Rows expire after 10
-- minutes and should be cleaned up periodically.
CREATE TABLE IF NOT EXISTS device_codes (
  device_code TEXT PRIMARY KEY,
  user_code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','authorized','denied','expired','consumed')),
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  client_metadata TEXT NOT NULL,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  authorized_at TEXT,
  consumed_at TEXT,
  last_polled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status);
