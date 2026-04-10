-- Schema migration: OAuth 2.1 authorization server tables (v1.0.3)
--
-- Adds support for API Locker being a standalone OAuth 2.1 authorization
-- server. This is required by Anthropic's Claude Connectors Directory
-- submission guide: remote MCP servers must implement the OAuth 2.0
-- authorization code flow with PKCE so users on claude.ai can click
-- "Add connector" and sign into API Locker through a standard OAuth
-- popup (rather than pasting master tokens).
--
-- Scope model:
--   vault:read   — list/get/reveal credentials, activity, doctor
--   vault:write  — rotate, rename, pause/resume, delete, create tokens
--   vault:proxy  — make proxied API calls through stored credentials
--
-- Two new tables:
--   1. oauth_clients        — DCR-registered clients (RFC 7591)
--   2. oauth_access_tokens  — issued access + refresh tokens with
--                             rotation family + reuse detection

-- ============================================================
-- oauth_clients — Dynamic Client Registration records
-- ============================================================
--
-- Each client is a caller that POST'd to /v1/oauth/register. Clients
-- are public (no client_secret) because they're primarily browser-based
-- MCP clients that can't keep a secret. PKCE provides the auth code
-- interception protection that a client secret would normally give.
CREATE TABLE IF NOT EXISTS oauth_clients (
  -- Client ID returned to the caller. Format: alc_<uuid>
  id TEXT PRIMARY KEY,
  -- Human-readable name shown on the consent screen. Provided by
  -- the caller during DCR; we trust but don't verify.
  client_name TEXT NOT NULL,
  -- JSON array of allowed redirect URIs. At least one required.
  -- Every /authorize call must supply a redirect_uri that matches
  -- one of these exactly.
  redirect_uris TEXT NOT NULL,
  -- JSON array of allowed grant types. Typically
  -- ["authorization_code", "refresh_token"].
  grant_types TEXT NOT NULL,
  -- JSON array of allowed response types. Typically ["code"].
  response_types TEXT NOT NULL,
  -- Token endpoint auth method. For public clients we accept
  -- "none" (no client auth, PKCE instead).
  token_endpoint_auth_method TEXT NOT NULL,
  -- Default / requested scope, space-separated.
  scope TEXT NOT NULL,
  -- Optional UI bits shown on the consent screen.
  logo_uri TEXT,
  client_uri TEXT,
  -- Timestamps.
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  -- Set when an admin disables this client. Tokens for disabled
  -- clients are rejected at validation time.
  disabled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_created ON oauth_clients(created_at);

-- ============================================================
-- oauth_access_tokens — issued tokens with refresh rotation
-- ============================================================
--
-- Each row represents one OAuth grant: a (user_id, client_id, scopes)
-- tuple with an access token and optionally a refresh token. Refresh
-- tokens rotate on use — every refresh produces a new (access, refresh)
-- pair and the old refresh becomes unusable. Reusing an old refresh
-- token is treated as a token theft indicator and revokes the entire
-- family (all rotations descended from the same authorization code).
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
  id TEXT PRIMARY KEY,                     -- oat_<uuid>
  user_id TEXT NOT NULL,                   -- which API Locker user
  client_id TEXT NOT NULL,                 -- which DCR client
  scopes TEXT NOT NULL,                    -- space-separated approved scopes

  -- The current access token, SHA-256 hashed so a DB compromise can't
  -- be turned into stolen tokens. Plaintext is returned to the client
  -- once at issuance and never again.
  access_token_hash TEXT NOT NULL UNIQUE,
  access_token_expires_at TEXT NOT NULL,

  -- Current refresh token, SHA-256 hashed. Nullable only if the grant
  -- explicitly chose not to issue one (we always issue one for now).
  refresh_token_hash TEXT UNIQUE,
  refresh_token_expires_at TEXT,

  -- Previous refresh token hash, kept one rotation in the past so we
  -- can detect reuse. If a refresh call matches this column instead of
  -- refresh_token_hash, the entire family is revoked.
  previous_refresh_token_hash TEXT,

  -- Random ID shared by every access_token row in the same grant
  -- family. When reuse is detected, we revoke all rows with this
  -- family_id in one SQL statement.
  refresh_token_family_id TEXT NOT NULL,

  -- Timestamps.
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_refreshed_at TEXT,

  -- Set when reuse is detected. Triggers family-wide revoke.
  reuse_detected_at TEXT,

  -- Set on explicit revoke (admin, user, or family revoke).
  revoked_at TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (client_id) REFERENCES oauth_clients(id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_access_hash ON oauth_access_tokens(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh_hash ON oauth_access_tokens(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family ON oauth_access_tokens(refresh_token_family_id);
