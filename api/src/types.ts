// ---- Environment bindings ----
export interface Env {
  KEYS: KVNamespace;
  DB: D1Database;
  TRAFFIC_MONITOR: DurableObjectNamespace;
  ENCRYPTION_KEY: string;
  SESSION_SECRET: string;
  /**
   * Legacy OAuth secrets — kept optional in the type for graceful rollout.
   * As of the vault-backed OAuth migration (v1.0.2), the Worker reads
   * Google/GitHub OAuth client_id and client_secret directly from the
   * vault at runtime via the vault-client helper. These env vars are
   * no longer required; once the migration is verified in production,
   * they can be deleted with `wrangler secret delete`.
   */
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  /**
   * User ID that owns the OAuth credentials used by the Worker's own
   * sign-in flow. The vault-client helper decrypts those credentials
   * directly from KV + D1 at runtime, so no HTTP loopback or bootstrap
   * token is needed. This is not a secret — user IDs are stable
   * identifiers, not credentials. Stored via `wrangler secret put`
   * for convenience (centralized config) rather than for confidentiality.
   */
  APILOCKER_SERVICE_USER_ID?: string;
  /**
   * Comma-separated list of user IDs who can access the hidden
   * /v1/admin/metrics endpoint (and the /admin dashboard page). Set via
   * `wrangler secret put ADMIN_USER_IDS`. Non-listed users get a 404
   * instead of a 403, so the endpoint pretends not to exist.
   */
  ADMIN_USER_IDS?: string;
}

// ---- Auth types ----
export type AuthHeaderType = 'bearer' | 'x-api-key' | 'basic' | 'query' | 'custom';
export type RotationType = 'static' | 'hourly' | 'daily' | 'weekly' | 'monthly';
/**
 * OAuth sign-in provider ID. Previously a strict union of 'github' |
 * 'google'; as of the generic provider registry (v1.0.2+), this is a
 * free-form string that matches an entry in src/oauth-providers.ts.
 * The database column is TEXT so no schema change is needed.
 */
export type OAuthProvider = string;

// ---- Credential types (v1.0.0) ----
//
// Every credential in the vault has one of these types. The default is
// `api_key` (a single opaque secret string), which matches the only
// shape that existed before v1.0.0. `oauth2` is multi-field: the KV
// blob decrypts to a JSON object with client_id, client_secret,
// refresh_token, and OAuth endpoint URLs.
export type CredentialType = 'api_key' | 'oauth2';

// ---- Provider category (v1.0.0, for the three-bucket dashboard) ----
export type ProviderCategory = 'llm' | 'service' | 'oauth';

// ---- Database models ----
export interface User {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
  oauth_provider: OAuthProvider;
  oauth_id: string;
  master_token_hash: string | null;
  created_at: string;
  last_login_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  session_token_hash: string;
  expires_at: string;
  created_at: string;
}

export interface KeyMetadata {
  id: string;
  user_id: string;
  name: string;
  provider: string;
  tags: string;
  // base_url can be empty string for credentials that are vault-only
  // (not proxy-configured). The application treats '' as "not configured".
  base_url: string;
  auth_header_type: AuthHeaderType;
  created_at: string;
  rotated_at: string | null;
  // v1.0.0 columns
  credential_type: CredentialType;
  paused_at: string | null;
  /**
   * JSON array of historical names. Appended to whenever the credential
   * is renamed. The reveal endpoint uses this as a fallback so existing
   * .apilockerrc files and app code that reference old names keep working
   * indefinitely (lossless rename).
   *
   * Name-recycling: if a new credential is stored under a name that's in
   * some other row's previous_names, the store handler purges it so the
   * new credential reclaims the name.
   */
  previous_names: string;
}

// An extension of KeyMetadata that also carries info about how the row
// was matched in a query. Used by getKeysByNames (below) when the match
// came from the previous_names fallback rather than a direct name match.
export interface MatchedKeyMetadata extends KeyMetadata {
  /** null = direct name match; string = the alias that matched previous_names */
  matched_via_alias: string | null;
}

export interface Token {
  id: string;
  user_id: string;
  name: string;
  hashed_token: string;
  allowed_keys: string;
  rotation_type: RotationType;
  current_token_expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
  // Refresh-flow columns (nullable for static + legacy tokens)
  refresh_token_hash: string | null;
  previous_refresh_token_hash: string | null;
  refresh_token_family_id: string | null;
  last_refreshed_at: string | null;
  reuse_detected_at: string | null;
  // Pause/resume
  paused_at: string | null;
}

export interface AuditLog {
  id: string;
  user_id: string;
  token_id: string | null;
  key_id: string | null;
  provider: string | null;
  forward_path: string | null;
  source_ip: string | null;
  status_code: number | null;
  latency_ms: number | null;
  timestamp: string;
  // v1.0.0 launch-tracking
  country: string | null;
}

export interface Device {
  id: string;
  user_id: string;
  name: string;
  hardware_fingerprint_hash: string;
  registered_at: string;
  last_used_at: string;
  // Added in cli-auth migration (v0.2.0) — nullable for legacy rows
  token_hash: string | null;
  revoked_at: string | null;
  hostname: string | null;
  platform: string | null;
  platform_version: string | null;
  cli_version: string | null;
}

// ---- Device code (RFC 8628 device authorization grant state) ----

export type DeviceCodeStatus =
  | 'pending'
  | 'authorized'
  | 'denied'
  | 'expired'
  | 'consumed';

export interface DeviceCode {
  device_code: string;
  user_code: string;
  status: DeviceCodeStatus;
  user_id: string | null;
  device_id: string | null;
  client_metadata: string; // JSON blob
  ip_address: string | null;
  created_at: string;
  expires_at: string;
  authorized_at: string | null;
  consumed_at: string | null;
  last_polled_at: string | null;
}

export interface ClientMetadata {
  hostname?: string;
  platform?: string;
  platform_version?: string;
  cli_version?: string;
  requested_name?: string;
}

// ---- OAuth credential shape (v1.0.0) ----
//
// When a credential has credential_type='oauth2', the encrypted KV blob
// decrypts to a JSON string of OAuthCredentialFields. The encrypt/decrypt
// functions already operate on arbitrary strings, so no new crypto is
// needed — we just JSON.stringify on the way in and JSON.parse on the
// way out.
export interface OAuthCredentialFields {
  client_id: string;
  client_secret: string;
  refresh_token?: string;
  authorize_url?: string;
  token_url?: string;
  scopes?: string;
  redirect_uri?: string;
}

// ---- KV stored data ----
export interface EncryptedKeyRecord {
  ciphertext: string;
  iv: string;
}

// ---- API request/response types ----
export interface StoreKeyRequest {
  name: string;
  provider: string;
  tags?: string[];
  // Common optional fields
  credential_type?: CredentialType;
  base_url?: string;
  auth_header_type?: AuthHeaderType;
  // For credential_type='api_key' (default)
  key?: string;
  // For credential_type='oauth2'
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  authorize_url?: string;
  token_url?: string;
  scopes?: string;
  redirect_uri?: string;
}

export interface StoreKeyResponse {
  id: string;
  name: string;
  provider: string;
  created_at: string;
  proxy_endpoint: string;
}

export interface KeyListItem {
  id: string;
  name: string;
  provider: string;
  tags: string[];
  base_url: string;
  auth_header_type: AuthHeaderType;
  created_at: string;
}

export interface CreateTokenRequest {
  name: string;
  allowed_keys: string[];
  rotation_type?: RotationType;
}

export interface CreateTokenResponse {
  id: string;
  name: string;
  /** Short-lived access token — use this as Bearer on proxy calls */
  access_token: string;
  /** When the access token expires (null for static tokens) */
  access_token_expires_at: string | null;
  /** Long-lived refresh token — use this ONLY with /v1/tokens/refresh (null for static tokens) */
  refresh_token: string | null;
  allowed_keys: string[];
  rotation_type: RotationType;
  created_at: string;
}

export interface RefreshTokenResponse {
  id: string;
  access_token: string;
  access_token_expires_at: string;
  refresh_token: string;
}

// ---- Router types ----
export type RouteHandler = (
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
) => Promise<Response>;

export type UnauthenticatedRouteHandler = (
  request: Request,
  env: Env,
  params: Record<string, string>
) => Promise<Response>;

export interface Route {
  method: string;
  pattern: URLPattern;
  handler: RouteHandler | UnauthenticatedRouteHandler;
  auth: 'none' | 'session' | 'scoped';
}
