/**
 * vault-client.ts — in-process vault reader for the Worker itself.
 *
 * The Worker's own OAuth sign-in flow (Google + GitHub) historically
 * read its client_id and client_secret from wrangler-level secrets
 * (`GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`, etc.). That worked,
 * but meant every rotation required a manual `wrangler secret put`
 * step after updating the vault — which was error-prone and failed
 * on several attempts with literal-vs-placeholder mistakes.
 *
 * This module turns that model inside out: the vault IS the source of
 * truth, and the Worker reads its own OAuth credentials from the vault
 * at request time. No HTTP loopback, no bootstrap token, no sync
 * command. When the user rotates a credential in the dashboard, the
 * next OAuth request picks up the new value (after a short cache TTL).
 *
 * Why in-process instead of HTTP loopback:
 *   - Zero network latency on the hot path
 *   - No token management / auth layer to get wrong
 *   - Cold-start-safe: no bootstrap credential to bootstrap
 *   - Still audit-logged — we insert a `/vault-fetch` entry for
 *     every uncached read, same as reveal would
 *
 * Cache strategy:
 *   - In-memory Map, scoped to the Worker isolate instance
 *   - 60s TTL — OAuth credentials don't change often, but after a
 *     rotation users should see the new value reflected within a
 *     minute without having to redeploy
 *   - On decrypt / DB errors, we log and throw — the OAuth handler
 *     will return a 500 to the user rather than fall back to a stale
 *     or wrong value
 */

import { Env, EncryptedKeyRecord, OAuthCredentialFields } from './types';
import { decrypt, generateId } from './crypto';
import { getKeysByNames, insertAuditLog } from './db';

const CACHE_TTL_MS = 60 * 1000; // 60 seconds

interface CacheEntry {
  value: OAuthCredentialFields;
  expires_at: number;
}

// Module-level cache keyed by `${userId}:${keyName}`.
// Survives for the lifetime of the Worker isolate, which on Cloudflare
// is typically minutes to hours. Rotation picks up within TTL.
const cache = new Map<string, CacheEntry>();

function cacheKey(userId: string, keyName: string): string {
  return `${userId}:${keyName}`;
}

/**
 * Fetch an OAuth credential from the vault, bypassing HTTP.
 *
 * Looks up the key by name under the configured service user, decrypts
 * the JSON blob, and returns the parsed OAuthCredentialFields. Cached
 * for 60s per (userId, keyName) pair.
 *
 * Throws if:
 *   - The credential isn't found
 *   - The credential isn't an oauth2 credential
 *   - Decryption or JSON parsing fails
 *
 * Audit log: one `/vault-fetch` entry per cache miss, with the
 * synthetic source_ip '127.0.0.1' (the Worker is calling itself) and
 * country null.
 */
export async function fetchOAuthCredential(
  env: Env,
  userId: string,
  keyName: string
): Promise<OAuthCredentialFields> {
  const key = cacheKey(userId, keyName);
  const cached = cache.get(key);
  const now = Date.now();

  if (cached && cached.expires_at > now) {
    return cached.value;
  }

  // Cache miss (or expired). Load from D1 + KV.
  const rows = await getKeysByNames(env, userId, [keyName]);
  if (rows.length === 0) {
    throw new Error(
      `Vault credential not found: "${keyName}" for user ${userId}`
    );
  }

  const row = rows[0];
  if (row.credential_type !== 'oauth2') {
    throw new Error(
      `Vault credential "${keyName}" is not an OAuth credential (got ${row.credential_type})`
    );
  }

  const encryptedJson = await env.KEYS.get(row.id);
  if (!encryptedJson) {
    throw new Error(`KV blob missing for vault credential "${keyName}"`);
  }

  let fields: OAuthCredentialFields;
  try {
    const record: EncryptedKeyRecord = JSON.parse(encryptedJson);
    const plaintext = await decrypt(record, env);
    fields = JSON.parse(plaintext) as OAuthCredentialFields;
  } catch (e) {
    throw new Error(
      `Failed to decrypt vault credential "${keyName}": ${(e as Error).message}`
    );
  }

  // Insert into cache
  cache.set(key, {
    value: fields,
    expires_at: now + CACHE_TTL_MS,
  });

  // Audit log: fire-and-forget, don't block on failures
  insertAuditLog(env, {
    id: generateId('log'),
    user_id: userId,
    token_id: null,
    key_id: row.id,
    provider: row.provider,
    forward_path: '/vault-fetch',
    source_ip: '127.0.0.1',
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country: null,
  }).catch((e) => console.error('vault-client audit log failed:', e));

  return fields;
}

/**
 * Resolve an OAuth credential by its vault key name, using the configured
 * service user. This is the generic entry point called by the OAuth
 * handler once it has looked up the provider config and knows which
 * vault key to fetch.
 *
 * Throws if APILOCKER_SERVICE_USER_ID is unset or the credential
 * doesn't exist / can't be decrypted.
 */
export async function getVaultOAuthCredential(
  env: Env,
  vaultKeyName: string
): Promise<OAuthCredentialFields> {
  const userId = env.APILOCKER_SERVICE_USER_ID;
  if (!userId) {
    throw new Error(
      'APILOCKER_SERVICE_USER_ID is not configured on the Worker'
    );
  }
  return fetchOAuthCredential(env, userId, vaultKeyName);
}

/**
 * Check whether a given vault key name has a credential for the
 * configured service user. Used by the /v1/auth/providers discovery
 * endpoint to decide which provider buttons to render on the login
 * page — a provider is "enabled" iff its credential exists.
 *
 * Returns true if the credential exists and is oauth2, false otherwise.
 * Never throws — any error is treated as "not enabled."
 */
export async function vaultCredentialExists(
  env: Env,
  vaultKeyName: string
): Promise<boolean> {
  const userId = env.APILOCKER_SERVICE_USER_ID;
  if (!userId) return false;

  // Fast path: cached entry counts as "exists"
  const cached = cache.get(cacheKey(userId, vaultKeyName));
  if (cached && cached.expires_at > Date.now()) return true;

  try {
    const rows = await getKeysByNames(env, userId, [vaultKeyName]);
    return rows.length > 0 && rows[0].credential_type === 'oauth2';
  } catch {
    return false;
  }
}

/**
 * Clear the vault-client cache. Useful for tests, or if you want
 * rotation to take effect instantly instead of waiting the TTL. Not
 * called automatically anywhere today.
 */
export function clearVaultCache(): void {
  cache.clear();
}
