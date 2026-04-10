/**
 * oauth-proxy.ts — Level 2 OAuth orchestration for the proxy.
 *
 * When an app calls POST /v1/proxy/:keyId on an OAuth credential,
 * this module handles the entire token lifecycle:
 *
 *   1. Check KV cache for a still-valid access_token
 *   2. If expired or missing: decrypt the stored OAuth credential,
 *      call the upstream provider's token_url with grant_type=
 *      refresh_token, get a fresh access_token
 *   3. Cache the new access_token in KV with a TTL
 *   4. If the upstream provider rotated the refresh_token in its
 *      response, update the stored credential in the vault
 *   5. Return the access_token for the proxy to inject as a Bearer
 *      header into the outbound request
 *
 * The app never sees the client_secret, the refresh_token, or even
 * the access_token. It holds a scoped proxy token, calls the proxy,
 * and gets data back. This is the "Nango killer" feature.
 *
 * Cache strategy:
 *   - KV key: `oauth_cached_token:<keyId>`
 *   - TTL: (expires_in - 60) seconds from the upstream response
 *     (60s buffer so we refresh before the token actually expires)
 *   - On cache miss or expiry: refresh, cache, return
 *
 * Refresh token rotation:
 *   Some providers (Google, Microsoft, Salesforce) issue a new
 *   refresh_token on every refresh. When that happens, we decrypt
 *   the stored credential, update the refresh_token field, re-encrypt,
 *   and write it back to KV — the same partial-update pattern the
 *   Rotate Secret dashboard feature uses. This is transparent to the
 *   user; the vault silently keeps the latest refresh_token.
 */

import { Env, EncryptedKeyRecord, OAuthCredentialFields, KeyMetadata } from './types';
import { decrypt, encrypt } from './crypto';
import { getProviderTemplate } from './providers';

const OAUTH_CACHED_TOKEN_PREFIX = 'oauth_cached_token:';

// Minimum TTL for cached tokens. Even if upstream says expires_in=30,
// we cache for at least this long to avoid hammering the token endpoint.
const MIN_CACHE_TTL_SECONDS = 30;

// Buffer subtracted from expires_in to refresh BEFORE actual expiry.
const EXPIRY_BUFFER_SECONDS = 60;

interface CachedToken {
  access_token: string;
  expires_at: number; // Unix timestamp ms
}

interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string; // Present if provider rotates refresh tokens
  scope?: string;
  error?: string;
  error_description?: string;
}

/**
 * Get a valid access token for the given OAuth credential. Returns the
 * token string on success, or throws an Error with a user-facing message
 * on failure (expired refresh token, upstream error, etc.).
 *
 * This is the entry point called by proxy.ts for oauth2 credentials.
 */
export async function getOAuthAccessToken(
  env: Env,
  keyId: string,
  metadata: KeyMetadata
): Promise<string> {
  // 1. Check KV cache
  const cacheKey = `${OAUTH_CACHED_TOKEN_PREFIX}${keyId}`;
  const cachedJson = await env.KEYS.get(cacheKey);

  if (cachedJson) {
    try {
      const cached: CachedToken = JSON.parse(cachedJson);
      if (cached.expires_at > Date.now()) {
        return cached.access_token;
      }
      // Expired in our local tracking — fall through to refresh
    } catch {
      // Corrupt cache entry — fall through to refresh
    }
  }

  // 2. Cache miss or expired — need to refresh
  // Decrypt the stored OAuth credential to get client_id, client_secret,
  // refresh_token, and token_url
  const encryptedJson = await env.KEYS.get(keyId);
  if (!encryptedJson) {
    throw new Error('Encrypted credential data missing from vault');
  }

  let fields: OAuthCredentialFields;
  try {
    const record: EncryptedKeyRecord = JSON.parse(encryptedJson);
    const plaintext = await decrypt(record, env);
    fields = JSON.parse(plaintext) as OAuthCredentialFields;
  } catch (e) {
    throw new Error(`Failed to decrypt OAuth credential: ${(e as Error).message}`);
  }

  if (!fields.refresh_token) {
    throw new Error(
      'This OAuth credential has no refresh_token stored. ' +
      'Add one via the dashboard (Rotate Secret → New refresh token) ' +
      'or via `apilocker rotate --field refresh_token`.'
    );
  }

  // Resolve the token_url: stored credential > provider template > error
  const tokenUrl =
    fields.token_url ||
    getProviderTemplate(metadata.provider)?.token_url ||
    null;

  if (!tokenUrl) {
    throw new Error(
      `No token_url configured for provider "${metadata.provider}". ` +
      'Add one to the credential or use a provider template that includes it.'
    );
  }

  // 3. Call the upstream token endpoint
  const tokenResponse = await refreshAccessToken({
    tokenUrl,
    clientId: fields.client_id,
    clientSecret: fields.client_secret,
    refreshToken: fields.refresh_token,
  });

  // 4. Cache the new access token
  const expiresIn = tokenResponse.expires_in || 3600; // Default 1 hour
  const cacheTtl = Math.max(expiresIn - EXPIRY_BUFFER_SECONDS, MIN_CACHE_TTL_SECONDS);
  const expiresAt = Date.now() + cacheTtl * 1000;

  const cacheEntry: CachedToken = {
    access_token: tokenResponse.access_token,
    expires_at: expiresAt,
  };

  await env.KEYS.put(cacheKey, JSON.stringify(cacheEntry), {
    expirationTtl: cacheTtl,
  });

  // 5. If the provider rotated the refresh token, update the vault
  if (
    tokenResponse.refresh_token &&
    tokenResponse.refresh_token !== fields.refresh_token
  ) {
    try {
      await updateStoredRefreshToken(
        env,
        keyId,
        fields,
        tokenResponse.refresh_token
      );
    } catch (e) {
      // Non-fatal: the proxy call should still succeed even if we fail
      // to persist the new refresh token. But log it so we can debug.
      console.error(
        `[oauth-proxy] Failed to update rotated refresh_token for ${keyId}:`,
        e
      );
    }
  }

  return tokenResponse.access_token;
}

/**
 * Call the upstream OAuth token endpoint with grant_type=refresh_token.
 * Returns the parsed token response on success, or throws on failure.
 */
async function refreshAccessToken(params: {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: params.clientId,
    client_secret: params.clientSecret,
    refresh_token: params.refreshToken,
  });

  let response: Response;
  try {
    response = await fetch(params.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
    });
  } catch (e) {
    throw new Error(
      `Failed to reach token endpoint at ${params.tokenUrl}: ${(e as Error).message}`
    );
  }

  let data: TokenResponse;
  try {
    data = (await response.json()) as TokenResponse;
  } catch {
    throw new Error(
      `Token endpoint at ${params.tokenUrl} returned non-JSON response (HTTP ${response.status})`
    );
  }

  if (!response.ok || data.error) {
    const errorDetail = data.error_description || data.error || `HTTP ${response.status}`;
    throw new Error(
      `Token refresh failed: ${errorDetail}. ` +
      'The refresh_token may be expired or revoked. ' +
      'Re-authorize the OAuth app and update the credential with a new refresh_token.'
    );
  }

  if (!data.access_token) {
    throw new Error(
      'Token endpoint returned a success response but no access_token was present'
    );
  }

  return data;
}

/**
 * Update the stored OAuth credential with a new refresh_token from the
 * upstream provider. Uses the same decrypt-merge-encrypt pattern as the
 * dashboard's Rotate Secret feature.
 */
async function updateStoredRefreshToken(
  env: Env,
  keyId: string,
  currentFields: OAuthCredentialFields,
  newRefreshToken: string
): Promise<void> {
  const merged: OAuthCredentialFields = {
    ...currentFields,
    refresh_token: newRefreshToken,
  };
  const encrypted: EncryptedKeyRecord = await encrypt(
    JSON.stringify(merged),
    env
  );
  await env.KEYS.put(keyId, JSON.stringify(encrypted));
}
