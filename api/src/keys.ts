import { Env, StoreKeyRequest, KeyMetadata, EncryptedKeyRecord, OAuthCredentialFields, CredentialType } from './types';
import { encrypt, decrypt } from './crypto';
import { generateId } from './crypto';
import { getProviderTemplate } from './providers';
import {
  insertKeyMetadata,
  listKeyMetadata,
  getKeyMetadata,
  deleteKeyMetadata,
  markKeyRotated,
  insertAuditLog,
  getKeyMetadataByName,
  renameKeyMetadata,
  pauseKeyMetadata,
  resumeKeyMetadata,
  purgeFromPreviousNames,
} from './db';
import { validateScopedToken } from './auth';
import { jsonOk, jsonError } from './responses';

/**
 * POST /v1/keys — store a credential in the vault.
 *
 * v1.0.0 supports two credential types:
 *
 *   1. api_key (default) — a single opaque secret string. Body must
 *      include `key`. Works for every provider template in the `llm`
 *      and `service` categories. `base_url` is optional now; a key
 *      stored without one is vault-only (usable via reveal/run/get/env
 *      but not via the proxy).
 *
 *   2. oauth2 — a multi-field credential. Body must include
 *      `client_id` and `client_secret`. Optionally: `refresh_token`,
 *      `authorize_url`, `token_url`, `scopes`, `redirect_uri`. These
 *      fields are packed into a JSON object and encrypted as a single
 *      KV blob. OAuth credentials are never usable via the proxy in
 *      v1.0.0 — they're reveal-only. (Level 2 OAuth orchestration,
 *      where the proxy performs the OAuth dance itself, is a future
 *      roadmap item.)
 */
export async function handleStoreKey(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: StoreKeyRequest;
  try {
    body = await request.json();
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!body.name || !body.provider) {
    return jsonError('Missing required fields: name, provider', 400);
  }

  // Resolve template and determine credential type
  const template = getProviderTemplate(body.provider);
  const credentialType: CredentialType =
    body.credential_type || template?.credential_type || 'api_key';

  // Determine the plaintext blob to encrypt based on credential type
  let plaintext: string;
  if (credentialType === 'oauth2') {
    if (!body.client_id || !body.client_secret) {
      return jsonError(
        'OAuth credentials require client_id and client_secret',
        400
      );
    }
    const oauthFields: OAuthCredentialFields = {
      client_id: body.client_id,
      client_secret: body.client_secret,
      refresh_token: body.refresh_token,
      authorize_url: body.authorize_url || template?.authorize_url,
      token_url: body.token_url || template?.token_url,
      scopes: body.scopes || template?.default_scopes,
      redirect_uri: body.redirect_uri || template?.default_redirect_uri,
    };
    plaintext = JSON.stringify(oauthFields);
  } else {
    // api_key: single-string credential
    if (!body.key) {
      return jsonError('Missing required field: key', 400);
    }
    plaintext = body.key;
  }

  // Resolve base_url: user-supplied > template > empty string
  // (empty string is the v1.0.0 convention for "vault-only, not
  // configured for proxy"). SQLite schema is still NOT NULL for
  // backwards compat, so we store '' rather than NULL.
  const baseUrl = body.base_url ?? template?.base_url ?? '';
  const authHeaderType =
    body.auth_header_type || template?.auth_header_type || 'bearer';

  const keyId = generateId('key');

  // Encrypt the plaintext (single string or JSON-stringified OAuth fields)
  const encrypted: EncryptedKeyRecord = await encrypt(plaintext, env);

  // Store encrypted blob in KV
  await env.KEYS.put(keyId, JSON.stringify(encrypted));

  // Store metadata in D1
  const metadata: KeyMetadata = {
    id: keyId,
    user_id: userId,
    name: body.name,
    provider: body.provider,
    tags: JSON.stringify(body.tags || []),
    base_url: baseUrl,
    auth_header_type: authHeaderType,
    created_at: new Date().toISOString(),
    rotated_at: null,
    credential_type: credentialType,
    paused_at: null,
    previous_names: '[]',
  };

  try {
    await insertKeyMetadata(env, metadata);
  } catch (e: any) {
    // Clean up KV if D1 insert fails
    await env.KEYS.delete(keyId);
    if (e.message?.includes('UNIQUE constraint')) {
      return jsonError('A key with this name already exists', 409);
    }
    throw e;
  }

  // Name-recycling: if this name was in any other credential's
  // previous_names (legacy alias), purge it so the new credential
  // cleanly reclaims the name. No-op if not.
  await purgeFromPreviousNames(env, userId, body.name).catch((e) => {
    console.error('purgeFromPreviousNames failed (non-fatal):', e);
  });

  return jsonOk(
    {
      id: keyId,
      name: body.name,
      provider: body.provider,
      credential_type: credentialType,
      created_at: metadata.created_at,
      proxy_endpoint: baseUrl ? `/v1/proxy/${keyId}` : null,
    },
    201
  );
}

export async function handleListKeys(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const keys = await listKeyMetadata(env, userId);
  const result = keys.map((k) => ({
    id: k.id,
    name: k.name,
    provider: k.provider,
    category: getProviderTemplate(k.provider)?.category ?? 'service',
    credential_type: k.credential_type ?? 'api_key',
    tags: safeParseTags(k.tags),
    base_url: k.base_url || null,
    auth_header_type: k.auth_header_type,
    created_at: k.created_at,
    rotated_at: k.rotated_at,
    paused_at: k.paused_at,
  }));

  return jsonOk({ keys: result });
}

/**
 * Safely parse the tags JSON blob from a KeyMetadata row. Returns an
 * empty array on any parse error — we never want a corrupted tags value
 * to take down the whole list endpoint.
 */
function safeParseTags(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((t) => typeof t === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * SDK auto-discovery endpoint: returns the keys that THIS scoped token can
 * access, keyed by friendly alias (the key's `name` field).
 *
 * Powers the "one-line .env" experience — the client SDK hits this on first
 * call, builds a local alias → keyId map, and from then on the developer
 * writes `client.proxy('openai', ...)` instead of having to know key IDs.
 *
 * Only metadata is returned (id, alias, provider, base_url, auth type).
 * The encrypted key blobs never leave the vault.
 *
 * Registered as an unauthenticated route so the handler can access the
 * token's allowedKeys directly (the standard 'scoped' router path only
 * forwards userId to the handler).
 */
export async function handleListAllowedKeys(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  const tokenInfo = await validateScopedToken(request, env);
  if (!tokenInfo) return jsonError('Unauthorized', 401);

  const all = await listKeyMetadata(env, tokenInfo.userId);
  const allowed = new Set(tokenInfo.allowedKeys);
  const result = all
    .filter((k) => allowed.has(k.id))
    .map((k) => ({
      id: k.id,
      alias: k.name,
      provider: k.provider,
      base_url: k.base_url,
      auth_header_type: k.auth_header_type,
    }));

  return jsonOk({ keys: result });
}

export async function handleDeleteKey(
  _request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;

  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }

  // Delete from both KV and D1
  await Promise.all([
    env.KEYS.delete(keyId),
    deleteKeyMetadata(env, keyId, userId),
  ]);

  return jsonOk({ deleted: true });
}

/**
 * POST /v1/keys/:keyId/rename — rename a credential.
 *
 * Updates the `name` field on keys_metadata. The KV blob is not touched.
 * Enforces the unique(user_id, name) constraint via catch-and-translate.
 *
 * Important caveat surfaced to users in the UI: if any .apilockerrc
 * files reference the old alias, they silently break. The CLI + web
 * rename flows warn about this.
 */
export async function handleRenameKey(
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;

  let body: { new_name?: string };
  try {
    body = (await request.json()) as { new_name?: string };
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!body.new_name || typeof body.new_name !== 'string') {
    return jsonError('Missing required field: new_name', 400);
  }

  const newName = body.new_name.trim();
  if (newName.length === 0 || newName.length > 128) {
    return jsonError('new_name must be between 1 and 128 characters', 400);
  }

  // Confirm ownership and existence
  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }

  // No-op if nothing changed
  if (metadata.name === newName) {
    return jsonOk({ id: keyId, name: newName, unchanged: true });
  }

  // Check collision
  const existing = await getKeyMetadataByName(env, userId, newName);
  if (existing) {
    return jsonError(`A key named "${newName}" already exists`, 409);
  }

  const ok = await renameKeyMetadata(env, keyId, userId, newName);
  if (!ok) {
    return jsonError('Rename failed', 500);
  }

  // Audit-log the rename
  const sourceIp =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null;
  const country = request.headers.get('CF-IPCountry') || null;
  await insertAuditLog(env, {
    id: generateId('log'),
    user_id: userId,
    token_id: null,
    key_id: keyId,
    provider: metadata.provider,
    forward_path: `/rename:${metadata.name}→${newName}`,
    source_ip: sourceIp,
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country,
  }).catch((e) => console.error('Audit log insert failed:', e));

  return jsonOk({
    id: keyId,
    name: newName,
    previous_name: metadata.name,
  });
}

/**
 * POST /v1/keys/:keyId/pause — pause a credential.
 *
 * Sets paused_at on the metadata row. The proxy handler refuses to
 * forward calls through a paused key (returns 423 Locked). Reveal /
 * run / get / env still work on paused keys — pausing is proxy-only
 * enforcement, so the user can still rotate or inspect the key without
 * un-pausing it.
 */
export async function handlePauseKey(
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;

  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }
  if (metadata.paused_at) {
    return jsonError('Key is already paused', 409);
  }

  const ok = await pauseKeyMetadata(env, keyId, userId);
  if (!ok) {
    return jsonError('Pause failed', 500);
  }

  const sourceIp =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null;
  const country = request.headers.get('CF-IPCountry') || null;
  await insertAuditLog(env, {
    id: generateId('log'),
    user_id: userId,
    token_id: null,
    key_id: keyId,
    provider: metadata.provider,
    forward_path: '/pause',
    source_ip: sourceIp,
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country,
  }).catch((e) => console.error('Audit log insert failed:', e));

  return jsonOk({ id: keyId, name: metadata.name, paused: true });
}

/**
 * POST /v1/keys/:keyId/resume — resume a paused credential.
 */
export async function handleResumeKey(
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;

  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }
  if (!metadata.paused_at) {
    return jsonError('Key is not paused', 409);
  }

  const ok = await resumeKeyMetadata(env, keyId, userId);
  if (!ok) {
    return jsonError('Resume failed', 500);
  }

  const sourceIp =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null;
  const country = request.headers.get('CF-IPCountry') || null;
  await insertAuditLog(env, {
    id: generateId('log'),
    user_id: userId,
    token_id: null,
    key_id: keyId,
    provider: metadata.provider,
    forward_path: '/resume',
    source_ip: sourceIp,
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country,
  }).catch((e) => console.error('Audit log insert failed:', e));

  return jsonOk({ id: keyId, name: metadata.name, paused: false });
}

/**
 * POST /v1/keys/:keyId/rotate — replace (part of) a credential's value.
 *
 * Behavior depends on the credential type:
 *
 *   • api_key — body must contain `{ key: "<new-value>" }`. The entire
 *     encrypted blob is replaced with the new single string. Same as
 *     pre-v1.0.1 behavior.
 *
 *   • oauth2 — body must contain at least one of `client_secret` or
 *     `refresh_token`. The existing encrypted JSON blob is decrypted,
 *     the supplied fields are merged in, and the result is re-encrypted
 *     and written back. All OTHER OAuth fields (client_id, authorize_url,
 *     token_url, scopes, redirect_uri) are preserved untouched. This is
 *     the important property: you're rotating the compromised secret
 *     without having to delete and recreate the whole OAuth entry and
 *     re-enter every field.
 *
 * In both cases, `rotated_at` is stamped and the rotation is audit-logged
 * with the user's country. The response contains no secrets.
 */
export async function handleRotateKey(
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;

  let body: {
    key?: string;
    client_secret?: string;
    refresh_token?: string;
  };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  // Confirm the key exists and belongs to the caller
  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }

  const credentialType: CredentialType = metadata.credential_type ?? 'api_key';

  let newPlaintext: string;
  let rotatedFields: string[];

  if (credentialType === 'oauth2') {
    // Partial rotation: require at least one of client_secret / refresh_token
    const hasClientSecret =
      typeof body.client_secret === 'string' && body.client_secret.length > 0;
    const hasRefreshToken =
      typeof body.refresh_token === 'string' && body.refresh_token.length > 0;

    if (!hasClientSecret && !hasRefreshToken) {
      return jsonError(
        'OAuth rotation requires at least one of: client_secret, refresh_token',
        400
      );
    }

    // Load and decrypt the existing blob so we can preserve untouched fields
    const existingEncryptedJson = await env.KEYS.get(keyId);
    if (!existingEncryptedJson) {
      return jsonError('Encrypted vault entry missing for this key', 500);
    }
    let existingFields: OAuthCredentialFields;
    try {
      const record: EncryptedKeyRecord = JSON.parse(existingEncryptedJson);
      const plaintext = await decrypt(record, env);
      existingFields = JSON.parse(plaintext) as OAuthCredentialFields;
    } catch (e) {
      console.error(`Failed to decrypt existing OAuth blob for ${keyId}:`, e);
      return jsonError('Could not read existing OAuth credential', 500);
    }

    // Merge: only overwrite the fields the caller explicitly sent.
    // Everything else (client_id, authorize_url, token_url, scopes, redirect_uri)
    // is preserved untouched — that's the whole point of partial rotation.
    const merged: OAuthCredentialFields = {
      ...existingFields,
      ...(hasClientSecret && { client_secret: body.client_secret }),
      ...(hasRefreshToken && { refresh_token: body.refresh_token }),
    };
    newPlaintext = JSON.stringify(merged);

    rotatedFields = [];
    if (hasClientSecret) rotatedFields.push('client_secret');
    if (hasRefreshToken) rotatedFields.push('refresh_token');
  } else {
    // api_key: full replacement, body.key is the new single secret
    if (!body.key || typeof body.key !== 'string' || body.key.length === 0) {
      return jsonError('Missing required field: key (the new secret value)', 400);
    }
    newPlaintext = body.key;
    rotatedFields = ['value'];
  }

  // Encrypt the new plaintext and overwrite the KV blob
  const encrypted: EncryptedKeyRecord = await encrypt(newPlaintext, env);
  await env.KEYS.put(keyId, JSON.stringify(encrypted));

  // Stamp rotated_at on the metadata row
  await markKeyRotated(env, keyId, userId);

  // Audit-log the rotation. For OAuth partials we record which fields
  // were rotated in the forward_path tag so the activity feed can
  // show "rotated client_secret" vs "rotated client_secret, refresh_token".
  const sourceIp =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null;
  const country = request.headers.get('CF-IPCountry') || null;
  const forwardPath =
    credentialType === 'oauth2'
      ? `/rotate:${rotatedFields.join(',')}`
      : '/rotate';
  await insertAuditLog(env, {
    id: generateId('log'),
    user_id: userId,
    token_id: null,
    key_id: keyId,
    provider: metadata.provider,
    forward_path: forwardPath,
    source_ip: sourceIp,
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country,
  }).catch((e) => console.error('Audit log insert failed:', e));

  return jsonOk({
    id: metadata.id,
    name: metadata.name,
    provider: metadata.provider,
    credential_type: credentialType,
    rotated_at: new Date().toISOString(),
    rotated_fields: rotatedFields,
  });
}
