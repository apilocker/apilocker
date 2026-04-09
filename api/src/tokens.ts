import { Env, CreateTokenRequest, RotationType } from './types';
import { generateId, generateToken, hashToken } from './crypto';
import {
  insertToken,
  listTokens,
  hardDeleteToken,
  pauseToken,
  resumeToken,
  findTokenByRefreshHash,
  rotateTokenPair,
  killTokenFamily,
} from './db';
import { jsonOk, jsonError } from './responses';

// ---- Access-token lifetimes, keyed off rotation_type ----
// Static tokens have no access-token expiry (single long-lived credential,
// no refresh token issued). Everything else gets a time-boxed access token
// and a long-lived refresh token that the client rotates transparently.
const ACCESS_TOKEN_LIFETIMES_MS: Record<Exclude<RotationType, 'static'>, number> = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
};

function accessTokenExpiresAt(rotationType: RotationType): string | null {
  if (rotationType === 'static') return null;
  const ms = ACCESS_TOKEN_LIFETIMES_MS[rotationType];
  return new Date(Date.now() + ms).toISOString();
}

export async function handleCreateToken(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: CreateTokenRequest;
  try {
    body = await request.json();
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!body.name || !body.allowed_keys || !body.allowed_keys.length) {
    return jsonError('Missing required fields: name, allowed_keys', 400);
  }

  const rotationType: RotationType = body.rotation_type || 'daily';
  const tokenId = generateId('tok');

  // Always issue an access token
  const rawAccessToken = generateToken();
  const accessHash = await hashToken(rawAccessToken);
  const accessExpiresAt = accessTokenExpiresAt(rotationType);

  // Rotating tokens also get a refresh token + family id. Static tokens don't.
  let rawRefreshToken: string | null = null;
  let refreshHash: string | null = null;
  let familyId: string | null = null;
  if (rotationType !== 'static') {
    rawRefreshToken = generateToken();
    refreshHash = await hashToken(rawRefreshToken);
    familyId = generateId('fam');
  }

  try {
    await insertToken(env, {
      id: tokenId,
      user_id: userId,
      name: body.name,
      hashed_token: accessHash,
      allowed_keys: JSON.stringify(body.allowed_keys),
      rotation_type: rotationType,
      current_token_expires_at: accessExpiresAt,
      created_at: new Date().toISOString(),
      refresh_token_hash: refreshHash,
      refresh_token_family_id: familyId,
    });
  } catch (e: any) {
    if (e.message?.includes('UNIQUE constraint')) {
      return jsonError('A token with this name already exists', 409);
    }
    throw e;
  }

  return jsonOk(
    {
      id: tokenId,
      name: body.name,
      access_token: rawAccessToken,
      access_token_expires_at: accessExpiresAt,
      refresh_token: rawRefreshToken,
      allowed_keys: body.allowed_keys,
      rotation_type: rotationType,
      created_at: new Date().toISOString(),
    },
    201
  );
}

export async function handleListTokens(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const tokens = await listTokens(env, userId);
  const result = tokens.map((t) => ({
    id: t.id,
    name: t.name,
    allowed_keys: JSON.parse(t.allowed_keys),
    rotation_type: t.rotation_type,
    expires_at: t.current_token_expires_at,
    created_at: t.created_at,
    last_refreshed_at: t.last_refreshed_at,
    revoked: !!t.revoked_at,
    paused: !!t.paused_at,
    compromised: !!t.reuse_detected_at,
  }));

  return jsonOk({ tokens: result });
}

/** Permanently delete a token (hard delete — row is removed from D1). */
export async function handleDeleteToken(
  _request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { tokenId } = params;
  const deleted = await hardDeleteToken(env, tokenId, userId);

  if (!deleted) {
    return jsonError('Token not found', 404);
  }

  return jsonOk({ deleted: true });
}

/** Temporarily disable a token. Resumable via /resume. */
export async function handlePauseToken(
  _request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { tokenId } = params;
  const paused = await pauseToken(env, tokenId, userId);

  if (!paused) {
    return jsonError('Token not found, already paused, or revoked', 404);
  }

  return jsonOk({ paused: true });
}

/** Resume a paused token. */
export async function handleResumeToken(
  _request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { tokenId } = params;
  const resumed = await resumeToken(env, tokenId, userId);

  if (!resumed) {
    return jsonError('Token not found or not paused', 404);
  }

  return jsonOk({ resumed: true });
}

/**
 * Refresh flow (OAuth2-style with reuse detection):
 *
 *   1. Client sends the refresh token in the Authorization header.
 *   2. We hash it and look it up.
 *   3. If it matches the CURRENT refresh hash → happy path: issue a new
 *      access + refresh pair and store the previous refresh hash so we can
 *      detect reuse within a short window.
 *   4. If it matches the PREVIOUS refresh hash (i.e. the attacker is
 *      replaying a stolen-but-already-rotated refresh token) → reuse
 *      detected. We invalidate the entire token family immediately.
 *   5. If it matches neither → generic 401.
 *
 * This endpoint is unauthenticated at the router level — we read the
 * refresh token directly from the Authorization header.
 */
export async function handleRefreshToken(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return jsonError('Missing refresh token', 401);
  }

  const providedRefresh = authHeader.slice(7);
  if (!providedRefresh) {
    return jsonError('Missing refresh token', 401);
  }

  const providedHash = await hashToken(providedRefresh);
  const row = await findTokenByRefreshHash(env, providedHash);

  if (!row) {
    return jsonError('Invalid refresh token', 401);
  }

  // Token has been revoked or the family is already compromised
  if (row.revoked_at || row.reuse_detected_at) {
    return jsonError('Refresh token is no longer valid', 401);
  }

  // Static tokens don't rotate and shouldn't hit this endpoint
  if (row.rotation_type === 'static' || !row.refresh_token_hash) {
    return jsonError('Static tokens cannot be refreshed', 400);
  }

  // --- REUSE DETECTION ---------------------------------------------------
  // If the caller is presenting the PREVIOUS hash (not the current one), an
  // attacker replayed an already-rotated refresh token. Kill the family.
  if (
    row.previous_refresh_token_hash &&
    providedHash === row.previous_refresh_token_hash &&
    providedHash !== row.refresh_token_hash
  ) {
    if (row.refresh_token_family_id) {
      await killTokenFamily(env, row.refresh_token_family_id);
    }
    return jsonError('Refresh token reuse detected — all tokens revoked', 401);
  }

  // Happy path — rotate both tokens
  const newAccessToken = generateToken();
  const newRefreshToken = generateToken();
  const newAccessHash = await hashToken(newAccessToken);
  const newRefreshHash = await hashToken(newRefreshToken);
  const newAccessExpiresAt = accessTokenExpiresAt(row.rotation_type) as string;

  await rotateTokenPair(
    env,
    row.id,
    newAccessHash,
    newRefreshHash,
    row.refresh_token_hash, // the old current hash becomes the new "previous"
    newAccessExpiresAt
  );

  return jsonOk({
    id: row.id,
    access_token: newAccessToken,
    access_token_expires_at: newAccessExpiresAt,
    refresh_token: newRefreshToken,
  });
}
