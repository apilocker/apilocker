/**
 * CLI device authorization flow (RFC 8628).
 *
 * Replaces the "paste master token from dashboard" flow with a browser
 * confirmation flow. See `docs/cli-auth.md` for the end-to-end description.
 *
 * Endpoints:
 *   POST /v1/cli-auth/start    — public, CLI kicks off a flow, gets codes
 *   GET  /v1/cli-auth/info     — public, the /cli-auth web page fetches
 *                                display info (device name, IP, countdown)
 *   POST /v1/cli-auth/approve  — session-authed, web page confirms authz
 *   POST /v1/cli-auth/deny     — session-authed, web page cancels
 *   POST /v1/cli-auth/poll     — public, CLI polls for completion
 *
 * Security properties:
 *   - device_code is 32 bytes base64url, 256 bits of entropy, unguessable
 *   - user_code is 8 chars from a 30-char unambiguous alphabet (~656B codes)
 *   - both expire 10 minutes after /start
 *   - approve/deny require a valid session cookie (enforced by router)
 *   - poll returns the master token exactly once then marks the code consumed
 *   - the master token lives in KV with 60s TTL between approve and poll,
 *     encrypted at rest by CF's infrastructure
 *   - returned master tokens are device-scoped (stored in devices.token_hash),
 *     so revoking a device invalidates only that device's token
 */

import { Env, ClientMetadata } from './types';
import {
  insertDeviceCode,
  getDeviceCodeByUserCode,
  getDeviceCodeByDeviceCode,
  authorizeDeviceCode,
  denyDeviceCode,
  markDeviceCodeConsumed,
  updateDeviceCodePolled,
  insertDevice,
  getUserById,
} from './db';
import { generateId, generateToken, hashToken } from './crypto';
import { jsonOk, jsonError } from './responses';

const DEVICE_CODE_TTL_SECONDS = 600; // 10 minutes
const POLL_MIN_INTERVAL_SECONDS = 2;
const MASTER_TOKEN_BRIDGE_PREFIX = 'cli_auth_token:';
const MASTER_TOKEN_BRIDGE_TTL_SECONDS = 60;

// 30-char alphabet — no 0/O, no 1/I/L, no U (often confused with V in some fonts)
const USER_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';

/**
 * Generate a random 8-char user code in the format XXXX-XXXX.
 * Uses crypto.getRandomValues for uniform distribution.
 */
function generateUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];
    if (i === 3) code += '-';
  }
  return code;
}

/**
 * Normalize a user-supplied user_code to the canonical format.
 * Strips whitespace, uppercases, adds the hyphen if missing.
 * Returns null if the result isn't a valid 8-char code.
 */
function normalizeUserCode(input: string | null | undefined): string | null {
  if (!input) return null;
  const cleaned = input.toUpperCase().replace(/[\s-]/g, '');
  if (cleaned.length !== 8) return null;
  for (const char of cleaned) {
    if (!USER_CODE_ALPHABET.includes(char)) return null;
  }
  return `${cleaned.slice(0, 4)}-${cleaned.slice(4)}`;
}

function parseClientMetadata(json: string): ClientMetadata {
  try {
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null) return {};
    return parsed as ClientMetadata;
  } catch {
    return {};
  }
}

function friendlyDeviceName(metadata: ClientMetadata): string {
  if (metadata.requested_name) return metadata.requested_name;
  const parts = [metadata.hostname, metadata.platform].filter(Boolean);
  return parts.join(' · ') || 'Unknown device';
}

function captureIp(request: Request): string | null {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
    null
  );
}

// ---- POST /v1/cli-auth/start ----

export async function handleCliAuthStart(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  let body: { client_metadata?: ClientMetadata; name?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const metadata: ClientMetadata = {
    hostname: body.client_metadata?.hostname?.slice(0, 64),
    platform: body.client_metadata?.platform?.slice(0, 32),
    platform_version: body.client_metadata?.platform_version?.slice(0, 64),
    cli_version: body.client_metadata?.cli_version?.slice(0, 32),
    requested_name: body.name?.slice(0, 64),
  };

  // Generate codes. device_code collision chance is astronomically low
  // (2^256); user_code collisions are possible but rare enough that one
  // retry handles it. We don't loop — if a collision happens, the client
  // can just hit /start again.
  const deviceCode = generateToken();
  const userCode = generateUserCode();

  const expiresAt = new Date(Date.now() + DEVICE_CODE_TTL_SECONDS * 1000).toISOString();

  try {
    await insertDeviceCode(env, {
      device_code: deviceCode,
      user_code: userCode,
      client_metadata: JSON.stringify(metadata),
      ip_address: captureIp(request),
      expires_at: expiresAt,
    });
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return jsonError('User code collision, please retry', 503);
    }
    throw e;
  }

  return jsonOk({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: 'https://www.apilocker.app/cli-auth',
    verification_uri_complete: `https://www.apilocker.app/cli-auth?code=${encodeURIComponent(userCode)}`,
    expires_in: DEVICE_CODE_TTL_SECONDS,
    interval: POLL_MIN_INTERVAL_SECONDS,
  });
}

// ---- GET /v1/cli-auth/info?user_code=ABCD-1234 ----

export async function handleCliAuthInfo(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  const url = new URL(request.url);
  const rawCode = url.searchParams.get('user_code');
  const userCode = normalizeUserCode(rawCode);
  if (!userCode) {
    return jsonError('Invalid user code', 400);
  }

  const row = await getDeviceCodeByUserCode(env, userCode);
  if (!row) return jsonError('Code not found', 404);
  if (row.status !== 'pending') return jsonError(`Code is ${row.status}`, 410);

  const expiresAt = new Date(row.expires_at).getTime();
  const now = Date.now();
  if (expiresAt < now) return jsonError('Code expired', 410);

  const metadata = parseClientMetadata(row.client_metadata);

  return jsonOk({
    user_code: row.user_code,
    device_name: friendlyDeviceName(metadata),
    hostname: metadata.hostname ?? null,
    platform: metadata.platform ?? null,
    platform_version: metadata.platform_version ?? null,
    cli_version: metadata.cli_version ?? null,
    ip_address: row.ip_address,
    expires_in: Math.max(0, Math.floor((expiresAt - now) / 1000)),
  });
}

// ---- POST /v1/cli-auth/approve ----

export async function handleCliAuthApprove(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: { user_code?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const userCode = normalizeUserCode(body.user_code);
  if (!userCode) return jsonError('Invalid user code', 400);

  const row = await getDeviceCodeByUserCode(env, userCode);
  if (!row) return jsonError('Code not found', 404);
  if (row.status !== 'pending') return jsonError(`Code is ${row.status}`, 410);
  if (new Date(row.expires_at) < new Date()) {
    return jsonError('Code expired', 410);
  }

  const metadata = parseClientMetadata(row.client_metadata);

  // Create a new device row. The fingerprint for a CLI auth device is
  // the device_code itself — these are per-registration, not per-hardware.
  // (Hardware fingerprint is still captured separately on the CLI side as
  // defense-in-depth; we hash the device_code here so each row has a
  // unique fingerprint column value.)
  const masterToken = generateToken();
  const masterTokenHash = await hashToken(masterToken);
  const deviceId = generateId('dev');
  const fingerprintHash = await hashToken(row.device_code);

  await insertDevice(env, {
    id: deviceId,
    user_id: userId,
    name: friendlyDeviceName(metadata),
    hardware_fingerprint_hash: fingerprintHash,
    token_hash: masterTokenHash,
    hostname: metadata.hostname ?? null,
    platform: metadata.platform ?? null,
    platform_version: metadata.platform_version ?? null,
    cli_version: metadata.cli_version ?? null,
  });

  const authorized = await authorizeDeviceCode(env, userCode, userId, deviceId);
  if (!authorized) {
    return jsonError('Code could not be authorized (already claimed?)', 410);
  }

  // Bridge the master token via KV with 60s TTL. The CLI's next /poll call
  // picks it up and this KV entry is deleted. If /poll never happens, the
  // entry expires automatically.
  await env.KEYS.put(
    `${MASTER_TOKEN_BRIDGE_PREFIX}${row.device_code}`,
    masterToken,
    { expirationTtl: MASTER_TOKEN_BRIDGE_TTL_SECONDS }
  );

  return jsonOk({
    ok: true,
    device_name: friendlyDeviceName(metadata),
  });
}

// ---- POST /v1/cli-auth/deny ----

export async function handleCliAuthDeny(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  _userId: string
): Promise<Response> {
  let body: { user_code?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const userCode = normalizeUserCode(body.user_code);
  if (!userCode) return jsonError('Invalid user code', 400);

  const ok = await denyDeviceCode(env, userCode);
  if (!ok) return jsonError('Code not found or already resolved', 410);

  return jsonOk({ ok: true });
}

// ---- POST /v1/cli-auth/poll ----

export async function handleCliAuthPoll(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  let body: { device_code?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!body.device_code || typeof body.device_code !== 'string') {
    return jsonError('Missing device_code', 400);
  }

  const row = await getDeviceCodeByDeviceCode(env, body.device_code);
  if (!row) return jsonError('Unknown device_code', 404);

  // Rate limit: enforce minimum poll interval
  if (row.last_polled_at) {
    const lastPoll = new Date(row.last_polled_at).getTime();
    const since = (Date.now() - lastPoll) / 1000;
    if (since < POLL_MIN_INTERVAL_SECONDS) {
      return new Response(
        JSON.stringify({ status: 'slow_down', interval: POLL_MIN_INTERVAL_SECONDS + 3 }),
        {
          status: 429,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
  }
  // Update last_polled_at (best-effort)
  updateDeviceCodePolled(env, body.device_code).catch(() => {});

  // Check expiry
  if (new Date(row.expires_at) < new Date()) {
    return jsonOk({ status: 'expired' });
  }

  // Status dispatch
  if (row.status === 'pending') {
    return jsonOk({ status: 'pending' });
  }

  if (row.status === 'denied') {
    return jsonOk({ status: 'denied' });
  }

  if (row.status === 'consumed') {
    return jsonError('already_consumed', 400);
  }

  if (row.status === 'authorized') {
    // Fetch the master token from KV bridge
    const bridgeKey = `${MASTER_TOKEN_BRIDGE_PREFIX}${row.device_code}`;
    const masterToken = await env.KEYS.get(bridgeKey);

    if (!masterToken) {
      // Bridge expired before the CLI could pick it up. Rare but possible.
      return jsonError('Token bridge expired, please re-register', 410);
    }

    // Mark consumed and delete bridge atomically (best effort — D1 doesn't
    // have cross-row transactions, but these two ops are idempotent)
    await markDeviceCodeConsumed(env, row.device_code);
    await env.KEYS.delete(bridgeKey);

    // Look up the user's email for the response
    const user = row.user_id ? await getUserById(env, row.user_id) : null;

    return jsonOk({
      status: 'authorized',
      master_token: masterToken,
      user_id: row.user_id,
      email: user?.email ?? null,
      device_id: row.device_id,
    });
  }

  // Unknown status — should never happen given the CHECK constraint
  return jsonError('Unknown device code status', 500);
}
