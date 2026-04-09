import { Env, Token } from './types';
import { hashToken } from './crypto';

export async function validateSession(request: Request, env: Env): Promise<string | null> {
  // Check session cookie first (dashboard)
  const cookie = request.headers.get('Cookie');
  if (cookie) {
    const sessionToken = parseCookie(cookie, 'apilocker_session');
    if (sessionToken) {
      return validateSessionToken(sessionToken, env);
    }
  }

  // Check Authorization header (master token from CLI)
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    return validateMasterToken(token, env);
  }

  return null;
}

async function validateSessionToken(token: string, env: Env): Promise<string | null> {
  const hashed = await hashToken(token);
  const session = await env.DB.prepare(
    'SELECT user_id, expires_at FROM sessions WHERE session_token_hash = ?'
  )
    .bind(hashed)
    .first<{ user_id: string; expires_at: string }>();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) return null;

  return session.user_id;
}

/**
 * Validate a CLI master token. Two paths, tried in order:
 *
 * 1. Per-device tokens (v0.2.0+). Each `devices` row may have its own
 *    `token_hash` populated during the RFC 8628 device authorization flow.
 *    Revoked devices (revoked_at NOT NULL) are filtered out by the query
 *    itself, so revocation takes effect immediately with no cache.
 *
 * 2. Legacy user-scoped master token (v0.1.x). `users.master_token_hash`
 *    was populated by the old "paste from dashboard" flow. This path is
 *    preserved for backwards compatibility with existing 0.1.x installs.
 *
 * The per-device path is strictly better (supports independent revocation,
 * per-device audit), so we prefer it when both match — but because tokens
 * are unguessable (256 bits of entropy), they won't match both paths unless
 * someone has manually populated both columns, which doesn't happen.
 */
async function validateMasterToken(token: string, env: Env): Promise<string | null> {
  const hashed = await hashToken(token);

  // Path 1: per-device token (v0.2.0+)
  const device = await env.DB.prepare(
    'SELECT user_id, id FROM devices WHERE token_hash = ? AND revoked_at IS NULL'
  )
    .bind(hashed)
    .first<{ user_id: string; id: string }>();

  if (device) {
    // Update last_used_at (fire-and-forget is fine — it's best-effort telemetry)
    env.DB.prepare("UPDATE devices SET last_used_at = datetime('now') WHERE id = ?")
      .bind(device.id)
      .run()
      .catch(() => {});
    return device.user_id;
  }

  // Path 2: legacy user-scoped master token (v0.1.x back-compat)
  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE master_token_hash = ?'
  )
    .bind(hashed)
    .first<{ id: string }>();

  return user?.id ?? null;
}

export interface ScopedTokenInfo {
  userId: string;
  tokenId: string;
  allowedKeys: string[];
}

export async function validateScopedToken(
  request: Request,
  env: Env
): Promise<ScopedTokenInfo | null> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  const hashed = await hashToken(token);

  const row = await env.DB.prepare(
    'SELECT id, user_id, allowed_keys, rotation_type, current_token_expires_at, revoked_at, reuse_detected_at, paused_at FROM tokens WHERE hashed_token = ?'
  )
    .bind(hashed)
    .first<Token>();

  if (!row) return null;
  if (row.revoked_at) return null;
  // Family compromised by refresh-token reuse detection
  if (row.reuse_detected_at) return null;
  // Paused — reversible, but the token is not currently valid
  if (row.paused_at) return null;

  // Check expiration for rotating tokens
  if (row.current_token_expires_at && new Date(row.current_token_expires_at) < new Date()) {
    return null;
  }

  return {
    userId: row.user_id,
    tokenId: row.id,
    allowedKeys: JSON.parse(row.allowed_keys),
  };
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function setSessionCookie(token: string, maxAge: number): string {
  return `apilocker_session=${encodeURIComponent(token)}; Domain=.apilocker.app; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie(): string {
  return 'apilocker_session=; Domain=.apilocker.app; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}
