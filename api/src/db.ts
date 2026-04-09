import { Env, User, KeyMetadata, MatchedKeyMetadata, Token, AuditLog, Device, DeviceCode, DeviceCodeStatus } from './types';

// ---- Users ----

export async function findUserByOAuth(
  env: Env,
  provider: string,
  oauthId: string
): Promise<User | null> {
  return env.DB.prepare(
    'SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?'
  )
    .bind(provider, oauthId)
    .first<User>();
}

export async function createUser(
  env: Env,
  user: Pick<User, 'id' | 'email' | 'name' | 'avatar_url' | 'oauth_provider' | 'oauth_id'>
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO users (id, email, name, avatar_url, oauth_provider, oauth_id) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(user.id, user.email, user.name, user.avatar_url, user.oauth_provider, user.oauth_id)
    .run();
}

export async function updateUserLogin(env: Env, userId: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE users SET last_login_at = datetime('now') WHERE id = ?"
  )
    .bind(userId)
    .run();
}

export async function setMasterTokenHash(env: Env, userId: string, hash: string): Promise<void> {
  await env.DB.prepare('UPDATE users SET master_token_hash = ? WHERE id = ?')
    .bind(hash, userId)
    .run();
}

export async function getUserById(env: Env, userId: string): Promise<User | null> {
  return env.DB.prepare('SELECT * FROM users WHERE id = ?')
    .bind(userId)
    .first<User>();
}

// ---- Sessions ----

export async function createSession(
  env: Env,
  id: string,
  userId: string,
  tokenHash: string,
  expiresAt: string
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, session_token_hash, expires_at) VALUES (?, ?, ?, ?)'
  )
    .bind(id, userId, tokenHash, expiresAt)
    .run();
}

export async function deleteUserSessions(env: Env, userId: string): Promise<void> {
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
}

// ---- Keys Metadata ----

export async function insertKeyMetadata(env: Env, key: KeyMetadata): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO keys_metadata
       (id, user_id, name, provider, tags, base_url, auth_header_type, credential_type, previous_names)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      key.id,
      key.user_id,
      key.name,
      key.provider,
      key.tags,
      key.base_url,
      key.auth_header_type,
      key.credential_type,
      key.previous_names || '[]'
    )
    .run();
}

/**
 * Look up a key by its user-facing name. Used by the rename endpoint
 * to check for name collisions and by the CLI `pause`/`resume`/`rename`
 * commands to resolve aliases to IDs.
 */
export async function getKeyMetadataByName(
  env: Env,
  userId: string,
  name: string
): Promise<KeyMetadata | null> {
  return env.DB.prepare(
    'SELECT * FROM keys_metadata WHERE user_id = ? AND name = ?'
  )
    .bind(userId, name)
    .first<KeyMetadata>();
}

/**
 * Rename a credential AND append the old name to its previous_names
 * history for lossless fallback. Also purges the new name from any
 * OTHER row's previous_names (name-recycling semantics: claiming a
 * name takes it back from any credential that previously held it).
 *
 * Returns false if the row doesn't exist.
 *
 * Note: collision with another credential's CURRENT name must be
 * checked by the caller BEFORE invoking this — the unique(user_id,
 * name) constraint will also enforce it at the DB layer, but giving
 * the user a nice error message is nicer than surfacing a DB error.
 */
export async function renameKeyMetadata(
  env: Env,
  keyId: string,
  userId: string,
  newName: string
): Promise<boolean> {
  // Load the current row to get its name and previous_names
  const row = await env.DB.prepare(
    'SELECT name, previous_names FROM keys_metadata WHERE id = ? AND user_id = ?'
  )
    .bind(keyId, userId)
    .first<{ name: string; previous_names: string }>();

  if (!row) return false;
  if (row.name === newName) return true; // no-op

  // Parse previous_names, add old name, dedupe
  let history: string[] = [];
  try {
    const parsed = JSON.parse(row.previous_names || '[]');
    if (Array.isArray(parsed)) {
      history = parsed.filter((v) => typeof v === 'string');
    }
  } catch {
    history = [];
  }
  // Append the OLD name, dedupe by removing existing occurrences first
  history = history.filter((n) => n !== row.name);
  history.push(row.name);
  // Also remove the NEW name from history (if we're renaming back to an
  // earlier name, it shouldn't remain in its own history)
  history = history.filter((n) => n !== newName);

  const result = await env.DB.prepare(
    'UPDATE keys_metadata SET name = ?, previous_names = ? WHERE id = ? AND user_id = ?'
  )
    .bind(newName, JSON.stringify(history), keyId, userId)
    .run();

  if (result.meta.changes === 0) return false;

  // Purge the new name from any OTHER row's previous_names (in case it
  // was a legacy alias on a different credential). This enforces
  // name-recycling semantics.
  await purgeFromPreviousNames(env, userId, newName);

  return true;
}

export async function pauseKeyMetadata(
  env: Env,
  keyId: string,
  userId: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE keys_metadata SET paused_at = datetime('now') WHERE id = ? AND user_id = ? AND paused_at IS NULL"
  )
    .bind(keyId, userId)
    .run();
  return result.meta.changes > 0;
}

export async function resumeKeyMetadata(
  env: Env,
  keyId: string,
  userId: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    'UPDATE keys_metadata SET paused_at = NULL WHERE id = ? AND user_id = ? AND paused_at IS NOT NULL'
  )
    .bind(keyId, userId)
    .run();
  return result.meta.changes > 0;
}

export async function listKeyMetadata(env: Env, userId: string): Promise<KeyMetadata[]> {
  const result = await env.DB.prepare(
    'SELECT * FROM keys_metadata WHERE user_id = ? ORDER BY created_at DESC'
  )
    .bind(userId)
    .all<KeyMetadata>();
  return result.results;
}

export async function getKeyMetadata(env: Env, keyId: string, userId: string): Promise<KeyMetadata | null> {
  return env.DB.prepare(
    'SELECT * FROM keys_metadata WHERE id = ? AND user_id = ?'
  )
    .bind(keyId, userId)
    .first<KeyMetadata>();
}

/**
 * Look up multiple keys by their user-facing names, with lossless rename
 * support. Two-phase lookup:
 *
 *   1. Direct name match — find rows where `name IN (...requested)`.
 *   2. previous_names fallback — for any requested names not found in
 *      phase 1, search every row's `previous_names` JSON array for the
 *      name. Returns the row (if any) with its `matched_via_alias` field
 *      set to the legacy name that was requested.
 *
 * This makes renames transparent: .apilockerrc files and app code that
 * reference old names continue to work indefinitely. The reveal endpoint
 * uses the `matched_via_alias` field to signal `deprecated_alias: true`
 * in the response, so the CLI can print a gentle nudge to update configs.
 *
 * Each returned row is guaranteed to have the `matched_via_alias` field
 * populated: null for direct matches, a string for fallback matches.
 */
export async function getKeysByNames(
  env: Env,
  userId: string,
  names: string[]
): Promise<MatchedKeyMetadata[]> {
  if (names.length === 0) return [];
  const uniqueNames = Array.from(new Set(names));

  // Phase 1: direct name match
  const placeholders = uniqueNames.map(() => '?').join(',');
  const direct = await env.DB.prepare(
    `SELECT * FROM keys_metadata WHERE user_id = ? AND name IN (${placeholders})`
  )
    .bind(userId, ...uniqueNames)
    .all<KeyMetadata>();

  const foundNames = new Set(direct.results.map((r) => r.name));
  const missingNames = uniqueNames.filter((n) => !foundNames.has(n));

  const results: MatchedKeyMetadata[] = direct.results.map((row) => ({
    ...row,
    matched_via_alias: null,
  }));

  if (missingNames.length === 0) {
    return results;
  }

  // Phase 2: previous_names fallback, one query per missing name
  // (SQLite JSON1 extension is available in D1)
  for (const missingName of missingNames) {
    const row = await env.DB.prepare(
      `SELECT * FROM keys_metadata
         WHERE user_id = ?
           AND EXISTS (
             SELECT 1 FROM json_each(previous_names) WHERE value = ?
           )
         LIMIT 1`
    )
      .bind(userId, missingName)
      .first<KeyMetadata>();

    if (row) {
      // Guard against the (theoretically impossible) case where the same
      // row was already returned in phase 1 via its current name.
      if (!results.some((r) => r.id === row.id && r.matched_via_alias === null)) {
        results.push({
          ...row,
          matched_via_alias: missingName,
        });
      }
    }
  }

  return results;
}

/**
 * Remove a name from every `previous_names` array owned by this user.
 * Called by the store handler (when a new credential is created with a
 * name that's in some other row's history) and by the rename handler
 * (when the new name is in some other row's history) to enforce
 * "name recycling reclaims" semantics.
 *
 * Safe to call unconditionally — if the name isn't in any row's history,
 * the EXISTS clause filters out every row and the UPDATE is a no-op.
 */
export async function purgeFromPreviousNames(
  env: Env,
  userId: string,
  nameToRemove: string
): Promise<void> {
  await env.DB.prepare(
    `UPDATE keys_metadata
        SET previous_names = COALESCE(
          (SELECT json_group_array(value)
             FROM json_each(previous_names)
            WHERE value != ?),
          '[]'
        )
      WHERE user_id = ?
        AND EXISTS (
          SELECT 1 FROM json_each(previous_names) WHERE value = ?
        )`
  )
    .bind(nameToRemove, userId, nameToRemove)
    .run();
}

export async function deleteKeyMetadata(env: Env, keyId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    'DELETE FROM keys_metadata WHERE id = ? AND user_id = ?'
  )
    .bind(keyId, userId)
    .run();
  return result.meta.changes > 0;
}

/**
 * Stamp a key as rotated — updates rotated_at on the metadata row. The
 * actual KV encrypted blob is rewritten separately by the caller.
 */
export async function markKeyRotated(env: Env, keyId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE keys_metadata SET rotated_at = datetime('now') WHERE id = ? AND user_id = ?"
  )
    .bind(keyId, userId)
    .run();
  return result.meta.changes > 0;
}

// ---- Tokens ----

export async function insertToken(
  env: Env,
  token: Omit<
    Token,
    | 'revoked_at'
    | 'previous_refresh_token_hash'
    | 'last_refreshed_at'
    | 'reuse_detected_at'
  >
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO tokens
      (id, user_id, name, hashed_token, allowed_keys, rotation_type, current_token_expires_at,
       refresh_token_hash, refresh_token_family_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      token.id,
      token.user_id,
      token.name,
      token.hashed_token,
      token.allowed_keys,
      token.rotation_type,
      token.current_token_expires_at,
      token.refresh_token_hash,
      token.refresh_token_family_id
    )
    .run();
}

/** Look up a token row by the hashed refresh token (current or previous) */
export async function findTokenByRefreshHash(
  env: Env,
  refreshHash: string
): Promise<Token | null> {
  return env.DB.prepare(
    'SELECT * FROM tokens WHERE refresh_token_hash = ? OR previous_refresh_token_hash = ?'
  )
    .bind(refreshHash, refreshHash)
    .first<Token>();
}

/** Rotate both the access and refresh tokens after a successful refresh */
export async function rotateTokenPair(
  env: Env,
  tokenId: string,
  newAccessHash: string,
  newRefreshHash: string,
  previousRefreshHash: string,
  newAccessExpiresAt: string
): Promise<void> {
  await env.DB.prepare(
    `UPDATE tokens
       SET hashed_token = ?,
           current_token_expires_at = ?,
           refresh_token_hash = ?,
           previous_refresh_token_hash = ?,
           last_refreshed_at = datetime('now')
     WHERE id = ?`
  )
    .bind(newAccessHash, newAccessExpiresAt, newRefreshHash, previousRefreshHash, tokenId)
    .run();
}

/**
 * Mark a token family as compromised (refresh token reuse detected).
 * After this, every token in the family stops working at the auth layer.
 */
export async function killTokenFamily(env: Env, familyId: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE tokens
       SET reuse_detected_at = datetime('now'),
           revoked_at = datetime('now')
     WHERE refresh_token_family_id = ?`
  )
    .bind(familyId)
    .run();
}

export async function listTokens(env: Env, userId: string): Promise<Token[]> {
  const result = await env.DB.prepare(
    'SELECT * FROM tokens WHERE user_id = ? ORDER BY created_at DESC'
  )
    .bind(userId)
    .all<Token>();
  return result.results;
}

export async function revokeToken(env: Env, tokenId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE tokens SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
  )
    .bind(tokenId, userId)
    .run();
  return result.meta.changes > 0;
}

/** Permanently delete a token row from D1. Gone forever. */
export async function hardDeleteToken(env: Env, tokenId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    'DELETE FROM tokens WHERE id = ? AND user_id = ?'
  )
    .bind(tokenId, userId)
    .run();
  return result.meta.changes > 0;
}

/** Temporarily disable a token. Reversible via resumeToken. */
export async function pauseToken(env: Env, tokenId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE tokens SET paused_at = datetime('now') WHERE id = ? AND user_id = ? AND paused_at IS NULL AND revoked_at IS NULL"
  )
    .bind(tokenId, userId)
    .run();
  return result.meta.changes > 0;
}

/** Resume a paused token. */
export async function resumeToken(env: Env, tokenId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    'UPDATE tokens SET paused_at = NULL WHERE id = ? AND user_id = ? AND paused_at IS NOT NULL AND revoked_at IS NULL'
  )
    .bind(tokenId, userId)
    .run();
  return result.meta.changes > 0;
}

export async function updateTokenHash(
  env: Env,
  tokenId: string,
  newHash: string,
  expiresAt: string | null
): Promise<void> {
  await env.DB.prepare(
    'UPDATE tokens SET hashed_token = ?, current_token_expires_at = ? WHERE id = ?'
  )
    .bind(newHash, expiresAt, tokenId)
    .run();
}

export async function getTokenById(env: Env, tokenId: string, userId: string): Promise<Token | null> {
  return env.DB.prepare(
    'SELECT * FROM tokens WHERE id = ? AND user_id = ?'
  )
    .bind(tokenId, userId)
    .first<Token>();
}

// ---- Audit Logs ----

export async function insertAuditLog(env: Env, log: AuditLog): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO audit_logs (id, user_id, token_id, key_id, provider, forward_path, source_ip, status_code, latency_ms, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(
      log.id, log.user_id, log.token_id, log.key_id, log.provider,
      log.forward_path, log.source_ip, log.status_code, log.latency_ms,
      log.country ?? null
    )
    .run();
}

export async function queryAuditLogs(
  env: Env,
  userId: string,
  filters?: { key_id?: string; token_id?: string; limit?: number }
): Promise<AuditLog[]> {
  let query = 'SELECT * FROM audit_logs WHERE user_id = ?';
  const bindings: unknown[] = [userId];

  if (filters?.key_id) {
    query += ' AND key_id = ?';
    bindings.push(filters.key_id);
  }
  if (filters?.token_id) {
    query += ' AND token_id = ?';
    bindings.push(filters.token_id);
  }

  query += ' ORDER BY timestamp DESC LIMIT ?';
  bindings.push(filters?.limit ?? 100);

  const result = await env.DB.prepare(query).bind(...bindings).all<AuditLog>();
  return result.results;
}

// ---- Devices ----

export interface InsertDeviceInput {
  id: string;
  user_id: string;
  name: string;
  hardware_fingerprint_hash: string;
  token_hash?: string | null;
  hostname?: string | null;
  platform?: string | null;
  platform_version?: string | null;
  cli_version?: string | null;
}

export async function insertDevice(env: Env, device: InsertDeviceInput): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO devices
      (id, user_id, name, hardware_fingerprint_hash,
       token_hash, hostname, platform, platform_version, cli_version)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      device.id,
      device.user_id,
      device.name,
      device.hardware_fingerprint_hash,
      device.token_hash ?? null,
      device.hostname ?? null,
      device.platform ?? null,
      device.platform_version ?? null,
      device.cli_version ?? null
    )
    .run();
}

export async function listDevices(env: Env, userId: string): Promise<Device[]> {
  const result = await env.DB.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY registered_at DESC'
  )
    .bind(userId)
    .all<Device>();
  return result.results;
}

export async function getDeviceById(
  env: Env,
  deviceId: string,
  userId: string
): Promise<Device | null> {
  return env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND user_id = ?'
  )
    .bind(deviceId, userId)
    .first<Device>();
}

export async function findDeviceByFingerprint(
  env: Env,
  userId: string,
  fingerprintHash: string
): Promise<Device | null> {
  return env.DB.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND hardware_fingerprint_hash = ? AND revoked_at IS NULL'
  )
    .bind(userId, fingerprintHash)
    .first<Device>();
}

export async function findDeviceByTokenHash(
  env: Env,
  tokenHash: string
): Promise<Device | null> {
  return env.DB.prepare(
    'SELECT * FROM devices WHERE token_hash = ? AND revoked_at IS NULL'
  )
    .bind(tokenHash)
    .first<Device>();
}

export async function updateDeviceLastUsed(env: Env, deviceId: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE devices SET last_used_at = datetime('now') WHERE id = ?"
  )
    .bind(deviceId)
    .run();
}

export async function revokeDevice(
  env: Env,
  deviceId: string,
  userId: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE devices SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
  )
    .bind(deviceId, userId)
    .run();
  return result.meta.changes > 0;
}

// ---- Device codes (RFC 8628 CLI authorization flow) ----

export interface InsertDeviceCodeInput {
  device_code: string;
  user_code: string;
  client_metadata: string;
  ip_address: string | null;
  expires_at: string;
}

export async function insertDeviceCode(
  env: Env,
  input: InsertDeviceCodeInput
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO device_codes
      (device_code, user_code, status, client_metadata, ip_address, expires_at)
     VALUES (?, ?, 'pending', ?, ?, ?)`
  )
    .bind(
      input.device_code,
      input.user_code,
      input.client_metadata,
      input.ip_address,
      input.expires_at
    )
    .run();
}

export async function getDeviceCodeByUserCode(
  env: Env,
  userCode: string
): Promise<DeviceCode | null> {
  return env.DB.prepare(
    'SELECT * FROM device_codes WHERE user_code = ?'
  )
    .bind(userCode)
    .first<DeviceCode>();
}

export async function getDeviceCodeByDeviceCode(
  env: Env,
  deviceCode: string
): Promise<DeviceCode | null> {
  return env.DB.prepare(
    'SELECT * FROM device_codes WHERE device_code = ?'
  )
    .bind(deviceCode)
    .first<DeviceCode>();
}

export async function authorizeDeviceCode(
  env: Env,
  userCode: string,
  userId: string,
  deviceId: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE device_codes
        SET status = 'authorized',
            user_id = ?,
            device_id = ?,
            authorized_at = datetime('now')
      WHERE user_code = ?
        AND status = 'pending'
        AND expires_at > datetime('now')`
  )
    .bind(userId, deviceId, userCode)
    .run();
  return result.meta.changes > 0;
}

export async function denyDeviceCode(
  env: Env,
  userCode: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE device_codes
        SET status = 'denied'
      WHERE user_code = ?
        AND status = 'pending'`
  )
    .bind(userCode)
    .run();
  return result.meta.changes > 0;
}

export async function markDeviceCodeConsumed(
  env: Env,
  deviceCode: string
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE device_codes
        SET status = 'consumed', consumed_at = datetime('now')
      WHERE device_code = ? AND status = 'authorized'`
  )
    .bind(deviceCode)
    .run();
  return result.meta.changes > 0;
}

export async function updateDeviceCodePolled(
  env: Env,
  deviceCode: string
): Promise<void> {
  await env.DB.prepare(
    "UPDATE device_codes SET last_polled_at = datetime('now') WHERE device_code = ?"
  )
    .bind(deviceCode)
    .run();
}
