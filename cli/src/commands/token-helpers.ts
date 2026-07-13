/**
 * Pure helpers for `apilocker token create` — extracted so the response
 * parsing and key resolution are unit-testable (see src/__tests__/).
 *
 * Context: the worker's POST /v1/tokens returns the secret as `access_token`
 * (plus `refresh_token` for rotating tokens and `access_token_expires_at`),
 * and its proxy authorization matches `allowed_keys` against key IDs only.
 * The CLI used to read `res.token` (undefined — the secret was lost forever)
 * and pass key NAMES through verbatim (tokens that could never authorize).
 */

/** Shape of the worker's POST /v1/tokens response (the fields we use). */
export interface TokenCreateResponse {
  id: string;
  name: string;
  access_token: string;
  refresh_token?: string | null;
  rotation_type: string;
  access_token_expires_at?: string | null;
}

/** Minimal key shape needed for name→ID resolution (from GET /v1/keys). */
export interface KeyRef {
  id: string;
  name: string;
}

/**
 * Resolve a mix of key IDs and key names to IDs.
 *
 * The proxy authorizes tokens by key ID, so anything that isn't an ID must be
 * resolved. Throws when a name matches nothing (creating a token scoped to a
 * non-existent key is always a mistake) or matches ambiguously.
 */
export function resolveKeyIdentifiers(inputs: string[], keys: KeyRef[]): string[] {
  return inputs.map((input) => {
    // Already an ID — pass through (worker IDs are "key_<uuid>").
    if (input.startsWith('key_')) {
      return input;
    }
    const matches = keys.filter((k) => k.name === input);
    if (matches.length === 0) {
      throw new Error(
        `No key named "${input}" found in your vault. Use \`apilocker list\` to see keys, or pass the key ID directly.`
      );
    }
    if (matches.length > 1) {
      throw new Error(
        `Multiple keys named "${input}" — pass the key ID instead (see \`apilocker list\`).`
      );
    }
    return matches[0].id;
  });
}

/**
 * Format the create response for display. Reads `access_token` (NOT `token` —
 * that field never existed on the worker response) and includes the refresh
 * token and expiry when the rotation type produces them.
 */
export function formatTokenCreateResult(res: TokenCreateResponse): string[] {
  const lines = [
    `Token created successfully.`,
    `  ID:       ${res.id}`,
    `  Name:     ${res.name}`,
    `  Rotation: ${res.rotation_type}`,
  ];
  if (res.access_token_expires_at) {
    lines.push(`  Expires:  ${new Date(res.access_token_expires_at).toLocaleString()}`);
  }
  lines.push(``, `  Token (save this — it won't be shown again):`, `  ${res.access_token}`);
  if (res.refresh_token) {
    lines.push(``, `  Refresh token (rotating token — store this too):`, `  ${res.refresh_token}`);
  }
  return lines;
}
