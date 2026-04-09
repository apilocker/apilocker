/**
 * Shared helper for fetching decrypted credentials from the vault.
 * Backs `apilocker run`, `apilocker get`, and `apilocker env`.
 *
 * v1.0.0: the server returns two shapes depending on credential type
 * (api_key single-value vs oauth2 multi-field), PLUS a lossless-rename
 * fallback: if the caller requests a name that's been renamed, the
 * server still returns the credential (matched via its previous_names
 * history) with `deprecated_alias: true` and `requested_as: <oldName>`.
 * The env var name is derived from the REQUESTED alias so the user's
 * code + .apilockerrc continue to work unchanged.
 *
 * The CLI uses `deprecated_alias` to print a gentle info line on stderr
 * after every run, so users are nudged to update their configs when
 * convenient — without anything ever breaking.
 */

import { apiRequest } from './api';

export type CredentialType = 'api_key' | 'oauth2';

export interface RevealedKey {
  name: string;
  provider: string;
  credential_type: CredentialType;
  // Lossless-rename metadata (v1.0.0)
  deprecated_alias?: boolean;
  requested_as?: string;
  // api_key shape
  value?: string;
  env_name?: string;
  // oauth2 shape
  fields?: Record<string, string | undefined>;
  env_names?: Record<string, string>;
}

export interface RevealResult {
  keys: RevealedKey[];
  missing: string[];
}

export async function revealKeys(aliases: string[]): Promise<RevealResult> {
  if (aliases.length === 0) {
    return { keys: [], missing: [] };
  }
  return apiRequest<RevealResult>('/v1/keys/reveal', {
    method: 'POST',
    body: JSON.stringify({ keys: aliases }),
  });
}

/**
 * Flatten a RevealResult into a flat map of ENV_NAME → value, suitable
 * for merging into process.env when spawning a child process.
 *
 * api_key credentials contribute a single entry. oauth2 credentials
 * contribute one entry per non-empty field (client_id, client_secret,
 * refresh_token, etc.).
 */
export function flattenToEnv(result: RevealResult): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of result.keys) {
    if (key.credential_type === 'oauth2' && key.fields && key.env_names) {
      for (const [fieldKey, fieldValue] of Object.entries(key.fields)) {
        if (fieldValue == null || fieldValue === '') continue;
        const envName = key.env_names[fieldKey];
        if (envName) out[envName] = fieldValue;
      }
    } else if (key.value != null && key.env_name) {
      out[key.env_name] = key.value;
    }
  }
  return out;
}

/**
 * Extract human-readable deprecation nudge lines from a RevealResult.
 * Returns one string per credential that was matched via legacy alias
 * (deprecated_alias: true). The caller is expected to print these to
 * STDERR so they don't pollute stdout (which may be the target of
 * shell substitution or eval).
 */
export function getDeprecationNudges(result: RevealResult): string[] {
  const nudges: string[] = [];
  for (const key of result.keys) {
    if (key.deprecated_alias && key.requested_as && key.requested_as !== key.name) {
      nudges.push(
        `"${key.requested_as}" was renamed to "${key.name}". Legacy alias still works — update your reference when convenient.`
      );
    }
  }
  return nudges;
}
