/**
 * POST /v1/keys/reveal — decrypt and return plaintext secrets by alias.
 *
 * Powers the `apilocker run`, `apilocker get`, and `apilocker env` commands.
 * Requires master-token auth (session cookie OR device master token).
 * Scoped tokens are explicitly rejected — scoped tokens exist so that app
 * code can proxy calls WITHOUT ever seeing raw credentials, and that
 * invariant should not leak.
 *
 * Security notes:
 *   1. Every reveal is audit-logged (user_id, key_ids, source IP).
 *   2. The response contains plaintext secrets. Callers must not cache.
 *   3. Rate limiting is enforced by the existing TrafficMonitor on a
 *      per-user basis.
 *   4. The handler itself does not care about device tokens vs session
 *      cookies — the router has already authenticated as 'session',
 *      which is satisfied by either path. That means a dashboard user
 *      COULD also call this endpoint, which is fine: they already can
 *      see plaintext via the dashboard if we add that UI later.
 */

import { Env, EncryptedKeyRecord, OAuthCredentialFields, CredentialType } from './types';
import { decrypt, generateId } from './crypto';
import { getKeysByNames, insertAuditLog } from './db';
import { jsonOk, jsonError } from './responses';

interface RevealRequest {
  keys: string[];
}

/**
 * A single revealed credential in the reveal response.
 *
 * For api_key credentials, `value` is the single secret string and
 * `env_name` is the normalized env var name. `fields` is not present.
 *
 * For oauth2 credentials, `fields` is an object whose keys are the
 * OAuth field names (client_id, client_secret, refresh_token, ...) and
 * whose values are the decrypted strings. `env_names` is a parallel
 * object mapping each field to its injected env var name (e.g.
 * GOOGLE_OAUTH_CLIENT_ID). `value` is not present.
 *
 * `deprecated_alias` is set to true when the credential was found via
 * the `previous_names` fallback (lossless rename). `requested_as` is
 * the legacy alias that was used. `name` is always the credential's
 * CURRENT name, which may differ from `requested_as`. The CLI uses
 * these fields to print a gentle nudge encouraging users to update
 * their .apilockerrc files and references.
 */
interface RevealedKey {
  name: string;
  provider: string;
  credential_type: CredentialType;
  // Lossless rename metadata (v1.0.0)
  deprecated_alias?: boolean;
  requested_as?: string;
  // api_key shape
  value?: string;
  env_name?: string;
  // oauth2 shape
  fields?: Record<string, string | undefined>;
  env_names?: Record<string, string>;
}

interface RevealResponse {
  keys: RevealedKey[];
  missing: string[];
}

/**
 * Normalize a key alias into an environment variable name.
 *
 * Rules:
 *   1. If the alias is already SCREAMING_SNAKE_CASE (starts with a letter,
 *      contains only uppercase letters / digits / underscores), use it
 *      verbatim.
 *   2. Otherwise, uppercase the whole thing and replace any run of
 *      non-alphanumeric characters with a single underscore. Strip
 *      leading/trailing underscores.
 *   3. If the result starts with a digit, prefix with an underscore.
 *
 * Examples:
 *   "OPENAI_API_KEY" → "OPENAI_API_KEY"
 *   "openai"         → "OPENAI"
 *   "stripe-secret"  → "STRIPE_SECRET"
 *   "my openai key"  → "MY_OPENAI_KEY"
 *   "stripe.prod"    → "STRIPE_PROD"
 *   "1password"      → "_1PASSWORD"
 */
export function normalizeEnvName(name: string): string {
  if (/^[A-Z][A-Z0-9_]*$/.test(name)) return name;
  let normalized = name.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  normalized = normalized.replace(/^_+|_+$/g, '');
  if (/^[0-9]/.test(normalized)) normalized = '_' + normalized;
  return normalized || 'KEY';
}

export async function handleRevealKeys(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: RevealRequest;
  try {
    body = (await request.json()) as RevealRequest;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    return jsonError('Missing required field: keys (non-empty array of aliases)', 400);
  }

  // Cap at 50 keys per reveal to prevent abuse / accidental massive exports.
  if (body.keys.length > 50) {
    return jsonError('Cannot reveal more than 50 keys at once', 400);
  }

  // Deduplicate requested names (case-sensitive, since name column is)
  const requestedNames = Array.from(new Set(body.keys.filter((k) => typeof k === 'string')));

  // Look up metadata rows with lossless rename fallback.
  // Each row carries `matched_via_alias`: null for direct matches, or
  // the legacy alias string if matched via previous_names.
  const rows = await getKeysByNames(env, userId, requestedNames);

  // Build the set of "satisfied" requested names — these are the names
  // that hit *something* in the vault (directly or via legacy alias).
  const satisfied = new Set<string>();
  for (const row of rows) {
    if (row.matched_via_alias === null) {
      satisfied.add(row.name);
    } else {
      satisfied.add(row.matched_via_alias);
    }
  }
  const missing = requestedNames.filter((n) => !satisfied.has(n));

  // Decrypt each found key in parallel. api_key credentials yield a
  // single-string `value`; oauth2 credentials yield a `fields` object
  // with per-field values + per-field env var names.
  //
  // For lossless rename: the env var name is derived from the LEGACY
  // alias (requested_as) if one was used, so that existing .apilockerrc
  // files + app code that expect the old env var name keep getting it.
  // The `name` field still reflects the credential's CURRENT name so
  // the CLI/dashboard can show both in the nudge message.
  const decrypted: (RevealedKey | null)[] = await Promise.all(
    rows.map(async (row): Promise<RevealedKey | null> => {
      const encryptedJson = await env.KEYS.get(row.id);
      if (!encryptedJson) {
        console.error(`Missing KV entry for key ${row.id} (user ${userId})`);
        return null;
      }
      const record: EncryptedKeyRecord = JSON.parse(encryptedJson);
      const plaintext = await decrypt(record, env);

      // Env var name derivation: use the requested alias (legacy) if
      // present, otherwise the current name. This is what keeps
      // `apilocker run` working against old .apilockerrc files — the
      // env var name the user's code expects is the one that gets set.
      const envBase = row.matched_via_alias || row.name;
      const isDeprecated = row.matched_via_alias !== null;

      if (row.credential_type === 'oauth2') {
        let fields: OAuthCredentialFields;
        try {
          fields = JSON.parse(plaintext) as OAuthCredentialFields;
        } catch {
          console.error(`Corrupt OAuth blob for key ${row.id}`);
          return null;
        }
        const baseEnvName = normalizeEnvName(envBase);
        const env_names: Record<string, string> = {};
        const fieldValues: Record<string, string | undefined> = {};
        for (const [fieldKey, fieldVal] of Object.entries(fields)) {
          if (fieldVal == null || fieldVal === '') continue;
          const envField = fieldKey.toUpperCase();
          env_names[fieldKey] = `${baseEnvName}_${envField}`;
          fieldValues[fieldKey] = fieldVal;
        }
        return {
          name: row.name,
          provider: row.provider,
          credential_type: 'oauth2',
          fields: fieldValues,
          env_names,
          deprecated_alias: isDeprecated || undefined,
          requested_as: row.matched_via_alias || undefined,
        };
      }

      // Default: api_key single-string credential
      return {
        name: row.name,
        provider: row.provider,
        credential_type: 'api_key',
        value: plaintext,
        env_name: normalizeEnvName(envBase),
        deprecated_alias: isDeprecated || undefined,
        requested_as: row.matched_via_alias || undefined,
      };
    })
  );

  // Drop any entries where decryption failed
  const keys = decrypted.filter((k): k is RevealedKey => k !== null);

  // Audit-log the reveal. One audit row per revealed key so the activity
  // feed shows "revealed: openai, anthropic, stripe" clearly.
  const sourceIp =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null;
  const country = request.headers.get('CF-IPCountry') || null;

  await Promise.all(
    keys.map((k) =>
      insertAuditLog(env, {
        id: generateId('log'),
        user_id: userId,
        token_id: null,
        key_id: rows.find((r) => r.name === k.name)?.id ?? null,
        provider: k.provider,
        forward_path: '/reveal',
        source_ip: sourceIp,
        status_code: 200,
        latency_ms: null,
        timestamp: new Date().toISOString(),
        country,
      }).catch((e) => console.error('Audit log insert failed:', e))
    )
  );

  const response: RevealResponse = { keys, missing };
  return jsonOk(response);
}
