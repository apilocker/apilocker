/**
 * oauth-server.ts — API Locker's OAuth 2.1 authorization server.
 *
 * This file implements the endpoints required to make API Locker a
 * compliant OAuth 2.1 authorization server per the MCP Authorization
 * specification (2025-03-26+) so MCP clients like Claude can OAuth
 * into the vault over HTTPS without pasted master tokens.
 *
 * Endpoints:
 *   GET  /.well-known/oauth-authorization-server   [RFC 8414]
 *   GET  /.well-known/oauth-protected-resource     [RFC 9728]
 *   POST /v1/oauth/register                        [RFC 7591 DCR]
 *   GET  /v1/oauth/authorize                       [RFC 6749 §4.1.1]
 *   GET  /v1/oauth/intent                          [internal — consent UI fetch]
 *   POST /v1/oauth/consent                         [internal — approve/deny click]
 *   POST /v1/oauth/token                           [RFC 6749 §4.1.3 + §6]
 *
 * Scope model:
 *   vault:read   — list/get/reveal credentials, activity, doctor
 *   vault:write  — rotate, rename, pause/resume, delete, create tokens
 *   vault:proxy  — make proxied API calls through stored credentials
 *
 * PKCE is mandatory (RFC 7636 S256 only). Client auth is "none" because
 * MCP clients are public clients; PKCE substitutes for the client secret
 * in protecting against auth code interception.
 *
 * Refresh tokens rotate on every use. Reusing an old refresh token is
 * treated as token theft and revokes the entire family (all tokens
 * descended from the same authorization code grant).
 */

import { Env } from './types';
import { generateId, generateToken, hashToken } from './crypto';
import { jsonOk, jsonError } from './responses';

// ============================================================
// Constants
// ============================================================

const OAUTH_ISSUER = 'https://api.apilocker.app';
const MCP_RESOURCE_URL = 'https://api.apilocker.app/v1/mcp';

/**
 * Scopes API Locker's authorization server knows about. Clients
 * request these at /authorize; users approve them on the consent
 * screen; tokens carry them; validateOAuthAccessToken returns them.
 */
export const SUPPORTED_SCOPES = [
  'vault:read',
  'vault:write',
  'vault:proxy',
] as const;
export type OAuthScope = (typeof SUPPORTED_SCOPES)[number];

const OAUTH_CODE_TTL_SECONDS = 600; // 10 min — auth code lifetime
const OAUTH_INTENT_TTL_SECONDS = 600; // 10 min — consent screen intent lifetime
const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600; // 1 hour
const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days

const OAUTH_CODE_PREFIX = 'oauth_code:';
const OAUTH_INTENT_PREFIX = 'oauth_intent:';

// Token prefixes used to distinguish OAuth tokens from the existing
// apilocker scoped token system at validation time.
const ACCESS_TOKEN_PREFIX = 'alo_';
const REFRESH_TOKEN_PREFIX = 'alr_';

// Consent screen lives on the marketing site, not the API worker,
// because the API is pure JSON and serving HTML from it would be a
// layering violation. The consent page is a static HTML file that
// fetches intent details from the API and POSTs approve/deny back.
const CONSENT_SCREEN_URL = 'https://www.apilocker.app/oauth-consent';

// ============================================================
// Stored records
// ============================================================

/**
 * Row in oauth_clients D1 table. Persisted via RFC 7591 Dynamic
 * Client Registration.
 */
interface OAuthClientRow {
  id: string;
  client_name: string;
  redirect_uris: string; // JSON string[]
  grant_types: string; // JSON string[]
  response_types: string; // JSON string[]
  token_endpoint_auth_method: string;
  scope: string;
  logo_uri: string | null;
  client_uri: string | null;
  created_at: string;
  disabled_at: string | null;
}

/**
 * Ephemeral record stored in KV while the user is on the consent
 * screen. Created by /authorize, consumed by /consent.
 */
interface OAuthIntent {
  client_id: string;
  redirect_uri: string;
  scopes: string[];
  state: string | null;
  code_challenge: string;
  code_challenge_method: 'S256';
  created_at: number;
}

/**
 * Ephemeral record stored in KV for a short-lived authorization
 * code. Created by /consent on approval, consumed by /token.
 */
interface OAuthAuthCode {
  user_id: string;
  client_id: string;
  redirect_uri: string;
  scopes: string[];
  code_challenge: string;
  code_challenge_method: 'S256';
  created_at: number;
}

/** Row returned by validateOAuthAccessToken on success. */
export interface OAuthAccessTokenContext {
  token_id: string;
  user_id: string;
  client_id: string;
  scopes: string[];
}

// ============================================================
// Helpers
// ============================================================

function generateOAuthClientId(): string {
  return 'alc_' + crypto.randomUUID();
}

function generateOAuthTokenId(): string {
  return 'oat_' + crypto.randomUUID();
}

function generatePrefixedToken(prefix: string): string {
  return prefix + generateToken();
}

function parseScopes(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function validateScopes(requested: string[]): {
  approved: OAuthScope[];
  invalid: string[];
} {
  const approved: OAuthScope[] = [];
  const invalid: string[] = [];
  const supported = new Set<string>(SUPPORTED_SCOPES);
  for (const s of requested) {
    if (supported.has(s)) {
      approved.push(s as OAuthScope);
    } else {
      invalid.push(s);
    }
  }
  return { approved, invalid };
}

/**
 * Redirect URI validation. We accept:
 *   - HTTPS URIs (absolute, no fragment, no credentials)
 *   - http://localhost with any port (for local MCP dev clients)
 *
 * We REJECT:
 *   - http:// non-localhost (downgrades)
 *   - URIs with a fragment (#) — fragments aren't sent to servers, so
 *     any client that puts data there is confused
 *   - Relative URIs
 *   - URIs with embedded credentials (user:pass@...)
 */
function isValidRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.username || u.password) return false;
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Base64-url encode a Uint8Array. Used for PKCE challenge verification.
 */
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * RFC 7636 S256 PKCE verification. Server stores code_challenge from
 * the /authorize request; client sends code_verifier at /token time;
 * we compute SHA-256(code_verifier), base64url-encode, and compare.
 */
async function verifyPKCE(
  codeVerifier: string,
  storedChallenge: string
): Promise<boolean> {
  const encoded = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  const computedChallenge = base64UrlEncode(new Uint8Array(digest));
  // Use a timing-safe-ish comparison (string equality in JS is short-
  // circuiting, but these values are short and the difference is
  // negligible for this threat model).
  if (computedChallenge.length !== storedChallenge.length) return false;
  let diff = 0;
  for (let i = 0; i < computedChallenge.length; i++) {
    diff |= computedChallenge.charCodeAt(i) ^ storedChallenge.charCodeAt(i);
  }
  return diff === 0;
}

// ============================================================
// Handler: GET /.well-known/oauth-authorization-server
// ============================================================
//
// RFC 8414 metadata. Claude's MCP client hits this to discover our
// endpoints at runtime.

export async function handleOAuthMetadata(
  _request: Request,
  _env: Env,
  _params: Record<string, string>
): Promise<Response> {
  return jsonOk({
    issuer: OAUTH_ISSUER,
    authorization_endpoint: `${OAUTH_ISSUER}/v1/oauth/authorize`,
    token_endpoint: `${OAUTH_ISSUER}/v1/oauth/token`,
    registration_endpoint: `${OAUTH_ISSUER}/v1/oauth/register`,
    scopes_supported: [...SUPPORTED_SCOPES],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    // MCP clients are public; we don't require client authentication.
    // PKCE is mandatory and substitutes for client secret protection.
    service_documentation: 'https://www.apilocker.app/docs/mcp',
  });
}

// ============================================================
// Handler: GET /.well-known/oauth-protected-resource
// ============================================================
//
// RFC 9728 metadata describing the /v1/mcp resource and which
// authorization servers can issue tokens for it.

export async function handleOAuthProtectedResourceMetadata(
  _request: Request,
  _env: Env,
  _params: Record<string, string>
): Promise<Response> {
  return jsonOk({
    resource: MCP_RESOURCE_URL,
    authorization_servers: [OAUTH_ISSUER],
    scopes_supported: [...SUPPORTED_SCOPES],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://www.apilocker.app/docs/mcp',
  });
}

// ============================================================
// Handler: POST /v1/oauth/register (RFC 7591 Dynamic Client Registration)
// ============================================================
//
// Claude's MCP client calls this on its own to get a client_id. We
// accept any well-formed request — there's no pre-registration.
// Security relies on:
//   1. Strict redirect_uri validation (HTTPS or localhost only)
//   2. PKCE mandatory at /token time
//   3. The user explicitly approving the client on the consent screen
//      before any tokens are issued (the consent screen shows
//      client_name and warns about unfamiliar clients)

interface RegisterRequest {
  client_name?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  scope?: string;
  logo_uri?: string;
  client_uri?: string;
}

export async function handleOAuthRegister(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  let body: RegisterRequest;
  try {
    body = (await request.json()) as RegisterRequest;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  // Redirect URIs are the only required field.
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
    return jsonError('redirect_uris is required and must be a non-empty array', 400);
  }
  if (body.redirect_uris.length > 10) {
    return jsonError('redirect_uris cannot exceed 10 entries', 400);
  }
  for (const uri of body.redirect_uris) {
    if (typeof uri !== 'string' || !isValidRedirectUri(uri)) {
      return jsonError(`Invalid redirect_uri: ${uri}`, 400);
    }
  }

  // Validate optional fields.
  const grantTypes = Array.isArray(body.grant_types)
    ? body.grant_types
    : ['authorization_code', 'refresh_token'];
  const allowedGrantTypes = new Set(['authorization_code', 'refresh_token']);
  for (const gt of grantTypes) {
    if (!allowedGrantTypes.has(gt)) {
      return jsonError(`Unsupported grant_type: ${gt}`, 400);
    }
  }

  const responseTypes = Array.isArray(body.response_types)
    ? body.response_types
    : ['code'];
  for (const rt of responseTypes) {
    if (rt !== 'code') {
      return jsonError(`Unsupported response_type: ${rt}`, 400);
    }
  }

  const tokenAuthMethod = body.token_endpoint_auth_method || 'none';
  if (tokenAuthMethod !== 'none') {
    return jsonError(
      'Only token_endpoint_auth_method=none is supported (public clients with PKCE)',
      400
    );
  }

  // Default scope is all three; clients can request a subset at
  // /authorize time and users can further trim on the consent screen.
  const requestedScopeStr =
    body.scope || [...SUPPORTED_SCOPES].join(' ');
  const { approved: approvedScopes, invalid: invalidScopes } = validateScopes(
    parseScopes(requestedScopeStr)
  );
  if (invalidScopes.length > 0) {
    return jsonError(
      `Unsupported scope(s): ${invalidScopes.join(', ')}. Supported: ${SUPPORTED_SCOPES.join(', ')}`,
      400
    );
  }

  // Clamp client_name to a reasonable length — it's shown on the
  // consent screen, so a malicious client can't use it to phish.
  const clientName = (body.client_name || 'Unnamed MCP Client').slice(0, 120);

  const clientId = generateOAuthClientId();
  const row: OAuthClientRow = {
    id: clientId,
    client_name: clientName,
    redirect_uris: JSON.stringify(body.redirect_uris),
    grant_types: JSON.stringify(grantTypes),
    response_types: JSON.stringify(responseTypes),
    token_endpoint_auth_method: tokenAuthMethod,
    scope: approvedScopes.join(' '),
    logo_uri: body.logo_uri || null,
    client_uri: body.client_uri || null,
    created_at: new Date().toISOString(),
    disabled_at: null,
  };

  try {
    await env.DB.prepare(
      `INSERT INTO oauth_clients
        (id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, scope, logo_uri, client_uri, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        row.id,
        row.client_name,
        row.redirect_uris,
        row.grant_types,
        row.response_types,
        row.token_endpoint_auth_method,
        row.scope,
        row.logo_uri,
        row.client_uri,
        row.created_at
      )
      .run();
  } catch (e) {
    console.error('oauth client insert failed', e);
    return jsonError('Failed to register client', 500);
  }

  // Return the DCR response per RFC 7591 §3.2.1.
  return jsonOk(
    {
      client_id: clientId,
      client_name: clientName,
      redirect_uris: body.redirect_uris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: tokenAuthMethod,
      scope: approvedScopes.join(' '),
      logo_uri: row.logo_uri,
      client_uri: row.client_uri,
      // No client_secret — public client with PKCE.
    },
    201
  );
}

// ============================================================
// Handler: GET /v1/oauth/authorize
// ============================================================
//
// Entry point for the authorization code flow. Validates the request,
// stores the details as an "intent" in KV, and redirects the user's
// browser to the consent screen on the marketing site. The consent
// screen then fetches intent details and POSTs approve/deny to
// /v1/oauth/consent.

export async function handleOAuthAuthorize(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;

  const clientId = params.get('client_id');
  const redirectUri = params.get('redirect_uri');
  const responseType = params.get('response_type');
  const scopeParam = params.get('scope') || '';
  const state = params.get('state');
  const codeChallenge = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method');

  // These errors can't be safely redirected back to the client (we
  // haven't validated the redirect URI yet) so we return a JSON error.
  if (!clientId) return jsonError('Missing client_id', 400);
  if (!redirectUri) return jsonError('Missing redirect_uri', 400);

  const client = await getClientById(env, clientId);
  if (!client) return jsonError('Unknown client_id', 400);
  if (client.disabled_at) return jsonError('Client disabled', 400);

  const allowedRedirectUris = JSON.parse(client.redirect_uris) as string[];
  if (!allowedRedirectUris.includes(redirectUri)) {
    return jsonError(
      'redirect_uri does not match any registered URI for this client',
      400
    );
  }

  // From this point on, validation errors can be redirected back to
  // the client per RFC 6749 §4.1.2.1. We encode the error as query
  // params on the redirect_uri.
  const redirectBack = (errorCode: string, errorDesc: string): Response => {
    const back = new URL(redirectUri);
    back.searchParams.set('error', errorCode);
    back.searchParams.set('error_description', errorDesc);
    if (state) back.searchParams.set('state', state);
    return Response.redirect(back.toString(), 302);
  };

  if (responseType !== 'code') {
    return redirectBack('unsupported_response_type', 'Only response_type=code is supported');
  }
  if (!codeChallenge) {
    return redirectBack('invalid_request', 'code_challenge is required (PKCE mandatory)');
  }
  if (codeChallengeMethod !== 'S256') {
    return redirectBack('invalid_request', 'code_challenge_method must be S256');
  }

  const requestedScopes = parseScopes(scopeParam);
  if (requestedScopes.length === 0) {
    return redirectBack('invalid_scope', 'At least one scope is required');
  }
  const { approved, invalid } = validateScopes(requestedScopes);
  if (invalid.length > 0) {
    return redirectBack(
      'invalid_scope',
      `Unsupported scope(s): ${invalid.join(', ')}`
    );
  }

  // Create the intent record and store it in KV.
  const intentId = generateToken();
  const intent: OAuthIntent = {
    client_id: clientId,
    redirect_uri: redirectUri,
    scopes: approved,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    created_at: Date.now(),
  };
  await env.KEYS.put(
    `${OAUTH_INTENT_PREFIX}${intentId}`,
    JSON.stringify(intent),
    { expirationTtl: OAUTH_INTENT_TTL_SECONDS }
  );

  // Redirect the browser to the consent screen on the marketing site.
  // The consent page will fetch intent details and render the UI.
  const consentUrl = new URL(CONSENT_SCREEN_URL);
  consentUrl.searchParams.set('intent', intentId);
  return Response.redirect(consentUrl.toString(), 302);
}

// ============================================================
// Handler: GET /v1/oauth/intent?id=... (session-required)
// ============================================================
//
// Called by the consent screen (www.apilocker.app/oauth-consent) to
// fetch details about the pending authorization. Returns the client
// name, the requested scopes, and basic info so the UI can render
// a meaningful consent card.
//
// Requires session auth, so the consent page only renders after the
// user is signed in to API Locker. If not signed in, the Pages-side
// JS catches the 401 and redirects to /login with return_to set to
// the consent page.

export async function handleOAuthIntent(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const url = new URL(request.url);
  const intentId = url.searchParams.get('id');
  if (!intentId) return jsonError('Missing id', 400);

  const raw = await env.KEYS.get(`${OAUTH_INTENT_PREFIX}${intentId}`);
  if (!raw) return jsonError('Intent not found or expired', 404);

  let intent: OAuthIntent;
  try {
    intent = JSON.parse(raw) as OAuthIntent;
  } catch {
    return jsonError('Corrupt intent record', 500);
  }

  const client = await getClientById(env, intent.client_id);
  if (!client) return jsonError('Unknown client', 404);

  // Look up the user's email so the consent screen can show "Signed
  // in as foo@bar.com" for clarity.
  const user = await env.DB.prepare('SELECT email, name FROM users WHERE id = ?')
    .bind(userId)
    .first<{ email: string; name: string | null }>();

  return jsonOk({
    intent_id: intentId,
    client: {
      name: client.client_name,
      logo_uri: client.logo_uri,
      client_uri: client.client_uri,
    },
    scopes: intent.scopes,
    scope_descriptions: scopeDescriptions(intent.scopes),
    user: {
      email: user?.email ?? null,
      name: user?.name ?? null,
    },
  });
}

/**
 * Plain-English descriptions of each scope to show on the consent
 * screen. Claude and other MCP clients typically request all three.
 */
function scopeDescriptions(scopes: string[]): Record<string, string> {
  const map: Record<string, string> = {
    'vault:read':
      'Read and list your credentials, reveal their values when you ask, view activity, and run vault health checks.',
    'vault:write':
      'Create, rotate, rename, pause, resume, and delete credentials in your vault.',
    'vault:proxy':
      'Make authenticated API calls to external services (OpenAI, Stripe, etc.) through your stored credentials. The raw keys are never sent to this client.',
  };
  const result: Record<string, string> = {};
  for (const s of scopes) result[s] = map[s] || s;
  return result;
}

// ============================================================
// Handler: POST /v1/oauth/consent (session-required)
// ============================================================
//
// The consent screen POSTs here with the intent_id and either
// { approved: true } or { approved: false }. On approval we generate
// an authorization code, store it in KV with the user_id bound, and
// return the redirect URL the browser should go to (Claude's callback
// with the code attached). The consent screen JS does a window.location
// to that URL.

interface ConsentRequest {
  intent_id: string;
  approved: boolean;
}

export async function handleOAuthConsent(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: ConsentRequest;
  try {
    body = (await request.json()) as ConsentRequest;
  } catch {
    return jsonError('Invalid JSON body', 400);
  }
  if (!body.intent_id) return jsonError('Missing intent_id', 400);

  const key = `${OAUTH_INTENT_PREFIX}${body.intent_id}`;
  const raw = await env.KEYS.get(key);
  if (!raw) return jsonError('Intent not found or expired', 404);
  // Single-use: delete immediately.
  await env.KEYS.delete(key);

  let intent: OAuthIntent;
  try {
    intent = JSON.parse(raw) as OAuthIntent;
  } catch {
    return jsonError('Corrupt intent record', 500);
  }

  // Denial: redirect back to the client with error=access_denied.
  if (!body.approved) {
    const back = new URL(intent.redirect_uri);
    back.searchParams.set('error', 'access_denied');
    back.searchParams.set('error_description', 'User denied the authorization request');
    if (intent.state) back.searchParams.set('state', intent.state);
    return jsonOk({ redirect_url: back.toString() });
  }

  // Approval: mint an authorization code and return the redirect URL.
  const code = generateToken();
  const codeRecord: OAuthAuthCode = {
    user_id: userId,
    client_id: intent.client_id,
    redirect_uri: intent.redirect_uri,
    scopes: intent.scopes,
    code_challenge: intent.code_challenge,
    code_challenge_method: intent.code_challenge_method,
    created_at: Date.now(),
  };
  await env.KEYS.put(
    `${OAUTH_CODE_PREFIX}${code}`,
    JSON.stringify(codeRecord),
    { expirationTtl: OAUTH_CODE_TTL_SECONDS }
  );

  const back = new URL(intent.redirect_uri);
  back.searchParams.set('code', code);
  if (intent.state) back.searchParams.set('state', intent.state);
  return jsonOk({ redirect_url: back.toString() });
}

// ============================================================
// Handler: POST /v1/oauth/token
// ============================================================
//
// Token endpoint. Supports two grant types:
//   1. authorization_code — exchange a code (from /authorize) for
//      access_token + refresh_token. PKCE verification required.
//   2. refresh_token      — rotate to a new access_token + refresh_token.
//                           Reuse of an old refresh token triggers
//                           family-wide revoke (token theft detection).

export async function handleOAuthToken(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  // OAuth token endpoint is form-urlencoded per RFC 6749.
  const contentType = request.headers.get('Content-Type') || '';
  let form: URLSearchParams;
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      form = new URLSearchParams(await request.text());
    } else if (contentType.includes('application/json')) {
      // Some MCP clients send JSON. Accept both for forgiveness.
      const body = (await request.json()) as Record<string, string>;
      form = new URLSearchParams(body as any);
    } else {
      // Attempt form parse anyway
      form = new URLSearchParams(await request.text());
    }
  } catch {
    return jsonError('Invalid request body', 400);
  }

  const grantType = form.get('grant_type');

  if (grantType === 'authorization_code') {
    return handleAuthorizationCodeGrant(form, env);
  }
  if (grantType === 'refresh_token') {
    return handleRefreshTokenGrant(form, env);
  }
  return oauthError('unsupported_grant_type', `Unsupported grant_type: ${grantType}`, 400);
}

async function handleAuthorizationCodeGrant(
  form: URLSearchParams,
  env: Env
): Promise<Response> {
  const code = form.get('code');
  const clientId = form.get('client_id');
  const redirectUri = form.get('redirect_uri');
  const codeVerifier = form.get('code_verifier');

  if (!code) return oauthError('invalid_request', 'Missing code', 400);
  if (!clientId) return oauthError('invalid_request', 'Missing client_id', 400);
  if (!redirectUri) return oauthError('invalid_request', 'Missing redirect_uri', 400);
  if (!codeVerifier) return oauthError('invalid_request', 'Missing code_verifier (PKCE mandatory)', 400);

  // Look up the code (single-use — delete after read).
  const codeKey = `${OAUTH_CODE_PREFIX}${code}`;
  const rawCode = await env.KEYS.get(codeKey);
  if (!rawCode) return oauthError('invalid_grant', 'Authorization code not found or expired', 400);
  await env.KEYS.delete(codeKey);

  let codeRecord: OAuthAuthCode;
  try {
    codeRecord = JSON.parse(rawCode) as OAuthAuthCode;
  } catch {
    return oauthError('invalid_grant', 'Corrupt authorization code', 400);
  }

  // Bind checks.
  if (codeRecord.client_id !== clientId) {
    return oauthError('invalid_grant', 'client_id mismatch', 400);
  }
  if (codeRecord.redirect_uri !== redirectUri) {
    return oauthError('invalid_grant', 'redirect_uri mismatch', 400);
  }

  // PKCE verification.
  const pkceOk = await verifyPKCE(codeVerifier, codeRecord.code_challenge);
  if (!pkceOk) {
    return oauthError('invalid_grant', 'PKCE verification failed', 400);
  }

  // Verify the client is still active.
  const client = await getClientById(env, clientId);
  if (!client || client.disabled_at) {
    return oauthError('invalid_client', 'Client not found or disabled', 400);
  }

  // Issue access + refresh tokens.
  // Re-narrow scopes from string[] to OAuthScope[] — they were
  // validated at /authorize time, so any element we stored is a
  // known scope.
  return await issueTokenPair(env, {
    user_id: codeRecord.user_id,
    client_id: clientId,
    scopes: codeRecord.scopes as OAuthScope[],
    familyId: null, // Create a new family
  });
}

async function handleRefreshTokenGrant(
  form: URLSearchParams,
  env: Env
): Promise<Response> {
  const refreshToken = form.get('refresh_token');
  const clientId = form.get('client_id');

  if (!refreshToken) return oauthError('invalid_request', 'Missing refresh_token', 400);
  if (!clientId) return oauthError('invalid_request', 'Missing client_id', 400);
  if (!refreshToken.startsWith(REFRESH_TOKEN_PREFIX)) {
    return oauthError('invalid_grant', 'Malformed refresh_token', 400);
  }

  const refreshHash = await hashToken(refreshToken);

  // Look up by current refresh token first.
  const row = await env.DB.prepare(
    `SELECT * FROM oauth_access_tokens WHERE refresh_token_hash = ? AND revoked_at IS NULL LIMIT 1`
  )
    .bind(refreshHash)
    .first<{
      id: string;
      user_id: string;
      client_id: string;
      scopes: string;
      refresh_token_expires_at: string;
      refresh_token_family_id: string;
    }>();

  if (row) {
    // Happy path: rotate.
    if (row.client_id !== clientId) {
      return oauthError('invalid_grant', 'client_id mismatch', 400);
    }
    if (new Date(row.refresh_token_expires_at) < new Date()) {
      return oauthError('invalid_grant', 'refresh_token expired', 400);
    }
    // Mark the current row as rotated (previous_refresh_token_hash =
    // current, then issue a new access+refresh. The old refresh is now
    // in "previous" slot for reuse detection.
    await env.DB.prepare(
      `UPDATE oauth_access_tokens
         SET previous_refresh_token_hash = refresh_token_hash,
             refresh_token_hash = NULL,
             last_refreshed_at = ?
         WHERE id = ?`
    )
      .bind(new Date().toISOString(), row.id)
      .run();

    return await issueTokenPair(env, {
      user_id: row.user_id,
      client_id: row.client_id,
      scopes: parseScopes(row.scopes) as OAuthScope[],
      familyId: row.refresh_token_family_id,
    });
  }

  // Token not found as current — check if it's a previous (reused) refresh.
  const reuseRow = await env.DB.prepare(
    `SELECT refresh_token_family_id FROM oauth_access_tokens WHERE previous_refresh_token_hash = ? LIMIT 1`
  )
    .bind(refreshHash)
    .first<{ refresh_token_family_id: string }>();

  if (reuseRow) {
    // REUSE DETECTED: revoke the entire family.
    await env.DB.prepare(
      `UPDATE oauth_access_tokens
         SET revoked_at = ?, reuse_detected_at = ?
         WHERE refresh_token_family_id = ? AND revoked_at IS NULL`
    )
      .bind(
        new Date().toISOString(),
        new Date().toISOString(),
        reuseRow.refresh_token_family_id
      )
      .run();
    return oauthError('invalid_grant', 'Refresh token reuse detected — family revoked', 400);
  }

  return oauthError('invalid_grant', 'Invalid refresh_token', 400);
}

/**
 * Issue a new (access_token, refresh_token) pair for a (user, client,
 * scopes) grant. If familyId is null, create a new family (fresh grant);
 * if set, reuse it (refresh rotation).
 */
async function issueTokenPair(
  env: Env,
  grant: {
    user_id: string;
    client_id: string;
    scopes: OAuthScope[];
    familyId: string | null;
  }
): Promise<Response> {
  const accessToken = generatePrefixedToken(ACCESS_TOKEN_PREFIX);
  const refreshToken = generatePrefixedToken(REFRESH_TOKEN_PREFIX);
  const accessHash = await hashToken(accessToken);
  const refreshHash = await hashToken(refreshToken);

  const now = new Date();
  const accessExpires = new Date(now.getTime() + OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000);
  const refreshExpires = new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_SECONDS * 1000);
  const familyId = grant.familyId || crypto.randomUUID();

  const rowId = generateOAuthTokenId();

  try {
    await env.DB.prepare(
      `INSERT INTO oauth_access_tokens
        (id, user_id, client_id, scopes, access_token_hash, access_token_expires_at, refresh_token_hash, refresh_token_expires_at, refresh_token_family_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        rowId,
        grant.user_id,
        grant.client_id,
        grant.scopes.join(' '),
        accessHash,
        accessExpires.toISOString(),
        refreshHash,
        refreshExpires.toISOString(),
        familyId,
        now.toISOString()
      )
      .run();
  } catch (e) {
    console.error('oauth token insert failed', e);
    return jsonError('Failed to issue token', 500);
  }

  return jsonOk({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope: grant.scopes.join(' '),
  });
}

// ============================================================
// Validation: called by MCP endpoint to authenticate OAuth tokens
// ============================================================

/**
 * Check if a Bearer token is a valid OAuth access token. Returns the
 * user, client, and approved scopes on success; null otherwise. Called
 * by validateMCPAuth BEFORE the existing scoped/session paths.
 *
 * Matching is by SHA-256 hash so a DB leak doesn't expose tokens.
 */
export async function validateOAuthAccessToken(
  token: string,
  env: Env
): Promise<OAuthAccessTokenContext | null> {
  if (!token.startsWith(ACCESS_TOKEN_PREFIX)) return null;

  const hash = await hashToken(token);
  const row = await env.DB.prepare(
    `SELECT id, user_id, client_id, scopes, access_token_expires_at, revoked_at
       FROM oauth_access_tokens
       WHERE access_token_hash = ?
       LIMIT 1`
  )
    .bind(hash)
    .first<{
      id: string;
      user_id: string;
      client_id: string;
      scopes: string;
      access_token_expires_at: string;
      revoked_at: string | null;
    }>();

  if (!row) return null;
  if (row.revoked_at) return null;
  if (new Date(row.access_token_expires_at) < new Date()) return null;

  return {
    token_id: row.id,
    user_id: row.user_id,
    client_id: row.client_id,
    scopes: parseScopes(row.scopes),
  };
}

// ============================================================
// Small D1 helper
// ============================================================

async function getClientById(env: Env, clientId: string): Promise<OAuthClientRow | null> {
  return await env.DB.prepare(`SELECT * FROM oauth_clients WHERE id = ? LIMIT 1`)
    .bind(clientId)
    .first<OAuthClientRow>();
}

/**
 * Build an OAuth-style error response per RFC 6749 §5.2.
 */
function oauthError(code: string, description: string, status: number): Response {
  return jsonError(`${code}: ${description}`, status);
}
