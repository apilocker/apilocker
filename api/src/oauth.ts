import { Env } from './types';
import { generateId, generateToken, hashToken } from './crypto';
import { findUserByOAuth, createUser, updateUserLogin, createSession, deleteUserSessions, getUserById, setMasterTokenHash } from './db';
import { setSessionCookie, clearSessionCookie } from './auth';
import { jsonOk, jsonError } from './responses';
import { getVaultOAuthCredential, vaultCredentialExists } from './vault-client';
import {
  getOAuthProvider,
  listOAuthProviders,
  OAuthProviderConfig,
  NormalizedOAuthUser,
} from './oauth-providers';

const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days in seconds
const DEFAULT_REDIRECT = 'https://www.apilocker.app/dashboard';

// ---- CSRF state + return_to support ----
//
// Every OAuth flow is now protected by a single-use, short-lived state token.
// This blocks CSRF attacks on the callback, and doubles as a signed carrier
// for a `return_to` URL so the same OAuth handlers can power the dashboard
// login AND the CLI device-authorization flow.
//
// Storage: we piggyback on the existing KEYS KV namespace with an
// `oauth_state:` prefix. No wrangler.toml changes needed.
//
// Security properties:
//   1. State is 32 random bytes, url-safe base64 encoded — unguessable.
//   2. TTL of 10 minutes via KV expirationTtl — attacker can't sit on a
//      leaked state token.
//   3. Single-use — state entry is DELETED immediately on consumption, so
//      replay attacks fail.
//   4. Provider-bound — a state minted for GitHub cannot be consumed by the
//      Google callback, even if it leaks.
//   5. return_to is validated against an allowlist of origins AND must be a
//      same-origin URL, preventing open-redirect attacks.

const OAUTH_STATE_TTL_SECONDS = 600; // 10 minutes
const OAUTH_STATE_PREFIX = 'oauth_state:';

const ALLOWED_REDIRECT_ORIGINS = [
  'https://www.apilocker.app',
  'https://apilocker.app',
];

/**
 * Validate a `return_to` value and normalize it to an absolute URL we are
 * willing to redirect to. Returns null if the input is unsafe.
 *
 * Accepts:
 *   - Relative paths starting with `/` but NOT `//` (which would be a
 *     protocol-relative URL pointing somewhere else). Normalized to
 *     www.apilocker.app as the host.
 *   - Absolute URLs whose origin exactly matches ALLOWED_REDIRECT_ORIGINS.
 *
 * Rejects everything else (other hosts, javascript:, data:, mailto:, etc.).
 */
function validateReturnTo(returnTo: string | null | undefined): string | null {
  if (!returnTo) return null;

  // Relative path — must start with a single slash
  if (returnTo.startsWith('/') && !returnTo.startsWith('//')) {
    return `https://www.apilocker.app${returnTo}`;
  }

  // Absolute URL — must match an allowed origin exactly
  try {
    const url = new URL(returnTo);
    const origin = `${url.protocol}//${url.host}`;
    if (ALLOWED_REDIRECT_ORIGINS.includes(origin)) {
      return returnTo;
    }
  } catch {
    // Not a valid URL
  }

  return null;
}

interface OAuthStateRecord {
  return_to: string;
  /** Provider ID from the registry (e.g. 'github', 'google', 'linkedin'). */
  provider: string;
  created_at: number;
}

/**
 * Mint a new state token for an OAuth flow and store the associated
 * return_to in KV with a 10-minute TTL. The returned state is passed through
 * to the OAuth provider and echoed back on the callback.
 */
async function mintOAuthState(
  env: Env,
  provider: string,
  returnTo: string
): Promise<string> {
  const state = generateToken(); // 32 random bytes, url-safe base64
  const record: OAuthStateRecord = {
    return_to: returnTo,
    provider,
    created_at: Date.now(),
  };
  await env.KEYS.put(
    `${OAUTH_STATE_PREFIX}${state}`,
    JSON.stringify(record),
    { expirationTtl: OAUTH_STATE_TTL_SECONDS }
  );
  return state;
}

/**
 * Validate and consume a state token on the OAuth callback. Returns the
 * associated `return_to` URL on success, or null on any failure (missing,
 * expired, wrong provider, malformed).
 *
 * The KV entry is deleted immediately on consumption — state is single-use.
 */
async function consumeOAuthState(
  env: Env,
  state: string | null,
  provider: string
): Promise<string | null> {
  if (!state) return null;

  const key = `${OAUTH_STATE_PREFIX}${state}`;
  const raw = await env.KEYS.get(key);
  if (!raw) return null;

  // Single-use: delete immediately so replays fail
  await env.KEYS.delete(key);

  try {
    const record = JSON.parse(raw) as OAuthStateRecord;
    if (record.provider !== provider) return null;
    return record.return_to;
  } catch {
    return null;
  }
}

// ---- Generic provider-driven OAuth handlers ----
//
// These two handlers power sign-in for EVERY provider in the registry
// (src/oauth-providers.ts). Routes `/v1/auth/:provider` and
// `/v1/auth/:provider/callback` dispatch here; the provider config is
// looked up by the :provider URL parameter and drives everything from
// authorize URL to user-info parsing.

export async function handleOAuthStart(
  request: Request,
  env: Env,
  params: Record<string, string>
): Promise<Response> {
  const providerId = params.provider;
  const provider = getOAuthProvider(providerId);
  if (!provider) {
    return jsonError(`Unknown OAuth provider: ${providerId}`, 404);
  }

  const url = new URL(request.url);
  const returnTo = validateReturnTo(url.searchParams.get('return_to')) ?? DEFAULT_REDIRECT;
  const state = await mintOAuthState(env, provider.id, returnTo);

  // Load the provider's credential from the vault (cached 60s).
  let creds;
  try {
    creds = await getVaultOAuthCredential(env, provider.vault_key_name);
  } catch (e) {
    console.error(`Failed to load ${provider.id} OAuth credential from vault:`, e);
    return jsonError('OAuth configuration error', 500);
  }

  const redirectUri = `${url.origin}/v1/auth/${provider.id}/callback`;

  // Build the authorize URL. We use URLSearchParams for proper
  // percent-encoding across all providers, since some (LinkedIn,
  // Microsoft) are picky about scope formatting.
  const authorizeParams = new URLSearchParams({
    client_id: creds.client_id,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: provider.scope,
    state,
  });

  return Response.redirect(`${provider.authorize_url}?${authorizeParams.toString()}`, 302);
}

export async function handleOAuthCallback(
  request: Request,
  env: Env,
  params: Record<string, string>
): Promise<Response> {
  const providerId = params.provider;
  const provider = getOAuthProvider(providerId);
  if (!provider) {
    return jsonError(`Unknown OAuth provider: ${providerId}`, 404);
  }

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code) {
    return jsonError('Missing authorization code', 400);
  }

  // CSRF protection: state must validate against THIS provider
  const returnTo = await consumeOAuthState(env, state, provider.id);
  if (!returnTo) {
    return jsonError('Invalid or expired OAuth state', 400);
  }

  // Load creds from vault (cached 60s)
  let creds;
  try {
    creds = await getVaultOAuthCredential(env, provider.vault_key_name);
  } catch (e) {
    console.error(`Failed to load ${provider.id} OAuth credential from vault:`, e);
    return jsonError('OAuth configuration error', 500);
  }

  const redirectUri = `${url.origin}/v1/auth/${provider.id}/callback`;

  // Token exchange — body format varies by provider
  const tokenExchangeBody = {
    code,
    client_id: creds.client_id,
    client_secret: creds.client_secret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  };

  let tokenResponse: Response;
  if (provider.token_exchange_style === 'json') {
    tokenResponse = await fetch(provider.token_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(tokenExchangeBody),
    });
  } else {
    // Default: form-urlencoded
    tokenResponse = await fetch(provider.token_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams(tokenExchangeBody as Record<string, string>),
    });
  }

  const tokenData = (await tokenResponse.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };
  if (!tokenData.access_token) {
    console.error(`${provider.id} token exchange failed:`, tokenData);
    return jsonError('Failed to exchange code for token', 400);
  }

  // Fetch user info using the access_token
  const userResponse = await fetch(provider.user_info_url, {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: 'application/json',
      ...(provider.user_info_headers || {}),
    },
  });

  if (!userResponse.ok) {
    console.error(
      `${provider.id} user-info fetch failed: HTTP ${userResponse.status}`
    );
    return jsonError('Failed to fetch user info from provider', 400);
  }

  let rawUserInfo: any;
  try {
    rawUserInfo = await userResponse.json();
  } catch (e) {
    console.error(`${provider.id} user-info parse failed:`, e);
    return jsonError('Invalid user-info response from provider', 400);
  }

  // Normalize the provider's user-info response
  let normalized: NormalizedOAuthUser;
  try {
    normalized = provider.user_mapper(rawUserInfo);
  } catch (e) {
    console.error(`${provider.id} user_mapper threw:`, e);
    return jsonError('Failed to parse user info from provider', 500);
  }

  // Provider-specific email fallback (GitHub returns null for private emails)
  if (!normalized.email && provider.resolve_email) {
    try {
      normalized.email = await provider.resolve_email(tokenData.access_token);
    } catch (e) {
      console.error(`${provider.id} resolve_email failed:`, e);
    }
  }

  if (!normalized.email) {
    return jsonError(
      `Could not retrieve email from ${provider.display_name}`,
      400
    );
  }

  return handleOAuthLogin(
    env,
    {
      provider: provider.id,
      oauthId: normalized.oauthId,
      email: normalized.email,
      name: normalized.name || normalized.email,
      avatarUrl: normalized.avatarUrl || '',
    },
    returnTo
  );
}

// ---- Discovery endpoint ----
//
// GET /v1/auth/providers — returns the list of OAuth providers that
// are (a) registered in src/oauth-providers.ts AND (b) have a
// credential present in the vault for the service user.
//
// The login / signup pages hit this on load and render buttons
// dynamically, so adding a new provider is zero-touch on the HTML
// side: store the credential, add the registry entry, deploy.

export async function handleListOAuthProviders(
  _request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  const all = listOAuthProviders();
  const enabled = await Promise.all(
    all.map(async (p) => ({
      id: p.id,
      display_name: p.display_name,
      enabled: await vaultCredentialExists(env, p.vault_key_name),
      auth_url: `/v1/auth/${p.id}`,
      icon_svg: p.icon_svg,
      brand_color: p.brand_color,
      text_color: p.text_color || '#ffffff',
    }))
  );
  return jsonOk({
    providers: enabled.filter((p) => p.enabled),
  });
}

// ---- Shared OAuth logic ----

interface OAuthUserInfo {
  provider: string;
  oauthId: string;
  email: string;
  name: string;
  avatarUrl: string;
}

async function handleOAuthLogin(
  env: Env,
  info: OAuthUserInfo,
  returnTo: string
): Promise<Response> {
  // Find or create user
  let user = await findUserByOAuth(env, info.provider, info.oauthId);

  if (!user) {
    const userId = generateId('usr');
    await createUser(env, {
      id: userId,
      email: info.email,
      name: info.name,
      avatar_url: info.avatarUrl,
      oauth_provider: info.provider,
      oauth_id: info.oauthId,
    });
    user = (await getUserById(env, userId))!;
  } else {
    await updateUserLogin(env, user.id);
  }

  // Create session
  const sessionId = generateId('ses');
  const sessionToken = generateToken();
  const sessionHash = await hashToken(sessionToken);
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString();

  await createSession(env, sessionId, user.id, sessionHash, expiresAt);

  // Redirect to the validated return_to URL with the session cookie set
  return new Response(null, {
    status: 302,
    headers: {
      Location: returnTo,
      'Set-Cookie': setSessionCookie(sessionToken, SESSION_MAX_AGE),
    },
  });
}

// ---- Logout ----

export async function handleLogout(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  await deleteUserSessions(env, userId);

  return new Response(null, {
    status: 200,
    headers: {
      'Set-Cookie': clearSessionCookie(),
      'Content-Type': 'application/json',
    },
  });
}

// ---- Me (current user info) ----

export async function handleMe(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const user = await getUserById(env, userId);
  if (!user) return jsonError('User not found', 404);

  return jsonOk({
    id: user.id,
    email: user.email,
    name: user.name,
    avatar_url: user.avatar_url,
    has_master_token: !!user.master_token_hash,
    created_at: user.created_at,
  });
}
