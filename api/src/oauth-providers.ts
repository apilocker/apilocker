/**
 * oauth-providers.ts — registry of supported sign-in OAuth providers.
 *
 * This is the single source of truth for how to run an OAuth
 * authorization-code flow against any supported provider. Adding a new
 * sign-in provider means adding one object to OAUTH_PROVIDERS below —
 * no changes to oauth.ts, routes.ts, or the login page HTML.
 *
 * The login flow is:
 *   1. User clicks a button on /login or /signup
 *   2. Browser hits GET /v1/auth/:provider — looks up the provider
 *      config here, loads the credential from the vault, redirects to
 *      the authorize URL with the right client_id + scopes
 *   3. User approves on the provider's consent screen
 *   4. Provider redirects to /v1/auth/:provider/callback?code=...
 *   5. Callback handler looks up the provider config, loads the
 *      credential from the vault, exchanges code for token, fetches
 *      user info, normalizes it via user_mapper, creates/updates the
 *      user row, sets session cookie, redirects to return_to
 *
 * Provider enablement is dynamic:
 *   - A provider is "enabled" iff the matching vault credential exists
 *     under the name `vault_key_name` for the service user
 *   - The GET /v1/auth/providers discovery endpoint returns the list
 *     of enabled providers, which the login page uses to render
 *     buttons dynamically
 *   - So: adding LinkedIn is two steps. (1) store the LinkedIn OAuth
 *     credential in the vault under "API Locker - LinkedIn".
 *     (2) If LinkedIn is already in this registry (it is, for the
 *     pre-populated providers below), done. If not, add an object
 *     here — one place, one file.
 */

/**
 * Shape of a single provider's user-info response after normalization.
 * Every provider's raw user response is passed through its `user_mapper`
 * to produce this shape before being handed to the shared login logic.
 */
export interface NormalizedOAuthUser {
  oauthId: string;
  email: string | null;
  name: string | null;
  avatarUrl: string | null;
}

/**
 * How the token exchange POST body is encoded. Different providers
 * expect different formats — Google/LinkedIn/Slack/Microsoft use
 * form-urlencoded, GitHub accepts JSON.
 */
export type TokenExchangeStyle = 'form' | 'json';

export interface OAuthProviderConfig {
  /** URL-safe ID used in routes. Must be lowercase alnum + dashes. */
  id: string;
  /** Human-readable name shown in the login button label. */
  display_name: string;
  /**
   * Vault credential name this provider looks for. Convention:
   * "API Locker - {DisplayName}". The service user must have a
   * credential stored under this exact name for the provider to be
   * considered "enabled."
   */
  vault_key_name: string;
  /** OAuth authorization endpoint (browser is redirected here) */
  authorize_url: string;
  /** OAuth token exchange endpoint (server-to-server POST) */
  token_url: string;
  /** Authenticated user-info endpoint (called with the access_token) */
  user_info_url: string;
  /** Space-separated scope string as the provider expects it */
  scope: string;
  /** Token exchange body encoding (defaults to 'form') */
  token_exchange_style?: TokenExchangeStyle;
  /**
   * Extra HTTP headers to send to the user_info_url. GitHub requires
   * a User-Agent; some providers want Accept: application/json.
   */
  user_info_headers?: Record<string, string>;
  /**
   * Map the provider's raw user-info JSON response to our normalized
   * shape. This is the one bit of provider-specific logic we can't
   * avoid — every provider uses different field names.
   */
  user_mapper: (rawUserInfo: any) => NormalizedOAuthUser;
  /**
   * Optional post-user-info hook for providers that need an extra
   * call to resolve the email (GitHub, which returns email=null when
   * the user keeps it private). Called only if the mapper returns
   * email=null, and its return value REPLACES the email.
   */
  resolve_email?: (accessToken: string) => Promise<string | null>;
  /**
   * SVG logo markup for the login button. Inlined so the login page
   * doesn't need to fetch external assets.
   */
  icon_svg: string;
  /** Brand color (used for button background if the theme wants it) */
  brand_color: string;
  /** Text color for the button (white for dark brands, dark for light) */
  text_color?: string;
}

// ============================================================
// PROVIDERS
// ============================================================
//
// To add a new sign-in provider:
//   1. Add an entry to OAUTH_PROVIDERS below
//   2. Store the credential in the vault under the matching
//      vault_key_name via the dashboard
//   3. Register the corresponding redirect URI with the provider:
//      https://api.apilocker.app/v1/auth/{id}/callback
//   4. Deploy. The login page auto-picks up the new button.
//
// That's it. No other files need to change.

export const OAUTH_PROVIDERS: Record<string, OAuthProviderConfig> = {
  // ---- Google ----
  google: {
    id: 'google',
    display_name: 'Google',
    vault_key_name: 'API Locker - Google',
    authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token',
    user_info_url: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scope: 'email profile',
    token_exchange_style: 'form',
    user_mapper: (u: any): NormalizedOAuthUser => ({
      oauthId: String(u.id),
      email: u.email || null,
      name: u.name || null,
      avatarUrl: u.picture || null,
    }),
    icon_svg:
      '<svg width="20" height="20" viewBox="0 0 48 48"><path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/><path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"/><path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/><path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002 6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/></svg>',
    brand_color: '#ffffff',
    text_color: '#1f2937',
  },

  // ---- GitHub ----
  github: {
    id: 'github',
    display_name: 'GitHub',
    vault_key_name: 'API Locker - GitHub',
    authorize_url: 'https://github.com/login/oauth/authorize',
    token_url: 'https://github.com/login/oauth/access_token',
    user_info_url: 'https://api.github.com/user',
    scope: 'user:email',
    token_exchange_style: 'json',
    user_info_headers: {
      'User-Agent': 'APILocker',
    },
    user_mapper: (u: any): NormalizedOAuthUser => ({
      oauthId: String(u.id),
      email: u.email || null,
      name: u.login || null,
      avatarUrl: u.avatar_url || null,
    }),
    // GitHub hides private emails from /user; fall back to /user/emails.
    resolve_email: async (accessToken: string): Promise<string | null> => {
      const res = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'APILocker',
        },
      });
      if (!res.ok) return null;
      const emails = (await res.json()) as Array<{ email: string; primary: boolean }>;
      return emails.find((e) => e.primary)?.email || emails[0]?.email || null;
    },
    icon_svg:
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.27-.01-1-.02-1.96-3.2.69-3.87-1.54-3.87-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.43-2.69 5.41-5.26 5.69.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z"/></svg>',
    brand_color: '#24292f',
    text_color: '#ffffff',
  },

  // ---- LinkedIn ----
  // Uses LinkedIn's "Sign In with LinkedIn using OpenID Connect" which
  // replaced the old v2 OAuth flow in 2023. Scopes are standard OIDC.
  linkedin: {
    id: 'linkedin',
    display_name: 'LinkedIn',
    vault_key_name: 'API Locker - LinkedIn',
    authorize_url: 'https://www.linkedin.com/oauth/v2/authorization',
    token_url: 'https://www.linkedin.com/oauth/v2/accessToken',
    user_info_url: 'https://api.linkedin.com/v2/userinfo',
    scope: 'openid profile email',
    token_exchange_style: 'form',
    user_mapper: (u: any): NormalizedOAuthUser => ({
      // LinkedIn OIDC returns `sub` as the stable user identifier
      oauthId: String(u.sub),
      email: u.email || null,
      name: u.name || null,
      avatarUrl: u.picture || null,
    }),
    icon_svg:
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="#0A66C2"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.063 2.063 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>',
    brand_color: '#0A66C2',
    text_color: '#ffffff',
  },

  // ---- Slack ----
  // "Sign in with Slack" uses OIDC too.
  slack: {
    id: 'slack',
    display_name: 'Slack',
    vault_key_name: 'API Locker - Slack',
    authorize_url: 'https://slack.com/openid/connect/authorize',
    token_url: 'https://slack.com/api/openid.connect.token',
    user_info_url: 'https://slack.com/api/openid.connect.userInfo',
    scope: 'openid profile email',
    token_exchange_style: 'form',
    user_mapper: (u: any): NormalizedOAuthUser => ({
      oauthId: String(u.sub),
      email: u.email || null,
      name: u.name || null,
      avatarUrl: u.picture || null,
    }),
    icon_svg:
      '<svg width="20" height="20" viewBox="0 0 24 24"><path fill="#E01E5A" d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z"/><path fill="#36C5F0" d="M8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312z"/><path fill="#2EB67D" d="M18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312z"/><path fill="#ECB22E" d="M15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>',
    brand_color: '#4A154B',
    text_color: '#ffffff',
  },

  // ---- Microsoft ----
  // Common-tenant OAuth 2.0 / Azure AD. Works for both personal
  // Microsoft accounts (outlook.com, hotmail) and organizational accounts.
  microsoft: {
    id: 'microsoft',
    display_name: 'Microsoft',
    vault_key_name: 'API Locker - Microsoft',
    authorize_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    token_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    user_info_url: 'https://graph.microsoft.com/v1.0/me',
    scope: 'openid profile email User.Read',
    token_exchange_style: 'form',
    user_mapper: (u: any): NormalizedOAuthUser => ({
      oauthId: String(u.id),
      email: u.mail || u.userPrincipalName || null,
      name: u.displayName || null,
      avatarUrl: null, // Graph /me/photo would need a separate call
    }),
    icon_svg:
      '<svg width="20" height="20" viewBox="0 0 23 23"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>',
    brand_color: '#2F2F2F',
    text_color: '#ffffff',
  },
};

/**
 * Look up a provider config by ID, or null if the ID isn't registered.
 */
export function getOAuthProvider(id: string): OAuthProviderConfig | null {
  return OAUTH_PROVIDERS[id] ?? null;
}

/**
 * List all registered providers. Order is the iteration order of the
 * OAUTH_PROVIDERS object (which in modern JS is insertion order).
 */
export function listOAuthProviders(): OAuthProviderConfig[] {
  return Object.values(OAUTH_PROVIDERS);
}
