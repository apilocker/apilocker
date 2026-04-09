import { addRoute } from './router';
import {
  handleStoreKey,
  handleListKeys,
  handleDeleteKey,
  handleListAllowedKeys,
  handleRotateKey,
  handleRenameKey,
  handlePauseKey,
  handleResumeKey,
} from './keys';
import { handleRevealKeys } from './keys-reveal';
import { handleProxy } from './proxy';
import {
  handleCreateToken,
  handleListTokens,
  handleDeleteToken,
  handlePauseToken,
  handleResumeToken,
  handleRefreshToken,
} from './tokens';
import { handleGetActivity } from './activity';
import {
  handleOAuthStart,
  handleOAuthCallback,
  handleListOAuthProviders,
  handleLogout,
  handleMe,
} from './oauth';
import { handleRegisterDevice, handleListDevices, handleRevokeDevice } from './device';
import {
  handleCliAuthStart,
  handleCliAuthInfo,
  handleCliAuthApprove,
  handleCliAuthDeny,
  handleCliAuthPoll,
} from './cli-auth';
import { handleMCP } from './mcp';
import { handleGetAlerts } from './alerts';
import { handleAdminMetrics, handleAdminCheck } from './admin';

// Auth routes
//
// Route-order matters: specific paths (`/v1/auth/me`, `/v1/auth/logout`,
// `/v1/auth/providers`) MUST come before the generic `/v1/auth/:provider`
// catch-all, otherwise the catch-all will swallow `GET /v1/auth/me` and
// treat "me" as an unknown provider ID.

// Specific routes — registered first so they win against `:provider`
addRoute('GET', '/v1/auth/me', handleMe as any, 'session');
addRoute('POST', '/v1/auth/logout', handleLogout as any, 'session');
addRoute('GET', '/v1/auth/providers', handleListOAuthProviders, 'none');

// Dynamic provider routing (v1.0.2+). `:provider` matches any provider
// ID in the oauth-providers.ts registry — google, github, linkedin,
// slack, microsoft, or any future addition. Discovery endpoint lists
// the providers that are actually enabled (credential present in the
// vault), which the login page uses to render buttons dynamically.
addRoute('GET', '/v1/auth/:provider', handleOAuthStart, 'none');
addRoute('GET', '/v1/auth/:provider/callback', handleOAuthCallback, 'none');

// Key management (session or master token)
addRoute('POST', '/v1/keys', handleStoreKey, 'session');
addRoute('GET', '/v1/keys', handleListKeys, 'session');
addRoute('DELETE', '/v1/keys/:keyId', handleDeleteKey, 'session');
// Reveal plaintext secrets by alias — powers `apilocker run/get/env`.
// Session-level auth (device master token OR dashboard session cookie).
addRoute('POST', '/v1/keys/reveal', handleRevealKeys, 'session');
// Rotate a credential in-place (overwrite KV blob, stamp rotated_at).
addRoute('POST', '/v1/keys/:keyId/rotate', handleRotateKey, 'session');
// Rename / pause / resume (v1.0.0)
addRoute('POST', '/v1/keys/:keyId/rename', handleRenameKey, 'session');
addRoute('POST', '/v1/keys/:keyId/pause', handlePauseKey, 'session');
addRoute('POST', '/v1/keys/:keyId/resume', handleResumeKey, 'session');
// SDK auto-discovery — scoped access token, returns alias-keyed key list.
// Registered as 'none' because the handler validates the scoped token itself.
addRoute('GET', '/v1/keys/allowed', handleListAllowedKeys as any, 'none');

// Token management (session or master token)
addRoute('POST', '/v1/tokens', handleCreateToken, 'session');
addRoute('GET', '/v1/tokens', handleListTokens, 'session');
// DELETE is now a HARD delete (row is removed from D1, cannot be undone).
addRoute('DELETE', '/v1/tokens/:tokenId', handleDeleteToken, 'session');
// Pause / resume — reversible soft-disable.
addRoute('POST', '/v1/tokens/:tokenId/pause', handlePauseToken, 'session');
addRoute('POST', '/v1/tokens/:tokenId/resume', handleResumeToken, 'session');
// Refresh endpoint is unauthenticated at the router level — the handler
// validates the refresh token directly from the Authorization header.
addRoute('POST', '/v1/tokens/refresh', handleRefreshToken as any, 'none');

// Proxy (scoped token only)
addRoute('POST', '/v1/proxy/:keyId', handleProxy, 'scoped');

// Activity logs (session or master token)
addRoute('GET', '/v1/activity', handleGetActivity, 'session');

// Device management (session or master token)
addRoute('POST', '/v1/devices/register', handleRegisterDevice, 'session');
addRoute('GET', '/v1/devices', handleListDevices, 'session');
addRoute('POST', '/v1/devices/:deviceId/revoke', handleRevokeDevice, 'session');

// CLI device authorization flow (v0.2.0+)
// start/info/poll are unauthenticated — the CLI has no credentials yet
// approve/deny require a session (GitHub/Google OAuth sign-in)
addRoute('POST', '/v1/cli-auth/start', handleCliAuthStart as any, 'none');
addRoute('GET', '/v1/cli-auth/info', handleCliAuthInfo as any, 'none');
addRoute('POST', '/v1/cli-auth/approve', handleCliAuthApprove as any, 'session');
addRoute('POST', '/v1/cli-auth/deny', handleCliAuthDeny as any, 'session');
addRoute('POST', '/v1/cli-auth/poll', handleCliAuthPoll as any, 'none');

// Traffic monitoring alerts
addRoute('GET', '/v1/alerts', handleGetAlerts, 'session');

// MCP server (for AI agents)
addRoute('GET', '/v1/mcp', handleMCP as any, 'none');
addRoute('POST', '/v1/mcp', handleMCP as any, 'none');

// Hidden admin analytics (session-authed; gated by ADMIN_USER_IDS secret)
addRoute('GET', '/v1/admin/metrics', handleAdminMetrics, 'session');
addRoute('GET', '/v1/admin/check', handleAdminCheck, 'session');
