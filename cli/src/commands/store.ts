import { Command } from 'commander';
import { apiRequest } from '../api';

/**
 * `apilocker store` — encrypt and store a credential in the vault.
 *
 * v1.0.0 supports two credential types, chosen via the --oauth flag:
 *
 * API key mode (default):
 *   apilocker store --name OPENAI_API_KEY --provider openai --key sk-...
 *
 * OAuth credential mode:
 *   apilocker store \\
 *     --oauth \\
 *     --name google-oauth \\
 *     --provider google-oauth \\
 *     --client-id ... \\
 *     --client-secret ... \\
 *     --refresh-token ... \\      # optional
 *     --scopes "openid email"     # optional
 *
 * Tags can be supplied either via --tags (comma-separated) or --tag
 * (repeatable). Both forms are merged and deduplicated.
 *
 * base_url is now OPTIONAL for all providers. If omitted, the credential
 * is vault-only (usable via run/get/env but not via the proxy). Pass
 * --base-url explicitly to enable proxy routing.
 */

export const storeCommand = new Command('store')
  .description('Store a credential in the vault')
  .requiredOption('--name <name>', 'Credential alias (e.g. OPENAI_API_KEY, google-oauth)')
  .option('--provider <provider>', 'Provider id (e.g. openai, stripe, google-oauth)', 'custom')
  .option('--oauth', 'Store as an OAuth credential (multi-field: client_id, client_secret, refresh_token, etc.)')
  // api_key mode
  .option('--key <key>', 'The raw credential value (api_key mode only)')
  // oauth2 mode fields
  .option('--client-id <id>', 'OAuth client ID (oauth mode only)')
  .option('--client-secret <secret>', 'OAuth client secret (oauth mode only)')
  .option('--refresh-token <token>', 'OAuth refresh token (oauth mode only, optional)')
  .option('--authorize-url <url>', 'OAuth authorize URL (oauth mode only, overrides template default)')
  .option('--token-url <url>', 'OAuth token URL (oauth mode only, overrides template default)')
  .option('--scopes <scopes>', 'OAuth scopes, space-separated (oauth mode only)')
  .option('--redirect-uri <uri>', 'OAuth redirect URI (oauth mode only)')
  // Common options
  .option('--base-url <url>', 'Base URL for proxy access (optional; credentials without this are vault-only)')
  .option('--auth-type <type>', 'Auth type: bearer, x-api-key, basic, query, custom', 'bearer')
  .option('--tag <tag>', 'Tag to apply (repeatable for multiple tags)', collect, [])
  .option('--tags <tags>', 'Comma-separated tag list (merged with --tag)')
  .action(async (opts) => {
    try {
      // Merge tags
      const tagSet = new Set<string>();
      for (const t of opts.tag || []) {
        const trimmed = String(t).trim();
        if (trimmed) tagSet.add(trimmed);
      }
      if (opts.tags) {
        for (const t of String(opts.tags).split(',')) {
          const trimmed = t.trim();
          if (trimmed) tagSet.add(trimmed);
        }
      }

      const body: any = {
        name: opts.name,
        provider: opts.provider,
      };
      if (tagSet.size > 0) body.tags = Array.from(tagSet);

      if (opts.oauth) {
        // OAuth credential mode
        if (!opts.clientId || !opts.clientSecret) {
          console.error('--oauth mode requires both --client-id and --client-secret');
          process.exit(1);
        }
        body.credential_type = 'oauth2';
        body.client_id = opts.clientId;
        body.client_secret = opts.clientSecret;
        if (opts.refreshToken) body.refresh_token = opts.refreshToken;
        if (opts.authorizeUrl) body.authorize_url = opts.authorizeUrl;
        if (opts.tokenUrl) body.token_url = opts.tokenUrl;
        if (opts.scopes) body.scopes = opts.scopes;
        if (opts.redirectUri) body.redirect_uri = opts.redirectUri;
      } else {
        // API key mode
        if (!opts.key) {
          console.error('--key is required (or use --oauth for OAuth credentials)');
          process.exit(1);
        }
        body.credential_type = 'api_key';
        body.key = opts.key;
        if (opts.baseUrl) body.base_url = opts.baseUrl;
        if (opts.authType && opts.provider === 'custom') {
          body.auth_header_type = opts.authType;
        }
      }

      const res = await apiRequest<{
        id: string;
        name: string;
        provider: string;
        credential_type: string;
        proxy_endpoint: string | null;
      }>('/v1/keys', { method: 'POST', body: JSON.stringify(body) });

      console.log(`\x1b[32m✓\x1b[0m Stored: ${res.name}`);
      console.log(`  ID:       ${res.id}`);
      console.log(`  Provider: ${res.provider}`);
      console.log(`  Type:     ${res.credential_type}`);
      if (tagSet.size > 0) {
        console.log(`  Tags:     ${Array.from(tagSet).join(', ')}`);
      }
      if (res.proxy_endpoint) {
        console.log(`  Proxy:    ${res.proxy_endpoint}`);
      } else {
        console.log(`  Proxy:    \x1b[2mnot configured (vault-only)\x1b[0m`);
      }
    } catch (e: any) {
      console.error(`Failed to store credential: ${e.message}`);
      process.exit(1);
    }
  });

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}
