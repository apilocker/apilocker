/**
 * `apilocker oauth` — manage OAuth 2.1 grants from the CLI.
 *
 * New in v1.0.3. Parity with the dashboard's "Connected MCP clients"
 * panel and the MCP server's implicit grant management surface.
 *
 * Subcommands:
 *   apilocker oauth grants list
 *   apilocker oauth grants revoke <id>
 *
 * Each "grant" corresponds to one (client, refresh_token_family_id)
 * pair: a single authorization the user approved via the consent
 * screen, regardless of how many refresh rotations have happened
 * since. Revoking kills the entire family in one shot.
 */

import { Command } from 'commander';
import * as readline from 'readline';
import { apiRequest } from '../api';

interface OAuthGrant {
  id: string;
  client_id: string;
  client_name: string;
  logo_uri: string | null;
  client_uri: string | null;
  scopes: string[];
  authorized_at: string;
  last_active_at: string;
  rotation_count: number;
}

interface GrantsListResponse {
  grants: OAuthGrant[];
}

export const oauthCommand = new Command('oauth').description(
  'Manage OAuth 2.1 grants — remote MCP clients that can access your vault'
);

// ---- Top-level: `apilocker oauth grants ...` ----

const grantsCommand = oauthCommand
  .command('grants')
  .description('Manage active OAuth grants (connected MCP clients)');

grantsCommand
  .command('list')
  .description('List every remote MCP client currently connected to your vault')
  .action(async () => {
    try {
      const res = await apiRequest<GrantsListResponse>('/v1/oauth/grants');
      if (res.grants.length === 0) {
        console.log('No remote MCP clients connected to your vault.');
        console.log('');
        console.log("  When you approve an MCP client via the OAuth consent");
        console.log("  screen (e.g. Claude on claude.ai clicking 'Add");
        console.log("  connector'), it'll show up here. Manage grants at");
        console.log('  https://www.apilocker.app/dashboard#mcp');
        return;
      }

      const rows = res.grants.map((g) => ({
        id: shortId(g.id),
        client: g.client_name,
        scopes: g.scopes.join(' '),
        authorized: friendlyTime(g.authorized_at),
        active: friendlyTime(g.last_active_at),
        rotations: String(g.rotation_count),
      }));

      printTable(
        ['ID', 'CLIENT', 'SCOPES', 'AUTHORIZED', 'LAST ACTIVE', 'ROTATIONS'],
        rows.map((r) => [r.id, r.client, r.scopes, r.authorized, r.active, r.rotations])
      );

      console.log('');
      console.log('Tip: `apilocker oauth grants revoke <id>` kills an entire grant family.');
    } catch (e: any) {
      console.error(`Failed to list grants: ${e.message}`);
      process.exit(1);
    }
  });

grantsCommand
  .command('revoke <id>')
  .description('Revoke an OAuth grant by ID. Kills access + refresh tokens in the whole family.')
  .option('--yes', 'Skip confirmation prompt')
  .action(async (grantId: string, opts: { yes?: boolean }) => {
    try {
      // Look up the grant so we can confirm before revoking
      const list = await apiRequest<GrantsListResponse>('/v1/oauth/grants');
      const match = list.grants.find(
        (g) => g.id === grantId || shortId(g.id) === grantId
      );
      if (!match) {
        console.error(`Grant not found: ${grantId}`);
        console.error("Run 'apilocker oauth grants list' to see active grants.");
        process.exit(1);
      }

      if (!opts.yes) {
        console.log(`About to revoke: \x1b[1m${match.client_name}\x1b[0m`);
        console.log(`  Scopes:       ${match.scopes.join(' ')}`);
        console.log(`  Authorized:   ${friendlyTime(match.authorized_at)}`);
        console.log(`  Last active:  ${friendlyTime(match.last_active_at)}`);
        console.log('');
        console.log('  This invalidates every access token AND every refresh token in the grant family.');
        console.log('  The client must go through the consent screen again to reconnect.');
        console.log('');
        const confirmed = await confirm('Continue? [y/N] ');
        if (!confirmed) {
          console.log('Cancelled.');
          return;
        }
      }

      const result = await apiRequest<{ revoked: boolean; tokens_revoked: number }>(
        `/v1/oauth/grants/${encodeURIComponent(match.id)}/revoke`,
        { method: 'POST' }
      );

      console.log(`\x1b[32m✓\x1b[0m Revoked grant for ${match.client_name}`);
      console.log(`  ${result.tokens_revoked} token(s) invalidated in one statement.`);
    } catch (e: any) {
      console.error(`Failed to revoke grant: ${e.message}`);
      process.exit(1);
    }
  });

// ---- Helpers ----

/**
 * OAuth grant IDs are UUIDs (the refresh_token_family_id column).
 * Show the first 8 hex chars for a compact table display. Users can
 * pass either the short or full form to `revoke`.
 */
function shortId(id: string): string {
  return id.slice(0, 8);
}

function friendlyTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffSec = Math.floor((Date.now() - then) / 1000);
  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] || '').length))
  );
  const line = (cols: string[]) =>
    cols.map((c, i) => (c || '').padEnd(widths[i])).join('  ');
  console.log(line(headers));
  console.log(widths.map((w) => '─'.repeat(w)).join('  '));
  for (const row of rows) {
    console.log(line(row));
  }
}

function confirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((res) => {
    rl.question(question, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      res(normalized === 'y' || normalized === 'yes');
    });
  });
}
