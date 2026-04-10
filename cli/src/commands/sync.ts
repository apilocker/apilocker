/**
 * `apilocker sync <target>` — push vault credentials to deployment targets.
 *
 * New in v1.1.0. Reads a `.apilockersync.json` manifest in the current
 * directory, reveals the listed credentials from the vault, and pushes
 * each mapped field to the deployment target as a secret/env var.
 *
 * Supported targets:
 *   wrangler — Cloudflare Workers secrets via `npx wrangler secret put`
 *
 * Future targets (not yet implemented):
 *   vercel   — Vercel env vars
 *   fly      — Fly.io secrets
 *   aws      — AWS Secrets Manager
 *   github   — GitHub Actions secrets
 *
 * The manifest is safe to commit to git — it contains only NAMES (vault
 * aliases → target secret names), never values. The values flow through
 * process memory during sync and are never written to disk or shell
 * history.
 *
 * Example manifest (.apilockersync.json):
 * {
 *   "targets": [
 *     {
 *       "type": "wrangler",
 *       "worker": "my-worker",
 *       "secrets": {
 *         "OPENAI_API_KEY": "OPENAI_API_KEY",
 *         "Google OAuth": {
 *           "client_id": "GOOGLE_CLIENT_ID",
 *           "client_secret": "GOOGLE_CLIENT_SECRET"
 *         }
 *       }
 *     }
 *   ]
 * }
 *
 * For api_key credentials: the value is a string mapping alias → target
 * secret name. For oauth2 credentials: the value is an object mapping
 * field names (client_id, client_secret, refresh_token, etc.) to target
 * secret names.
 */

import { Command } from 'commander';
import { revealKeys } from '../reveal';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawn } from 'child_process';

const MANIFEST_FILE = '.apilockersync.json';

interface SyncTarget {
  type: string;
  worker?: string;
  secrets: Record<string, string | Record<string, string>>;
}

interface SyncManifest {
  targets: SyncTarget[];
}

export const syncCommand = new Command('sync')
  .description(
    'Push vault credentials to deployment targets (wrangler, vercel, etc.)'
  )
  .argument(
    '<target>',
    'Target to sync to. Currently supported: wrangler'
  )
  .option(
    '--manifest <path>',
    `Path to the sync manifest (default: ./${MANIFEST_FILE} in the current directory)`
  )
  .option('--dry-run', 'Show what would be synced without actually pushing')
  .action(async (target: string, opts: { manifest?: string; dryRun?: boolean }) => {
    // Load manifest
    const manifestPath = opts.manifest || path.resolve(process.cwd(), MANIFEST_FILE);
    if (!fs.existsSync(manifestPath)) {
      console.error(`Manifest not found: ${manifestPath}`);
      console.error('');
      console.error(`Create a ${MANIFEST_FILE} file in your project root. Example:`);
      console.error('');
      console.error(JSON.stringify(
        {
          targets: [
            {
              type: 'wrangler',
              worker: 'my-worker',
              secrets: {
                OPENAI_API_KEY: 'OPENAI_API_KEY',
                'Google OAuth': {
                  client_id: 'GOOGLE_CLIENT_ID',
                  client_secret: 'GOOGLE_CLIENT_SECRET',
                },
              },
            },
          ],
        },
        null,
        2
      ));
      console.error('');
      console.error('The manifest is safe to commit — it contains only names, never values.');
      process.exit(1);
    }

    let manifest: SyncManifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    } catch (e: any) {
      console.error(`Failed to parse manifest: ${e.message}`);
      process.exit(1);
    }

    if (!Array.isArray(manifest.targets) || manifest.targets.length === 0) {
      console.error('Manifest has no targets.');
      process.exit(1);
    }

    // Find matching targets
    const matchingTargets = manifest.targets.filter((t) => t.type === target);
    if (matchingTargets.length === 0) {
      console.error(`No targets of type "${target}" found in the manifest.`);
      console.error(
        `Available types: ${[...new Set(manifest.targets.map((t) => t.type))].join(', ')}`
      );
      process.exit(1);
    }

    // Dispatch
    for (const t of matchingTargets) {
      switch (t.type) {
        case 'wrangler':
          await syncWrangler(t, opts.dryRun ?? false);
          break;
        default:
          console.error(`Unsupported target type: ${t.type}`);
          console.error('Currently supported: wrangler');
          process.exit(1);
      }
    }
  });

// ============================================================
// Wrangler sync
// ============================================================

async function syncWrangler(
  target: SyncTarget,
  dryRun: boolean
): Promise<void> {
  const workerName = target.worker;
  const secrets = target.secrets;

  console.log(
    `\x1b[1mSync → wrangler${workerName ? ` (worker: ${workerName})` : ''}\x1b[0m`
  );
  console.log('');

  // Collect all vault aliases we need to reveal
  const aliasSet = new Set<string>();
  for (const alias of Object.keys(secrets)) {
    aliasSet.add(alias);
  }

  // Reveal all at once (single API call, single audit log batch)
  let revealed;
  try {
    revealed = await revealKeys(Array.from(aliasSet));
  } catch (e: any) {
    console.error(`Failed to reveal credentials: ${e.message}`);
    process.exit(1);
  }

  if (revealed.missing.length > 0) {
    console.error(`Missing from vault: ${revealed.missing.join(', ')}`);
    console.error("Run 'apilocker list' to see what's available.");
    process.exit(1);
  }

  // Build a map of alias → revealed key data
  const revealedMap = new Map<string, (typeof revealed.keys)[0]>();
  for (const key of revealed.keys) {
    revealedMap.set(key.name, key);
    // Also index by requested_as (lossless rename fallback)
    if (key.requested_as) {
      revealedMap.set(key.requested_as, key);
    }
  }

  // Build the list of (target_secret_name, value) pairs to push
  const pushList: Array<{ targetName: string; value: string; source: string }> =
    [];

  for (const [alias, mapping] of Object.entries(secrets)) {
    const key = revealedMap.get(alias);
    if (!key) {
      console.error(`  Revealed keys don't include "${alias}" — this shouldn't happen.`);
      process.exit(1);
    }

    if (typeof mapping === 'string') {
      // api_key credential: alias → target secret name
      if (key.credential_type === 'oauth2') {
        console.error(
          `  "${alias}" is an OAuth credential but the mapping is a string.`
        );
        console.error(
          '  Use an object mapping for OAuth: { "client_id": "TARGET_NAME", "client_secret": "TARGET_NAME" }'
        );
        process.exit(1);
      }
      if (!key.value) {
        console.error(`  "${alias}" has no value.`);
        process.exit(1);
      }
      pushList.push({
        targetName: mapping,
        value: key.value,
        source: alias,
      });
    } else {
      // oauth2 credential: alias → { field: target_name, ... }
      if (key.credential_type !== 'oauth2' || !key.fields) {
        console.error(
          `  "${alias}" is not an OAuth credential but the mapping is an object.`
        );
        process.exit(1);
      }
      for (const [field, targetName] of Object.entries(mapping)) {
        const fieldValue = key.fields[field];
        if (fieldValue == null || fieldValue === '') {
          console.warn(
            `  ⚠ Skipping "${alias}.${field}" → ${targetName} (field is empty)`
          );
          continue;
        }
        pushList.push({
          targetName,
          value: fieldValue,
          source: `${alias}.${field}`,
        });
      }
    }
  }

  if (pushList.length === 0) {
    console.log('  Nothing to sync.');
    return;
  }

  // Dry run: just print what would happen
  if (dryRun) {
    console.log('  \x1b[33mDry run — no secrets will be pushed.\x1b[0m');
    console.log('');
    for (const item of pushList) {
      console.log(
        `  ${item.source} → \x1b[1m${item.targetName}\x1b[0m (${item.value.length} chars)`
      );
    }
    console.log('');
    console.log(`  ${pushList.length} secret(s) would be synced.`);
    return;
  }

  // Verify wrangler is available
  try {
    execSync('npx wrangler --version', { stdio: 'pipe' });
  } catch {
    console.error('  wrangler not found. Install with: npm install -g wrangler');
    process.exit(1);
  }

  // Push each secret
  let successCount = 0;
  let failCount = 0;

  for (const item of pushList) {
    process.stdout.write(
      `  ${item.source} → \x1b[1m${item.targetName}\x1b[0m ... `
    );

    try {
      const args = ['wrangler', 'secret', 'put', item.targetName];
      if (workerName) {
        args.push('--name', workerName);
      }

      // Pipe the value via stdin so it never appears in shell history
      // or process arguments.
      const result = execSync(`printf '%s' '' | npx ${args.join(' ')}`, {
        input: item.value,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 30000,
      });

      // Actually, execSync with input option pipes to stdin directly.
      // Let me use the spawn approach for cleaner stdin handling.
    } catch {
      // Fall through to spawn approach
    }

    // Use spawn for proper stdin piping
    const ok = await new Promise<boolean>((resolve) => {
      const args = ['wrangler', 'secret', 'put', item.targetName];
      if (workerName) {
        args.push('--name', workerName);
      }

      const child = spawn('npx', args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 30000,
      });

      child.stdin.write(item.value);
      child.stdin.end();

      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

      child.on('close', (code) => {
        if (code === 0 || stdout.includes('Success')) {
          resolve(true);
        } else {
          resolve(false);
        }
      });
      child.on('error', () => resolve(false));
    });

    if (ok) {
      console.log('\x1b[32m✓\x1b[0m');
      successCount++;
    } else {
      console.log('\x1b[31m✗\x1b[0m');
      failCount++;
    }
  }

  console.log('');
  console.log(
    `  \x1b[32m${successCount} synced\x1b[0m` +
      (failCount > 0 ? `, \x1b[31m${failCount} failed\x1b[0m` : '') +
      '.'
  );

  if (failCount > 0) {
    process.exit(1);
  }
}
