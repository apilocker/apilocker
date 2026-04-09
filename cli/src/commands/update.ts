import { Command } from 'commander';

/**
 * `apilocker update` — check the npm registry for a newer version of
 * the CLI and show the upgrade command.
 *
 * Intentionally does NOT run `npm install -g apilocker@latest` itself.
 * Installing global packages from within a running global package is
 * fragile (permissions, PATH, half-applied upgrades) and can leave the
 * user in a broken state. We show the exact command and let the user
 * run it when they're ready.
 *
 * The current version is compiled in via package.json at build time.
 * The "latest" version comes from an unauthenticated GET against the
 * public npm registry (no Bearer token needed — everyone can query).
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json') as { version: string };

const REGISTRY_URL = 'https://registry.npmjs.org/apilocker/latest';
const UPGRADE_COMMAND = 'npm install -g apilocker@latest';

export const updateCommand = new Command('update')
  .description('Check for a newer version of apilocker on npm')
  .action(async () => {
    const currentVersion = pkg.version;
    console.log(`  Current version: \x1b[1m${currentVersion}\x1b[0m`);
    console.log('  Checking npm registry…');

    let latest: string;
    try {
      const res = await fetch(REGISTRY_URL, {
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`registry returned HTTP ${res.status}`);
      }
      const body = (await res.json()) as { version?: string };
      if (!body.version) {
        throw new Error('registry response missing version field');
      }
      latest = body.version;
    } catch (e: any) {
      console.error(`  Could not reach the npm registry: ${e.message}`);
      console.error(`  You can always upgrade manually: ${UPGRADE_COMMAND}`);
      process.exit(1);
    }

    console.log(`  Latest version:  \x1b[1m${latest}\x1b[0m`);
    console.log('');

    const cmp = compareSemver(currentVersion, latest);
    if (cmp >= 0) {
      console.log(`  \x1b[32m✓\x1b[0m You're on the latest version. Nothing to do.`);
      return;
    }

    console.log(`  \x1b[33m→\x1b[0m A newer version is available.`);
    console.log('');
    console.log(`     Upgrade with:  \x1b[1m${UPGRADE_COMMAND}\x1b[0m`);
    console.log('');
    console.log('  Release notes: https://www.npmjs.com/package/apilocker?activeTab=versions');
  });

/**
 * Compare two semver-ish strings. Returns:
 *   > 0 if a is newer,
 *   < 0 if a is older,
 *   = 0 if equal.
 *
 * Pre-release identifiers (e.g. "0.5.0-beta.1") are not fully handled —
 * we just compare major.minor.patch numerically and treat any suffix as
 * "equal to the unsuffixed form." Good enough for our purposes; the
 * full semver package is a 15KB dep we don't need.
 */
function compareSemver(a: string, b: string): number {
  const parse = (v: string) => {
    const clean = v.replace(/^v/, '').split(/[-+]/)[0];
    return clean.split('.').map((part) => parseInt(part, 10) || 0);
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const ai = pa[i] || 0;
    const bi = pb[i] || 0;
    if (ai !== bi) return ai - bi;
  }
  return 0;
}
