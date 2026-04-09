import { Command } from 'commander';
import { apiRequest } from '../api';

/**
 * `apilocker pause <alias>` and `apilocker resume <alias>` — toggle
 * proxy access for a credential without deleting it.
 *
 * v1.0.0 pause semantics: blocks the proxy ONLY. Reveal / run / get /
 * env still work on paused credentials, because those are "you
 * accessing your own secret" rather than "an app calling through the
 * vault." The most likely pause scenario is "I suspect abuse, cut off
 * live traffic" — in that scenario you still want to be able to
 * rotate the key, which requires reading the old value first.
 *
 * Also exported: `resumeCommand`. Both live in this file because they
 * share most of their logic.
 */

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
  paused_at: string | null;
}

async function resolveKey(alias: string): Promise<KeyListItem> {
  let listRes: { keys: KeyListItem[] };
  try {
    listRes = await apiRequest<{ keys: KeyListItem[] }>('/v1/keys');
  } catch (e: any) {
    console.error(`Failed to look up credential: ${e.message}`);
    process.exit(1);
  }
  const match = listRes.keys.find((k) => k.name === alias);
  if (!match) {
    console.error(`Credential not found: ${alias}`);
    console.error("Run 'apilocker list' to see what's in your vault.");
    process.exit(1);
  }
  return match;
}

export const pauseCommand = new Command('pause')
  .description('Pause proxy access for a credential (reveal/run/get/env still work)')
  .argument('<alias>', 'The credential alias to pause')
  .action(async (alias: string) => {
    const key = await resolveKey(alias);

    if (key.paused_at) {
      console.log(`${alias} is already paused.`);
      return;
    }

    try {
      await apiRequest(`/v1/keys/${encodeURIComponent(key.id)}/pause`, { method: 'POST' });
    } catch (e: any) {
      console.error(`Pause failed: ${e.message}`);
      process.exit(1);
    }

    console.log('');
    console.log(`\x1b[32m✓\x1b[0m Paused: \x1b[1m${alias}\x1b[0m`);
    console.log(`  Proxy access blocked. Reveal/run/get/env still work.`);
    console.log(`  Resume with: \x1b[1mapilocker resume ${alias}\x1b[0m`);
    console.log('');
  });

export const resumeCommand = new Command('resume')
  .description('Resume proxy access for a paused credential')
  .argument('<alias>', 'The credential alias to resume')
  .action(async (alias: string) => {
    const key = await resolveKey(alias);

    if (!key.paused_at) {
      console.log(`${alias} is not paused.`);
      return;
    }

    try {
      await apiRequest(`/v1/keys/${encodeURIComponent(key.id)}/resume`, { method: 'POST' });
    } catch (e: any) {
      console.error(`Resume failed: ${e.message}`);
      process.exit(1);
    }

    console.log('');
    console.log(`\x1b[32m✓\x1b[0m Resumed: \x1b[1m${alias}\x1b[0m`);
    console.log(`  Proxy access restored.`);
    console.log('');
  });
