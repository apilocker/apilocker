import { Command } from 'commander';
import { apiRequest } from '../api';

/**
 * `apilocker rename <old-alias> <new-alias>` — rename a credential in
 * the vault. Updates the alias; the encrypted value and all other
 * metadata stay the same. Scoped tokens referencing the key keep
 * working because they reference by key ID, not by name.
 *
 * ⚠ Important: if any .apilockerrc files reference the old alias,
 * they silently break after the rename. This command warns about
 * that explicitly.
 */

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
}

export const renameCommand = new Command('rename')
  .description('Rename a credential in the vault (alias only; value and metadata unchanged)')
  .argument('<oldAlias>', 'The current credential alias')
  .argument('<newAlias>', 'The new credential alias')
  .action(async (oldAlias: string, newAlias: string) => {
    // Look up the key by current name
    let listRes: { keys: KeyListItem[] };
    try {
      listRes = await apiRequest<{ keys: KeyListItem[] }>('/v1/keys');
    } catch (e: any) {
      console.error(`Failed to look up key: ${e.message}`);
      process.exit(1);
    }

    const match = listRes.keys.find((k) => k.name === oldAlias);
    if (!match) {
      console.error(`Credential not found: ${oldAlias}`);
      console.error("Run 'apilocker list' to see what's in your vault.");
      process.exit(1);
    }

    if (oldAlias === newAlias) {
      console.log(`${oldAlias} → ${newAlias}: unchanged.`);
      return;
    }

    // Collision check (client-side, for a nicer error — server checks again)
    if (listRes.keys.some((k) => k.name === newAlias)) {
      console.error(`A credential named "${newAlias}" already exists in your vault.`);
      process.exit(1);
    }

    try {
      await apiRequest<{ id: string; name: string; previous_name: string }>(
        `/v1/keys/${encodeURIComponent(match.id)}/rename`,
        {
          method: 'POST',
          body: JSON.stringify({ new_name: newAlias }),
        }
      );
    } catch (e: any) {
      console.error(`Rename failed: ${e.message}`);
      process.exit(1);
    }

    console.log('');
    console.log(`\x1b[32m✓\x1b[0m Renamed: \x1b[2m${oldAlias}\x1b[0m → \x1b[1m${newAlias}\x1b[0m`);
    console.log('');
    console.log(`\x1b[36mℹ\x1b[0m  Nothing breaks. Any existing .apilockerrc files or app code that`);
    console.log(`    reference "${oldAlias}" keep working — API Locker remembers the old`);
    console.log(`    alias and transparently resolves it to "${newAlias}".`);
    console.log('');
    console.log(`    You'll see a gentle reminder next time you run \x1b[1mapilocker run\x1b[0m`);
    console.log(`    in a project that still uses the old alias. Update at your pace.`);
    console.log('');
  });
