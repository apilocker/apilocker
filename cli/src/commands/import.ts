import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { apiRequest } from '../api';
import { parseEnvFile, detectProvider, ParsedEntry } from '../envparser';
import { writeRcFile, RC_FILENAME } from '../rcfile';

/**
 * `apilocker import [file]` — migrate an existing .env file into the vault.
 *
 * Flow:
 *   1. Parse the .env file
 *   2. Show a preview table (variable name → provider → collision status)
 *   3. Ask for confirmation (unless --yes)
 *   4. For each entry, POST /v1/keys with provider auto-detected from the
 *      variable name. On collision, prompt: overwrite / skip / rename.
 *   5. On success, offer to:
 *      - Delete the .env file
 *      - Write a .apilockerrc pointing at the imported aliases
 *   6. Print next-step hint: `apilocker run -- <your command>`
 */

interface ListedKey {
  id: string;
  name: string;
  provider: string;
}

export const importCommand = new Command('import')
  .description('Import credentials from an existing .env file into the vault')
  .argument('[file]', 'Path to the .env file to import', '.env')
  .option('--yes', 'Skip all confirmation prompts (non-interactive)')
  .option('--tag <tag>', 'Tag to apply to all imported keys (repeatable)', collect, [])
  .action(async (filePath: string, opts: { yes?: boolean; tag?: string[] }) => {
    // Resolve + read the file
    const absPath = path.resolve(filePath);
    if (!fs.existsSync(absPath)) {
      console.error(`File not found: ${absPath}`);
      console.error('');
      console.error('Usage: apilocker import [file]');
      console.error('  apilocker import           # defaults to ./.env');
      console.error('  apilocker import .env.prod');
      process.exit(1);
    }

    let source: string;
    try {
      source = fs.readFileSync(absPath, 'utf-8');
    } catch (e: any) {
      console.error(`Failed to read ${absPath}: ${e.message}`);
      process.exit(1);
    }

    // Parse
    const { entries, warnings } = parseEnvFile(source);
    if (entries.length === 0) {
      console.log(`No environment variables found in ${absPath}.`);
      return;
    }

    // Fetch existing keys to detect collisions
    let existing: ListedKey[] = [];
    try {
      const res = await apiRequest<{ keys: ListedKey[] }>('/v1/keys');
      existing = res.keys || [];
    } catch (e: any) {
      console.error(`Failed to fetch existing vault: ${e.message}`);
      process.exit(1);
    }
    const existingNames = new Set(existing.map((k) => k.name));

    // Build the preview
    const rows = entries.map((entry) => ({
      key: entry.key,
      provider: detectProvider(entry.key),
      collision: existingNames.has(entry.key),
    }));

    // Print warnings from the parser
    if (warnings.length > 0) {
      console.log('');
      console.log('\x1b[33mParser warnings:\x1b[0m');
      for (const w of warnings) {
        console.log(`  line ${w.line_number}: ${w.message}`);
      }
    }

    // Print the preview table
    console.log('');
    console.log(`Found \x1b[1m${entries.length}\x1b[0m secret${entries.length === 1 ? '' : 's'} in ${path.relative(process.cwd(), absPath) || absPath}:`);
    console.log('');
    const widthKey = Math.max('NAME'.length, ...rows.map((r) => r.key.length));
    const widthProv = Math.max('PROVIDER'.length, ...rows.map((r) => r.provider.length));
    const header = `  ${'NAME'.padEnd(widthKey)}  ${'PROVIDER'.padEnd(widthProv)}  STATUS`;
    console.log(header);
    console.log('  ' + '-'.repeat(widthKey + widthProv + 12));
    for (const row of rows) {
      const status = row.collision
        ? '\x1b[33mexists (will prompt)\x1b[0m'
        : '\x1b[32mnew\x1b[0m';
      console.log(`  ${row.key.padEnd(widthKey)}  ${row.provider.padEnd(widthProv)}  ${status}`);
    }
    console.log('');

    if (opts.tag && opts.tag.length > 0) {
      console.log(`Tags to apply: ${opts.tag.join(', ')}`);
      console.log('');
    }

    // Confirm
    if (!opts.yes) {
      const ok = await confirm('Import these secrets into your vault? [y/N] ');
      if (!ok) {
        console.log('Cancelled.');
        return;
      }
    }

    // Import each entry
    const imported: string[] = [];
    const skipped: string[] = [];

    for (const entry of entries) {
      const provider = detectProvider(entry.key);
      let targetName = entry.key;
      let shouldStore = true;

      if (existingNames.has(entry.key) && !opts.yes) {
        const choice = await askCollisionChoice(entry.key);
        if (choice === 'skip') {
          skipped.push(entry.key);
          continue;
        }
        if (choice === 'overwrite') {
          // Delete the old one, then store the new one under the same name
          const oldKey = existing.find((k) => k.name === entry.key);
          if (oldKey) {
            try {
              await apiRequest(`/v1/keys/${oldKey.id}`, { method: 'DELETE' });
            } catch (e: any) {
              console.error(`  \x1b[31m✗\x1b[0m ${entry.key}: failed to overwrite — ${e.message}`);
              skipped.push(entry.key);
              continue;
            }
          }
        }
        if (choice === 'rename') {
          const newName = await ask(`  → New name for ${entry.key}: `);
          if (!newName) {
            skipped.push(entry.key);
            continue;
          }
          targetName = newName.trim();
        }
      } else if (existingNames.has(entry.key) && opts.yes) {
        // Non-interactive mode: default to SKIP on collision to be safe
        skipped.push(entry.key);
        continue;
      }

      try {
        await storeOne(entry, targetName, provider, opts.tag || []);
        imported.push(targetName);
        console.log(`  \x1b[32m✓\x1b[0m ${targetName}  (${provider})`);
      } catch (e: any) {
        console.error(`  \x1b[31m✗\x1b[0m ${targetName}: ${e.message}`);
        skipped.push(targetName);
      }
    }

    // Summary
    console.log('');
    console.log(`Imported \x1b[1m${imported.length}\x1b[0m / ${entries.length} secret${entries.length === 1 ? '' : 's'}.`);
    if (skipped.length > 0) {
      console.log(`Skipped: ${skipped.join(', ')}`);
    }

    if (imported.length === 0) {
      return;
    }

    // Offer to delete the .env and write a .apilockerrc
    console.log('');
    const rcPath = path.join(path.dirname(absPath), RC_FILENAME);
    const replaceEnv = opts.yes
      ? false
      : await confirm(
          `Delete ${path.basename(absPath)} and replace with ${RC_FILENAME}? [y/N] `
        );

    if (replaceEnv) {
      try {
        writeRcFile(rcPath, imported);
        fs.unlinkSync(absPath);
        console.log(`  \x1b[32m✓\x1b[0m Wrote ${RC_FILENAME}`);
        console.log(`  \x1b[32m✓\x1b[0m Deleted ${path.basename(absPath)}`);
      } catch (e: any) {
        console.error(`Failed to replace: ${e.message}`);
      }
    }

    console.log('');
    console.log('Next: apilocker run -- <your command>');
    console.log('');
  });

async function storeOne(
  entry: ParsedEntry,
  name: string,
  provider: string,
  tags: string[]
): Promise<void> {
  const body: any = {
    name,
    provider,
    key: entry.value,
  };
  if (tags.length > 0) {
    body.tags = tags;
  }
  // Custom provider needs a base_url — use a placeholder that makes it
  // clear this was imported and not proxy-configured.
  if (provider === 'custom') {
    body.base_url = 'https://example.invalid';
    body.auth_header_type = 'bearer';
  }
  await apiRequest('/v1/keys', { method: 'POST', body: JSON.stringify(body) });
}

function ask(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function confirm(prompt: string): Promise<boolean> {
  const answer = await ask(prompt);
  const normalized = answer.trim().toLowerCase();
  return normalized === 'y' || normalized === 'yes';
}

async function askCollisionChoice(
  existingName: string
): Promise<'overwrite' | 'skip' | 'rename'> {
  console.log('');
  console.log(`  \x1b[33m${existingName}\x1b[0m already exists in your vault.`);
  console.log(`    [o] overwrite the existing key`);
  console.log(`    [s] skip this import`);
  console.log(`    [r] rename and import as a new key`);
  const answer = (await ask('  > ')).trim().toLowerCase();
  if (answer === 'o' || answer === 'overwrite') return 'overwrite';
  if (answer === 'r' || answer === 'rename') return 'rename';
  return 'skip';
}

// Commander collector for repeatable flags
function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}
