import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { apiRequest } from '../api';
import { writeRcFile, RC_FILENAME } from '../rcfile';

/**
 * `apilocker init` — bootstrap a project-level .apilockerrc file.
 *
 * Walks the user through selecting which vault keys this project should
 * use, then writes a .apilockerrc in the current directory. After this,
 * `apilocker run -- <cmd>` and `apilocker env` in this directory
 * auto-use the selected keys.
 *
 * Design constraint: zero new dependencies. We render a simple numbered
 * picker using readline, not a TUI library.
 */

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
}

interface KeyListResponse {
  keys: KeyListItem[];
}

export const initCommand = new Command('init')
  .description('Create a .apilockerrc in this directory to pin vault keys to the project')
  .option('--keys <aliases>', 'Comma-separated aliases (skip interactive picker)')
  .option('--force', 'Overwrite an existing .apilockerrc without prompting')
  .action(async (opts) => {
    const rcPath = path.join(process.cwd(), RC_FILENAME);

    // Guard: existing file
    if (fs.existsSync(rcPath) && !opts.force) {
      const overwrite = await askYesNo(
        `A ${RC_FILENAME} already exists here. Overwrite? [y/N] `
      );
      if (!overwrite) {
        console.log('Cancelled.');
        return;
      }
    }

    // Resolve the key list
    let selectedAliases: string[];
    if (opts.keys) {
      selectedAliases = String(opts.keys)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else {
      // Interactive mode: fetch the user's vault and let them pick
      let listResponse: KeyListResponse;
      try {
        listResponse = await apiRequest<KeyListResponse>('/v1/keys');
      } catch (e: any) {
        console.error(`Failed to fetch your vault: ${e.message}`);
        process.exit(1);
      }

      const keys = listResponse.keys || [];
      if (keys.length === 0) {
        console.log('Your vault is empty. Store some keys first:');
        console.log('  apilocker store <name> <value> --provider <provider>');
        console.log('');
        console.log("Then run 'apilocker init' again.");
        return;
      }

      selectedAliases = await runInteractivePicker(keys);
      if (selectedAliases.length === 0) {
        console.log('No keys selected. Cancelled.');
        return;
      }
    }

    writeRcFile(rcPath, selectedAliases);

    // Also add to .gitignore? No — the file is safe to commit by design.
    // But offer to add it if there's no .gitignore touching it already.
    console.log('');
    console.log(`\x1b[32m✓\x1b[0m Wrote ${RC_FILENAME} with ${selectedAliases.length} key${selectedAliases.length === 1 ? '' : 's'}:`);
    for (const k of selectedAliases) {
      console.log(`    - ${k}`);
    }
    console.log('');
    console.log('This file is safe to commit to git — it contains only pointers, not secrets.');
    console.log('');
    console.log('Next:');
    console.log('  apilocker run -- <your command>');
    console.log('');
  });

/**
 * Render a numbered list of the user's keys and let them select by
 * typing comma-separated numbers (or ranges like "1-3") or "all".
 */
async function runInteractivePicker(keys: KeyListItem[]): Promise<string[]> {
  console.log('');
  console.log('Your vault:');
  console.log('');
  const pad = String(keys.length).length;
  keys.forEach((k, i) => {
    const num = String(i + 1).padStart(pad, ' ');
    const provider = k.provider ? `\x1b[2m${k.provider}\x1b[0m` : '';
    console.log(`  ${num}. ${k.name}  ${provider}`);
  });
  console.log('');
  console.log('Select which keys to pin to this project.');
  console.log('Enter numbers separated by commas or ranges (e.g. 1,3,5-7), or "all", or "none":');
  console.log('');

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer: string = await new Promise((resolve) =>
    rl.question('> ', (a) => {
      rl.close();
      resolve(a.trim());
    })
  );

  if (!answer || answer.toLowerCase() === 'none') return [];
  if (answer.toLowerCase() === 'all') return keys.map((k) => k.name);

  const indices = parseSelection(answer, keys.length);
  return indices.map((i) => keys[i].name);
}

/**
 * Parse a selection string like "1,3,5-7" into a set of zero-based
 * indices, clamped to [0, max). Invalid tokens are silently ignored.
 */
function parseSelection(input: string, max: number): number[] {
  const set = new Set<number>();
  for (const tokenRaw of input.split(',')) {
    const token = tokenRaw.trim();
    if (!token) continue;

    const rangeMatch = token.match(/^(\d+)\s*-\s*(\d+)$/);
    if (rangeMatch) {
      const start = parseInt(rangeMatch[1], 10);
      const end = parseInt(rangeMatch[2], 10);
      if (Number.isInteger(start) && Number.isInteger(end) && start <= end) {
        for (let i = start; i <= end; i++) {
          const idx = i - 1;
          if (idx >= 0 && idx < max) set.add(idx);
        }
      }
      continue;
    }

    const num = parseInt(token, 10);
    if (Number.isInteger(num)) {
      const idx = num - 1;
      if (idx >= 0 && idx < max) set.add(idx);
    }
  }
  return Array.from(set).sort((a, b) => a - b);
}

function askYesNo(prompt: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === 'y' || normalized === 'yes');
    });
  });
}
