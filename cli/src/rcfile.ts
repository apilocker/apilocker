/**
 * .apilockerrc support.
 *
 * A project-local config file that pins a list of key aliases to the
 * current working directory. Committed to git — the file contains only
 * aliases (pointers), never secrets. Team members each have their own
 * vault with their own keys at the same aliases.
 *
 * Format (YAML-subset, intentionally minimal):
 *
 *     keys:
 *       - openai
 *       - anthropic
 *       - stripe-secret
 *
 * Or a flat text form (also accepted) where each non-comment, non-blank
 * line is treated as a single alias:
 *
 *     openai
 *     anthropic
 *     # stripe is disabled for now
 *     stripe-secret
 *
 * We deliberately do NOT depend on a YAML parser. The parser here is ~30
 * lines of hand-rolled code that handles both forms.
 */

import * as fs from 'fs';
import * as path from 'path';

export const RC_FILENAME = '.apilockerrc';

export interface RcFile {
  keys: string[];
  /** Absolute path where the file was found, or null if none. */
  path: string | null;
}

/**
 * Walk up from `startDir` looking for a .apilockerrc. Stops at the user's
 * home directory or the filesystem root, whichever comes first.
 */
export function findRcFile(startDir: string = process.cwd()): string | null {
  const homedir = process.env.HOME || process.env.USERPROFILE || '';
  let current = path.resolve(startDir);
  while (true) {
    const candidate = path.join(current, RC_FILENAME);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) return null; // filesystem root
    if (homedir && current === homedir) return null; // don't cross home
    current = parent;
  }
}

/**
 * Load the nearest .apilockerrc, parse it, and return its key list.
 * Returns `{ keys: [], path: null }` if no rc file is found.
 */
export function loadRcFile(startDir: string = process.cwd()): RcFile {
  const filePath = findRcFile(startDir);
  if (!filePath) return { keys: [], path: null };

  const raw = fs.readFileSync(filePath, 'utf-8');
  return { keys: parseRc(raw), path: filePath };
}

/**
 * Parse the contents of a .apilockerrc file. Accepts two formats:
 *   1. YAML subset:
 *        keys:
 *          - alias1
 *          - alias2
 *   2. Flat text (one alias per line, # for comments)
 *
 * Both are permissive — leading/trailing whitespace and comments are
 * stripped, blank lines are skipped.
 */
export function parseRc(raw: string): string[] {
  const lines = raw.split(/\r?\n/);
  const keys: string[] = [];

  // Detect YAML subset (lines starting with "keys:" or "- ")
  const isYaml = lines.some((l) => /^\s*keys\s*:/.test(l)) ||
    lines.some((l) => /^\s*-\s+\S/.test(l));

  for (let rawLine of lines) {
    // Strip comments starting with #
    const commentIdx = rawLine.indexOf('#');
    if (commentIdx !== -1) rawLine = rawLine.slice(0, commentIdx);

    const line = rawLine.trim();
    if (!line) continue;

    if (isYaml) {
      // In YAML mode, only accept dash-prefixed items
      const match = line.match(/^-\s+(.+)$/);
      if (match) {
        const value = match[1].trim().replace(/^["']|["']$/g, '');
        if (value) keys.push(value);
      }
      // Ignore the "keys:" header and any other lines
      continue;
    }

    // Flat text: every non-blank line is an alias
    keys.push(line);
  }

  // Deduplicate while preserving order
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const k of keys) {
    if (!seen.has(k)) {
      seen.add(k);
      unique.push(k);
    }
  }
  return unique;
}

/**
 * Write a .apilockerrc file with the given keys in YAML format, with a
 * friendly header comment explaining what it does.
 */
export function writeRcFile(filePath: string, keys: string[]): void {
  const content =
    `# API Locker project config — https://www.apilocker.app\n` +
    `#\n` +
    `# This file pins the vault key aliases this project uses. Safe to commit\n` +
    `# to git — it contains only pointers, never the secrets themselves.\n` +
    `# Anyone with 'apilocker run -- <cmd>' in this directory will get these\n` +
    `# keys injected as environment variables for the duration of the command.\n` +
    `#\n` +
    `keys:\n` +
    keys.map((k) => `  - ${k}`).join('\n') +
    '\n';
  fs.writeFileSync(filePath, content);
}
