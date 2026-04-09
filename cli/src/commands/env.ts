import { Command } from 'commander';
import { revealKeys, flattenToEnv, getDeprecationNudges } from '../reveal';
import { loadRcFile } from '../rcfile';

/**
 * `apilocker env [--keys <aliases>]` — emit shell-eval-able export lines.
 *
 * Usage:
 *   eval "$(apilocker env)"
 *   eval "$(apilocker env --keys openai,stripe)"
 *
 * After running, your CURRENT shell has the listed secrets available as
 * environment variables. This is useful for interactive debugging in a
 * REPL — but note that `apilocker run -- <cmd>` is strictly safer for
 * running a single command, since env-injected vars persist in your
 * shell until you close it.
 *
 * Key source precedence (same as `apilocker run`):
 *   1. --keys flag
 *   2. .apilockerrc (walks up from CWD)
 *   3. Error
 *
 * Output format: one `export NAME='value'` per line. Single quotes are
 * used because they disable shell interpretation of $, backticks, etc.
 * Any literal single quotes in the value are escaped via the POSIX
 * concatenation trick: ' → '\''
 */

export const envCommand = new Command('env')
  .description('Emit shell-eval-able export statements for the given keys')
  .option('--keys <aliases>', 'Comma-separated list of key aliases (overrides .apilockerrc)')
  .option('--format <shell>', 'Output format: sh (default), fish, powershell', 'sh')
  .action(async (opts) => {
    // Resolve aliases from flag or .apilockerrc
    let aliases: string[];
    if (opts.keys) {
      aliases = String(opts.keys)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else {
      const rc = loadRcFile();
      if (!rc.path) {
        console.error("No --keys specified and no .apilockerrc found in this directory or any parent.");
        console.error("Run 'apilocker init' to create one, or pass --keys explicitly.");
        process.exit(1);
      }
      aliases = rc.keys;
      if (aliases.length === 0) {
        console.error(`The .apilockerrc at ${rc.path} is empty.`);
        process.exit(1);
      }
    }

    let result;
    try {
      result = await revealKeys(aliases);
    } catch (e: any) {
      console.error(`Failed to fetch secrets: ${e.message}`);
      process.exit(1);
    }

    if (result.missing.length > 0) {
      console.error(`Missing keys in vault: ${result.missing.join(', ')}`);
      process.exit(1);
    }

    // Lossless-rename nudges on stderr — stdout is used for shell eval
    // so nothing non-exportable can go there.
    const nudges = getDeprecationNudges(result);
    for (const msg of nudges) {
      process.stderr.write(`# ℹ ${msg}\n`);
    }

    // Flatten both api_key and oauth2 credentials into a single env var
    // map, then emit one export line per entry in the requested format.
    const format = String(opts.format || 'sh').toLowerCase();
    const flat = flattenToEnv(result);
    for (const [envName, value] of Object.entries(flat)) {
      process.stdout.write(formatExport(format, envName, value) + '\n');
    }
  });

function formatExport(format: string, name: string, value: string): string {
  switch (format) {
    case 'fish':
      // fish: set -gx NAME 'value'  (escape ' by splitting the string)
      return `set -gx ${name} '${escapeSingleQuoted(value)}'`;
    case 'powershell':
    case 'ps':
    case 'pwsh':
      // PowerShell: $env:NAME = 'value'
      return `$env:${name} = '${escapePowerShellSingleQuoted(value)}'`;
    case 'sh':
    case 'bash':
    case 'zsh':
    default:
      // POSIX sh: export NAME='value'
      return `export ${name}='${escapeSingleQuoted(value)}'`;
  }
}

/**
 * Escape a string for inclusion inside POSIX single-quoted context.
 * Single quotes are the only char that needs special handling: the
 * standard idiom is to close the quoted string, emit an escaped
 * single quote, and re-open. E.g. "it's" becomes "it'\''s".
 */
function escapeSingleQuoted(value: string): string {
  return value.replace(/'/g, "'\\''");
}

/**
 * PowerShell single-quoted strings escape a single quote by doubling it.
 */
function escapePowerShellSingleQuoted(value: string): string {
  return value.replace(/'/g, "''");
}
