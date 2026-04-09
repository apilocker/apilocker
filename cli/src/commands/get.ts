import { Command } from 'commander';
import { revealKeys, getDeprecationNudges } from '../reveal';

/**
 * `apilocker get <alias> [--field <name>]` — print a credential value
 * to stdout, for scripting.
 *
 * For api_key credentials:
 *   apilocker get openai
 *   # → prints the raw secret to stdout, no trailing newline
 *
 * For oauth2 credentials:
 *   apilocker get google-oauth
 *   # → prints JSON: {"client_id":"...", "client_secret":"...", ...}
 *
 *   apilocker get google-oauth --field client_secret
 *   # → prints just the client_secret as a raw string
 *
 * `--field` is valid for both credential types but only meaningful for
 * oauth2. For api_key credentials, `--field` is silently ignored (the
 * value is always the single secret).
 *
 * Security note: putting a secret into a shell variable via $(...)
 * lands it in the shell's variable table. It won't usually appear in
 * history unless the user echoes it — but `apilocker run` is strictly
 * safer for interactive use.
 */

export const getCommand = new Command('get')
  .description('Print a credential value to stdout (for scripting)')
  .argument('<alias>', 'The credential alias to retrieve')
  .option('--field <name>', 'For OAuth credentials, print just this field (e.g. client_secret)')
  .action(async (alias: string, opts: { field?: string }) => {
    let result;
    try {
      result = await revealKeys([alias]);
    } catch (e: any) {
      console.error(`Failed to fetch credential: ${e.message}`);
      process.exit(1);
    }

    if (result.missing.length > 0 || result.keys.length === 0) {
      console.error(`Credential not found: ${alias}`);
      console.error("Run 'apilocker list' to see what's available.");
      process.exit(1);
    }

    // Lossless-rename nudge on stderr — stdout is the raw secret.
    for (const msg of getDeprecationNudges(result)) {
      process.stderr.write(`# ℹ ${msg}\n`);
    }

    const key = result.keys[0];

    if (key.credential_type === 'oauth2') {
      if (opts.field) {
        const value = key.fields?.[opts.field];
        if (value == null) {
          console.error(`Field not found: ${opts.field}`);
          console.error(`Available fields: ${Object.keys(key.fields || {}).join(', ')}`);
          process.exit(1);
        }
        process.stdout.write(value);
        return;
      }
      // No --field: emit the whole credential as JSON
      process.stdout.write(JSON.stringify(key.fields || {}, null, 2));
      return;
    }

    // api_key credential
    if (key.value == null) {
      console.error('Credential has no value');
      process.exit(1);
    }
    process.stdout.write(key.value);
  });
