import { Command } from 'commander';
import * as readline from 'readline';
import { apiRequest } from '../api';

/**
 * `apilocker rotate <alias>` — replace (part of) a credential's value.
 *
 * api_key credentials:
 *   apilocker rotate openai
 *   apilocker rotate openai --value sk-...
 *   Replaces the single encrypted secret. Name, provider, and tags stay.
 *
 * oauth2 credentials (v1.0.1+):
 *   apilocker rotate google-oauth --field client_secret
 *   apilocker rotate google-oauth --field client_secret --value GOCSPX-...
 *   apilocker rotate google-oauth --field refresh_token
 *
 *   Partial rotation: only the field you name is replaced. client_id,
 *   authorize_url, token_url, scopes, and redirect_uri are preserved.
 *   This is what you want when a client secret leaks — you rotate the
 *   compromised field without wiping the rest of the OAuth entry.
 *
 *   Valid fields: client_secret, refresh_token
 *
 * Scoped tokens that reference the rotated key continue to work in both
 * cases — they never held the raw value directly.
 */

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
  credential_type?: 'api_key' | 'oauth2';
  rotated_at: string | null;
}

const ROTATABLE_OAUTH_FIELDS = ['client_secret', 'refresh_token'] as const;
type RotatableOAuthField = (typeof ROTATABLE_OAUTH_FIELDS)[number];

export const rotateCommand = new Command('rotate')
  .description('Replace a credential value in the vault (name and metadata stay the same)')
  .argument('<alias>', 'The key alias (name) to rotate')
  .option('--value <value>', 'New value, provided inline (skips the prompt; avoids shell history if you use process substitution)')
  .option('--field <name>', 'For OAuth credentials, the field to rotate (client_secret or refresh_token)')
  .action(async (alias: string, opts: { value?: string; field?: string }) => {
    // Find the key by name
    let listRes: { keys: KeyListItem[] };
    try {
      listRes = await apiRequest<{ keys: KeyListItem[] }>('/v1/keys');
    } catch (e: any) {
      console.error(`Failed to look up key: ${e.message}`);
      process.exit(1);
    }

    const match = listRes.keys.find((k) => k.name === alias);
    if (!match) {
      console.error(`Key not found: ${alias}`);
      console.error("Run 'apilocker list' to see what's in your vault.");
      process.exit(1);
    }

    const credentialType = match.credential_type ?? 'api_key';
    const isOAuth = credentialType === 'oauth2';

    // Validate --field usage
    let field: RotatableOAuthField | null = null;
    if (isOAuth) {
      if (!opts.field) {
        console.error(`"${match.name}" is an OAuth credential. You must specify which field to rotate:`);
        console.error('  apilocker rotate ' + JSON.stringify(match.name) + ' --field client_secret');
        console.error('  apilocker rotate ' + JSON.stringify(match.name) + ' --field refresh_token');
        process.exit(1);
      }
      if (!ROTATABLE_OAUTH_FIELDS.includes(opts.field as RotatableOAuthField)) {
        console.error(`Invalid --field: ${opts.field}`);
        console.error(`Valid values: ${ROTATABLE_OAUTH_FIELDS.join(', ')}`);
        process.exit(1);
      }
      field = opts.field as RotatableOAuthField;
    } else if (opts.field) {
      console.error(`"${match.name}" is not an OAuth credential; --field does not apply.`);
      process.exit(1);
    }

    // Get the new value
    let newValue: string;
    if (opts.value) {
      newValue = opts.value;
    } else {
      console.log(`Rotating: \x1b[1m${match.name}\x1b[0m  (${match.provider}${isOAuth ? ' · ' + field : ''})`);
      if (match.rotated_at) {
        console.log(`Last rotated: ${match.rotated_at}`);
      }
      console.log('');
      const promptLabel = isOAuth ? `New ${field}: ` : 'New value: ';
      newValue = await askMasked(promptLabel);
      if (!newValue) {
        console.error('Empty value, cancelled.');
        process.exit(1);
      }
    }

    // Build the rotate body. api_key uses `key`; oauth2 uses the
    // specific field name so the server can do a partial merge.
    const body: Record<string, string> = isOAuth
      ? { [field!]: newValue }
      : { key: newValue };

    // Call the rotate endpoint
    try {
      const res = await apiRequest<{
        id: string;
        name: string;
        provider: string;
        credential_type?: string;
        rotated_at: string;
        rotated_fields?: string[];
      }>(`/v1/keys/${match.id}/rotate`, {
        method: 'POST',
        body: JSON.stringify(body),
      });

      console.log('');
      const label = isOAuth && res.rotated_fields?.length
        ? `${res.name} (${res.rotated_fields.join(', ')})`
        : res.name;
      console.log(`\x1b[32m✓\x1b[0m Rotated: ${label}`);
      console.log(`  Rotated at: ${res.rotated_at}`);
      console.log('');
      if (isOAuth) {
        console.log('Other OAuth fields (client_id, scopes, etc.) are unchanged.');
      }
      console.log("Your scoped tokens continue to work — they don't need to be reissued.");
    } catch (e: any) {
      console.error(`Failed to rotate: ${e.message}`);
      process.exit(1);
    }
  });

/**
 * Prompt for input with the terminal's echo disabled so the user's
 * typed value isn't visible on-screen. Falls back to normal echo if
 * the raw mode isn't supported (e.g. non-TTY stdin).
 */
async function askMasked(prompt: string): Promise<string> {
  const stdin = process.stdin as any;
  const stdout = process.stdout;

  // Non-TTY fallback: just use normal readline
  if (!stdin.isTTY) {
    return new Promise((resolve) => {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    });
  }

  return new Promise((resolve) => {
    stdout.write(prompt);
    let captured = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    const onData = (chunk: string) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          stdout.write('\n');
          resolve(captured.trim());
          return;
        }
        if (code === 3) {
          // Ctrl+C
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          stdout.write('\n');
          process.exit(130);
        }
        if (code === 127 || code === 8) {
          // Backspace
          if (captured.length > 0) {
            captured = captured.slice(0, -1);
            stdout.write('\b \b');
          }
          continue;
        }
        captured += ch;
        stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}
