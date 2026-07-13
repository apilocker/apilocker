import { Command } from 'commander';
import { apiRequest } from '../api';
import {
  formatTokenCreateResult,
  resolveKeyIdentifiers,
  KeyRef,
  TokenCreateResponse,
} from './token-helpers';

export const tokenCommand = new Command('token')
  .description('Manage scoped access tokens');

tokenCommand
  .command('create')
  .description('Create a new scoped token')
  .requiredOption('--name <name>', 'Token name')
  .requiredOption('--keys <keys>', 'Comma-separated key IDs or names')
  .option('--rotation <type>', 'Rotation: static, daily, weekly, monthly', 'static')
  .action(async (opts) => {
    try {
      const inputs = opts.keys.split(',').map((k: string) => k.trim()).filter(Boolean);

      // The proxy authorizes by key ID only — resolve any names first.
      let allowedKeys = inputs;
      if (inputs.some((k: string) => !k.startsWith('key_'))) {
        const { keys } = await apiRequest<{ keys: KeyRef[] }>('/v1/keys');
        allowedKeys = resolveKeyIdentifiers(inputs, keys);
      }

      const res = await apiRequest<TokenCreateResponse>('/v1/tokens', {
        method: 'POST',
        body: JSON.stringify({
          name: opts.name,
          allowed_keys: allowedKeys,
          rotation_type: opts.rotation,
        }),
      });

      for (const line of formatTokenCreateResult(res)) {
        console.log(line);
      }
    } catch (e: any) {
      console.error(`Failed to create token: ${e.message}`);
      process.exit(1);
    }
  });

tokenCommand
  .command('list')
  .description('List all tokens')
  .action(async () => {
    try {
      const res = await apiRequest<{
        tokens: Array<{
          id: string;
          name: string;
          rotation_type: string;
          expires_at: string | null;
          revoked: boolean;
        }>;
      }>('/v1/tokens');

      if (res.tokens.length === 0) {
        console.log('No tokens created yet.');
        return;
      }

      console.log(`\n${'Name'.padEnd(25)} ${'Rotation'.padEnd(10)} ${'Status'.padEnd(10)} ${'ID'}`);
      console.log('-'.repeat(80));

      for (const t of res.tokens) {
        const status = t.revoked ? 'revoked' : 'active';
        console.log(
          `${t.name.padEnd(25)} ${t.rotation_type.padEnd(10)} ${status.padEnd(10)} ${t.id}`
        );
      }

      console.log(`\n${res.tokens.length} token(s).`);
    } catch (e: any) {
      console.error(`Failed to list tokens: ${e.message}`);
      process.exit(1);
    }
  });

tokenCommand
  .command('revoke')
  .description('Revoke a token')
  .argument('<tokenId>', 'Token ID to revoke')
  .action(async (tokenId: string) => {
    try {
      await apiRequest(`/v1/tokens/${tokenId}`, { method: 'DELETE' });
      console.log(`Token ${tokenId} revoked.`);
    } catch (e: any) {
      console.error(`Failed to revoke token: ${e.message}`);
      process.exit(1);
    }
  });
