import { Command } from 'commander';
import { apiRequest } from '../api';

export const deleteCommand = new Command('delete')
  .description('Delete a stored key')
  .argument('<keyId>', 'Key ID or name to delete')
  .action(async (keyId: string) => {
    try {
      await apiRequest(`/v1/keys/${keyId}`, { method: 'DELETE' });
      console.log(`Key ${keyId} deleted.`);
    } catch (e: any) {
      console.error(`Failed to delete key: ${e.message}`);
      process.exit(1);
    }
  });
