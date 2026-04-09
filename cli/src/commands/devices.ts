import { Command } from 'commander';
import * as readline from 'readline';
import { apiRequest } from '../api';

interface DeviceListItem {
  id: string;
  name: string;
  hostname: string | null;
  platform: string | null;
  platform_version: string | null;
  cli_version: string | null;
  registered_at: string;
  last_used_at: string;
  current: boolean;
}

interface DeviceListResponse {
  devices: DeviceListItem[];
}

export const devicesCommand = new Command('devices').description(
  'Manage devices registered to your account'
);

devicesCommand
  .command('list')
  .description('List all devices registered to this account')
  .action(async () => {
    try {
      const res = await apiRequest<DeviceListResponse>('/v1/devices');
      if (res.devices.length === 0) {
        console.log('No devices registered.');
        return;
      }

      const rows = res.devices.map((d) => ({
        id: shortId(d.id),
        name: d.name,
        platform:
          [d.platform, d.platform_version].filter(Boolean).join(' ') || '—',
        last: friendlyTime(d.last_used_at),
        current: d.current ? 'yes' : '',
      }));

      printTable(['ID', 'NAME', 'PLATFORM', 'LAST SEEN', 'CURRENT'], [
        ...rows.map((r) => [r.id, r.name, r.platform, r.last, r.current]),
      ]);
    } catch (e: any) {
      console.error(`Failed to list devices: ${e.message}`);
      process.exit(1);
    }
  });

devicesCommand
  .command('revoke <deviceId>')
  .description('Revoke a device by ID (use `devices list` to find the ID)')
  .option('--yes', 'Skip confirmation prompt')
  .action(async (deviceId: string, opts: { yes?: boolean }) => {
    try {
      // Look up the device to confirm it exists and tell the user what
      // they're about to revoke
      const list = await apiRequest<DeviceListResponse>('/v1/devices');
      const match = list.devices.find(
        (d) => d.id === deviceId || shortId(d.id) === deviceId
      );
      if (!match) {
        console.error(`Device not found: ${deviceId}`);
        console.error("Run 'apilocker devices list' to see your devices.");
        process.exit(1);
      }

      // Warn if user is about to revoke the current device
      if (match.current) {
        console.log('⚠  You are about to revoke the device you are currently using.');
        console.log('   After this, apilocker commands on THIS machine will stop working.');
        console.log("   You'd need to run 'apilocker register' again to re-register.");
        console.log();
      }

      if (!opts.yes) {
        const confirmed = await confirm(
          `Revoke device "${match.name}"? This cannot be undone. [y/N] `
        );
        if (!confirmed) {
          console.log('Cancelled.');
          return;
        }
      }

      await apiRequest<{ ok: true }>(`/v1/devices/${match.id}/revoke`, {
        method: 'POST',
      });

      console.log(`✓ Revoked device: ${match.name}`);
    } catch (e: any) {
      console.error(`Failed to revoke device: ${e.message}`);
      process.exit(1);
    }
  });

// ---- Helpers ----

function shortId(id: string): string {
  // Device IDs look like `dev_<uuid>` — show the first chunk for compactness
  const parts = id.split('_');
  if (parts.length < 2) return id;
  return parts[0] + '_' + parts[1].slice(0, 8);
}

function friendlyTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffSec = Math.floor((Date.now() - then) / 1000);
  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function printTable(headers: string[], rows: string[][]): void {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] || '').length))
  );
  const line = (cols: string[]) =>
    cols.map((c, i) => (c || '').padEnd(widths[i])).join('  ');
  console.log(line(headers));
  console.log(widths.map((w) => '─'.repeat(w)).join('  '));
  for (const row of rows) {
    console.log(line(row));
  }
}

function confirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((res) => {
    rl.question(question, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      res(normalized === 'y' || normalized === 'yes');
    });
  });
}
