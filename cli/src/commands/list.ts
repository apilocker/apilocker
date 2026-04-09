import { Command } from 'commander';
import { apiRequest } from '../api';

/**
 * `apilocker list` — list stored credentials, grouped into three buckets:
 * LLM keys, service API keys, and OAuth credentials. Filters are applied
 * client-side against the full vault.
 *
 * Flags:
 *   --tag <t>        Show only keys with this tag (repeatable for OR)
 *   --provider <p>   Show only keys matching this provider
 *   --category <c>   Show only keys in this category (llm | service | oauth)
 *   --search <q>     Substring match on name (case-insensitive)
 *   --json           Emit the raw list as JSON (for scripting)
 */

type Category = 'llm' | 'service' | 'oauth';
type CredentialType = 'api_key' | 'oauth2';

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
  category: Category;
  credential_type: CredentialType;
  tags: string[];
  auth_header_type: string;
  base_url: string | null;
  created_at: string;
  rotated_at: string | null;
  paused_at: string | null;
}

export const listCommand = new Command('list')
  .description('List stored credentials grouped by category (LLM / Service / OAuth)')
  .option('--tag <tag>', 'Filter by tag (repeatable)', collect, [])
  .option('--provider <provider>', 'Filter by provider id')
  .option('--category <category>', 'Filter by category: llm | service | oauth')
  .option('--search <query>', 'Case-insensitive substring match on name')
  .option('--json', 'Emit the list as JSON instead of a table')
  .action(async (opts: { tag?: string[]; provider?: string; category?: string; search?: string; json?: boolean }) => {
    try {
      const res = await apiRequest<{ keys: KeyListItem[] }>('/v1/keys');
      let keys = res.keys;

      // Apply filters
      if (opts.tag && opts.tag.length > 0) {
        const wanted = new Set(opts.tag.map((t) => t.toLowerCase()));
        keys = keys.filter((k) =>
          (k.tags || []).some((t) => wanted.has(t.toLowerCase()))
        );
      }
      if (opts.provider) {
        const p = opts.provider.toLowerCase();
        keys = keys.filter((k) => k.provider.toLowerCase() === p);
      }
      if (opts.category) {
        const c = opts.category.toLowerCase() as Category;
        keys = keys.filter((k) => k.category === c);
      }
      if (opts.search) {
        const q = opts.search.toLowerCase();
        keys = keys.filter((k) => k.name.toLowerCase().includes(q));
      }

      if (opts.json) {
        console.log(JSON.stringify({ keys }, null, 2));
        return;
      }

      if (keys.length === 0) {
        if (opts.tag?.length || opts.provider || opts.category || opts.search) {
          console.log('No credentials match your filters.');
        } else {
          console.log('No credentials stored yet.');
        }
        return;
      }

      // Group by category
      const buckets: Record<Category, KeyListItem[]> = {
        llm: keys.filter((k) => k.category === 'llm'),
        service: keys.filter((k) => k.category === 'service'),
        oauth: keys.filter((k) => k.category === 'oauth'),
      };

      const labels: Record<Category, string> = {
        llm: 'LLM API Keys',
        service: 'Service API Keys',
        oauth: 'OAuth Credentials',
      };

      let first = true;
      for (const category of ['llm', 'service', 'oauth'] as Category[]) {
        const bucketKeys = buckets[category];
        if (bucketKeys.length === 0) continue;
        if (!first) console.log('');
        first = false;
        console.log(`\x1b[1m${labels[category]}\x1b[0m  \x1b[2m(${bucketKeys.length})\x1b[0m`);
        printTable(bucketKeys);
      }

      console.log('');
      console.log(`${keys.length} credential${keys.length === 1 ? '' : 's'}${opts.tag?.length || opts.provider || opts.category || opts.search ? ' matching filters' : ''}.`);
    } catch (e: any) {
      console.error(`Failed to list credentials: ${e.message}`);
      process.exit(1);
    }
  });

function printTable(keys: KeyListItem[]): void {
  const rows = keys.map((k) => ({
    name: k.name,
    provider: k.provider,
    type: k.credential_type === 'oauth2' ? 'oauth' : 'key',
    tags: (k.tags || []).join(',') || '—',
    status: k.paused_at ? '\x1b[33mpaused\x1b[0m' : '',
    rotated: k.rotated_at ? fmtRelative(k.rotated_at) : '—',
  }));

  const widths = {
    name: Math.max('NAME'.length, ...rows.map((r) => r.name.length)),
    provider: Math.max('PROVIDER'.length, ...rows.map((r) => r.provider.length)),
    type: Math.max('TYPE'.length, ...rows.map((r) => r.type.length)),
    tags: Math.max('TAGS'.length, ...rows.map((r) => r.tags.length)),
    status: Math.max('STATUS'.length, ...rows.map((r) => stripAnsi(r.status).length || 1)),
    rotated: Math.max('ROTATED'.length, ...rows.map((r) => r.rotated.length)),
  };

  const header =
    '  ' +
    pad('NAME', widths.name) + '  ' +
    pad('PROVIDER', widths.provider) + '  ' +
    pad('TYPE', widths.type) + '  ' +
    pad('TAGS', widths.tags) + '  ' +
    pad('STATUS', widths.status) + '  ' +
    'ROTATED';
  console.log(header);
  console.log('  ' + [widths.name, widths.provider, widths.type, widths.tags, widths.status, widths.rotated].map((w) => '─'.repeat(w)).join('  '));
  for (const r of rows) {
    console.log(
      '  ' +
      pad(r.name, widths.name) + '  ' +
      pad(r.provider, widths.provider) + '  ' +
      pad(r.type, widths.type) + '  ' +
      pad(r.tags, widths.tags) + '  ' +
      padAnsi(r.status, widths.status) + '  ' +
      r.rotated
    );
  }
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function padAnsi(s: string, n: number): string {
  const visible = stripAnsi(s);
  if (visible.length >= n) return s;
  return s + ' '.repeat(n - visible.length);
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}

function fmtRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffSec = Math.floor((Date.now() - then) / 1000);
  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 86400 * 30) return `${Math.floor(diffSec / 86400)}d ago`;
  if (diffSec < 86400 * 365) return `${Math.floor(diffSec / (86400 * 30))}mo ago`;
  return `${Math.floor(diffSec / (86400 * 365))}y ago`;
}
