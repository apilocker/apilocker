import { Command } from 'commander';
import { apiRequest } from '../api';

/**
 * `apilocker activity` — view the audit log of credential access.
 *
 * Supports two modes:
 *   1. Snapshot mode (default): prints the most recent N entries and exits.
 *   2. Follow mode (--follow or -f): polls every few seconds and streams
 *      new entries as they come in, like `tail -f`. Dedup is handled by
 *      tracking audit log IDs we've already printed this session.
 *
 * Filters (--key, --token) work in both modes.
 */

interface AuditLog {
  id: string;
  provider: string | null;
  forward_path: string | null;
  status_code: number | null;
  latency_ms: number | null;
  source_ip: string | null;
  timestamp: string;
  key_id: string | null;
  token_id: string | null;
}

export const activityCommand = new Command('activity')
  .description('View audit log of credential access (use --follow for live streaming)')
  .option('--key <keyId>', 'Filter by key ID (short or long)')
  .option('--token <tokenId>', 'Filter by token ID')
  .option('-n, --limit <n>', 'Number of entries to show in snapshot mode', '20')
  .option('-f, --follow', 'Stream new entries as they happen (Ctrl+C to exit)')
  .option('--interval <seconds>', 'Poll interval for --follow, in seconds', '2')
  .action(async (opts) => {
    const filterParams = new URLSearchParams();
    if (opts.key) filterParams.set('key_id', opts.key);
    if (opts.token) filterParams.set('token_id', opts.token);

    if (opts.follow) {
      await runFollow(filterParams, Math.max(1, parseInt(String(opts.interval), 10) || 2));
      return;
    }

    // Snapshot mode
    try {
      filterParams.set('limit', String(opts.limit));
      const res = await apiRequest<{ logs: AuditLog[] }>(
        `/v1/activity?${filterParams.toString()}`
      );

      if (res.logs.length === 0) {
        console.log('No activity recorded yet.');
        return;
      }

      printHeader();
      for (const log of [...res.logs].reverse()) {
        printLogRow(log);
      }
      console.log(`\n${res.logs.length} entries.`);
    } catch (e: any) {
      console.error(`Failed to get activity: ${e.message}`);
      process.exit(1);
    }
  });

/**
 * Poll the activity endpoint on an interval and stream new entries.
 * Seen IDs are tracked in a Set; new entries are printed in chronological
 * order (oldest first) so they read naturally as they scroll by.
 *
 * First poll primes the Set with existing IDs so we don't flood stdout
 * with historical data — only NEW activity after the command starts is
 * printed.
 */
async function runFollow(
  filterParams: URLSearchParams,
  intervalSeconds: number
): Promise<void> {
  const seen = new Set<string>();
  let firstPoll = true;

  printHeader();
  console.log('  (streaming live — Ctrl+C to exit)');

  const poll = async () => {
    try {
      filterParams.set('limit', '50');
      const res = await apiRequest<{ logs: AuditLog[] }>(
        `/v1/activity?${filterParams.toString()}`
      );
      const newest: AuditLog[] = [];
      for (const log of res.logs) {
        if (seen.has(log.id)) continue;
        seen.add(log.id);
        if (!firstPoll) newest.push(log);
      }
      // Print in chronological order (API returns newest-first)
      for (const log of newest.reverse()) {
        printLogRow(log);
      }
      firstPoll = false;
    } catch (e: any) {
      // Don't die on transient errors — just note and retry on next tick
      process.stderr.write(`\r  (poll error: ${e.message}, retrying…)   \n`);
    }
  };

  // Prime and then loop
  await poll();
  const timer = setInterval(poll, intervalSeconds * 1000);

  // Clean exit on Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(timer);
    console.log('\n  (stopped)');
    process.exit(0);
  });
}

function printHeader(): void {
  console.log('');
  console.log(
    `  ${'TIME'.padEnd(19)}  ${'PROVIDER'.padEnd(12)}  ${'STATUS'.padEnd(6)}  ${'LATENCY'.padEnd(7)}  PATH`
  );
  console.log(`  ${'─'.repeat(19)}  ${'─'.repeat(12)}  ${'─'.repeat(6)}  ${'─'.repeat(7)}  ────`);
}

function printLogRow(log: AuditLog): void {
  const time = new Date(log.timestamp).toISOString().slice(0, 19).replace('T', ' ');
  const provider = (log.provider || '—').slice(0, 12);
  const status = log.status_code != null ? String(log.status_code) : '—';
  const statusColor =
    log.status_code != null && log.status_code >= 400
      ? '\x1b[31m'
      : log.status_code != null && log.status_code >= 200 && log.status_code < 300
      ? '\x1b[32m'
      : '';
  const latency = log.latency_ms != null ? `${log.latency_ms}ms` : '—';
  const path = log.forward_path || '—';
  console.log(
    `  ${time.padEnd(19)}  ${provider.padEnd(12)}  ${statusColor}${status.padEnd(6)}\x1b[0m  ${latency.padEnd(7)}  ${path}`
  );
}
