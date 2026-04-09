import { Env } from './types';
import { handleRequest } from './router';
import { jsonOk } from './responses';
import './routes';

export { TrafficMonitor } from './traffic-monitor';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return jsonOk({ status: 'ok' });
    }

    return handleRequest(request, env);
  },

  /**
   * Scheduled handler — runs on the cron trigger defined in wrangler.toml.
   *
   * Current jobs:
   *   1. Purge expired device_codes. Rows are set with expires_at = now+10min
   *      when a CLI starts the device authorization flow. After that window
   *      they're useless, and if the user doesn't complete the flow the
   *      row just sits in the table forever. This job deletes rows whose
   *      `expires_at` is more than 24 hours in the past (giving us a
   *      small grace window for forensics).
   *
   * Scheduled handlers have a strict wall-clock budget; we use
   * `ctx.waitUntil` on the cleanup promise so the handler returns
   * immediately while the DELETE runs in the background.
   */
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cleanupExpiredDeviceCodes(env));
  },
};

async function cleanupExpiredDeviceCodes(env: Env): Promise<void> {
  try {
    const result = await env.DB.prepare(
      `DELETE FROM device_codes
       WHERE datetime(expires_at) < datetime('now', '-1 day')`
    ).run();
    const deleted = result.meta.changes ?? 0;
    if (deleted > 0) {
      console.log(`[cron] Purged ${deleted} expired device_code rows`);
    }
  } catch (e) {
    console.error('[cron] device_codes cleanup failed:', e);
  }
}
