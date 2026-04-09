import { Env } from './types';
import { listTokens } from './db';
import { jsonOk } from './responses';

export async function handleGetAlerts(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  // Get all tokens for this user
  const tokens = await listTokens(env, userId);
  const activeTokens = tokens.filter((t) => !t.revoked_at);

  const allAlerts: any[] = [];
  const allStats: any[] = [];

  // Fetch alerts and stats from each token's Durable Object
  await Promise.all(
    activeTokens.map(async (token) => {
      try {
        const monitorId = env.TRAFFIC_MONITOR.idFromName(token.id);
        const monitor = env.TRAFFIC_MONITOR.get(monitorId);

        const [alertsRes, statsRes] = await Promise.all([
          monitor.fetch('https://monitor/alerts'),
          monitor.fetch('https://monitor/stats'),
        ]);

        const alertsData = (await alertsRes.json()) as { alerts: any[] };
        const statsData = (await statsRes.json()) as any;

        for (const alert of alertsData.alerts) {
          allAlerts.push({ ...alert, token_name: token.name });
        }

        allStats.push({
          token_id: token.id,
          token_name: token.name,
          ...statsData,
        });
      } catch {
        // Skip if monitor not yet initialized
      }
    })
  );

  // Sort alerts by timestamp descending
  allAlerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return jsonOk({
    alerts: allAlerts.slice(0, 50),
    stats: allStats,
  });
}
