// Durable Object for per-token traffic monitoring
// Tracks request patterns and flags anomalies — never blocks requests

interface RequestRecord {
  timestamp: number;
  keyId: string;
}

interface TrafficAlert {
  type: 'spike';
  tokenId: string;
  message: string;
  currentRate: number;
  baselineRate: number;
  timestamp: string;
}

export class TrafficMonitor implements DurableObject {
  private state: DurableObjectState;
  private requests: RequestRecord[] = [];
  private alerts: TrafficAlert[] = [];

  // Sliding window: track requests in the last hour
  private readonly WINDOW_MS = 60 * 60 * 1000; // 1 hour
  // Alert threshold: 10x the average rate
  private readonly SPIKE_MULTIPLIER = 10;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.state.blockConcurrencyWhile(async () => {
      this.requests = (await this.state.storage.get<RequestRecord[]>('requests')) || [];
      this.alerts = (await this.state.storage.get<TrafficAlert[]>('alerts')) || [];
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/record') {
      return this.recordRequest(request);
    }

    if (request.method === 'GET' && url.pathname === '/alerts') {
      return Response.json({ alerts: this.alerts.slice(-50) });
    }

    if (request.method === 'GET' && url.pathname === '/stats') {
      return Response.json(this.getStats());
    }

    return new Response('Not found', { status: 404 });
  }

  private async recordRequest(request: Request): Promise<Response> {
    const body = (await request.json()) as { tokenId: string; keyId: string };
    const now = Date.now();

    // Add new request
    this.requests.push({ timestamp: now, keyId: body.keyId });

    // Prune old requests outside the window
    const cutoff = now - this.WINDOW_MS;
    this.requests = this.requests.filter((r) => r.timestamp > cutoff);

    // Check for anomalies
    const alert = this.checkForSpike(body.tokenId, now);
    if (alert) {
      this.alerts.push(alert);
      // Keep only last 100 alerts
      if (this.alerts.length > 100) {
        this.alerts = this.alerts.slice(-100);
      }
      await this.state.storage.put('alerts', this.alerts);
    }

    await this.state.storage.put('requests', this.requests);

    return Response.json({ recorded: true, alert: alert ?? null });
  }

  private checkForSpike(tokenId: string, now: number): TrafficAlert | null {
    // Need at least 1 hour of data to establish a baseline
    if (this.requests.length < 10) return null;

    // Calculate requests per minute over the last hour
    const oneHourAgo = now - this.WINDOW_MS;
    const hourRequests = this.requests.filter((r) => r.timestamp > oneHourAgo);
    const baselineRpm = hourRequests.length / 60;

    // Calculate requests per minute in the last 5 minutes
    const fiveMinAgo = now - 5 * 60 * 1000;
    const recentRequests = this.requests.filter((r) => r.timestamp > fiveMinAgo);
    const currentRpm = recentRequests.length / 5;

    // Spike detection
    if (baselineRpm > 0 && currentRpm > baselineRpm * this.SPIKE_MULTIPLIER) {
      return {
        type: 'spike',
        tokenId,
        message: `Traffic spike detected: ${currentRpm.toFixed(1)} req/min vs baseline ${baselineRpm.toFixed(1)} req/min`,
        currentRate: Math.round(currentRpm),
        baselineRate: Math.round(baselineRpm),
        timestamp: new Date().toISOString(),
      };
    }

    return null;
  }

  private getStats() {
    const now = Date.now();
    const fiveMinAgo = now - 5 * 60 * 1000;
    const oneHourAgo = now - this.WINDOW_MS;

    const recentRequests = this.requests.filter((r) => r.timestamp > fiveMinAgo);
    const hourRequests = this.requests.filter((r) => r.timestamp > oneHourAgo);

    return {
      total_requests_last_hour: hourRequests.length,
      requests_per_minute_current: (recentRequests.length / 5).toFixed(1),
      requests_per_minute_baseline: (hourRequests.length / 60).toFixed(1),
      active_alerts: this.alerts.filter(
        (a) => new Date(a.timestamp).getTime() > now - 30 * 60 * 1000
      ).length,
    };
  }
}
