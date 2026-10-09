import * as vscode from 'vscode';
import {
  isConfigured,
  listKeys,
  listTokens,
  listDevices,
  getActivity,
  KeyMetadata,
  TokenInfo,
  DeviceInfo,
  ActivityEntry,
} from './api';

interface Finding {
  severity: 'warn' | 'info' | 'ok';
  category: string;
  summary: string;
  details: string[];
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    private readonly hasDetails: boolean,
  ) {
    super(
      finding.summary,
      hasDetails
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None,
    );

    const iconMap: Record<string, [string, string]> = {
      warn: ['warning', 'list.warningForeground'],
      info: ['info', 'foreground'],
      ok: ['pass', 'testing.iconPassed'],
    };
    const [icon, color] = iconMap[finding.severity] ?? iconMap.info;
    this.iconPath = new vscode.ThemeIcon(icon, new vscode.ThemeColor(color));
    this.contextValue = 'finding';
  }
}

class DetailItem extends vscode.TreeItem {
  constructor(text: string) {
    super(text, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon('circle-small');
  }
}

class SummaryItem extends vscode.TreeItem {
  constructor(warnings: number, infos: number) {
    const label =
      warnings === 0 && infos === 0
        ? 'Vault is healthy'
        : `${warnings} warning${warnings !== 1 ? 's' : ''}, ${infos} note${infos !== 1 ? 's' : ''}`;
    super(label, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon(
      warnings === 0 ? 'shield' : 'shield',
      new vscode.ThemeColor(warnings === 0 ? 'testing.iconPassed' : 'list.warningForeground'),
    );
    this.description = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
}

export class HealthTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private findings: Finding[] = [];
  private summaryItem: SummaryItem | null = null;

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
    if (!isConfigured()) return [];

    // Detail children of a finding
    if (element instanceof FindingItem) {
      return element.finding.details.map((d) => new DetailItem(d));
    }

    if (element) return [];

    // Root — run the health checks
    try {
      const [keys, tokens, devices, activity] = await Promise.all([
        listKeys(),
        listTokens(),
        listDevices(),
        getActivity(500),
      ]);

      this.findings = runHealthChecks(keys, tokens, devices, activity);
      const warnings = this.findings.filter((f) => f.severity === 'warn').length;
      const infos = this.findings.filter((f) => f.severity === 'info').length;
      this.summaryItem = new SummaryItem(warnings, infos);

      if (this.findings.length === 0) {
        return [this.summaryItem];
      }

      return [
        this.summaryItem,
        ...this.findings.map((f) => new FindingItem(f, f.details.length > 0)),
      ];
    } catch (err: any) {
      const errorItem = new vscode.TreeItem('Failed to run health check');
      errorItem.description = err.message;
      errorItem.iconPath = new vscode.ThemeIcon('error');
      return [errorItem];
    }
  }
}

function runHealthChecks(
  keys: KeyMetadata[],
  tokens: TokenInfo[],
  devices: DeviceInfo[],
  activity: ActivityEntry[],
): Finding[] {
  const findings: Finding[] = [];
  const now = Date.now();
  const daysSince = (iso: string | null): number | null => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (isNaN(t)) return null;
    return Math.floor((now - t) / 86400000);
  };

  // 1. Stale rotations (90+ days)
  const staleRotations = keys.filter((k) => {
    const ref = k.rotated_at || k.created_at;
    const d = daysSince(ref);
    return d != null && d >= 90;
  });
  if (staleRotations.length) {
    findings.push({
      severity: 'warn',
      category: 'rotation',
      summary: `${staleRotations.length} key${staleRotations.length !== 1 ? 's' : ''} not rotated in 90+ days`,
      details: staleRotations.map(
        (k) => `${k.name} — ${daysSince(k.rotated_at || k.created_at)} days`,
      ),
    });
  }

  // 2. Unused keys (no activity in 30 days)
  const cutoff = now - 30 * 86400000;
  const activeKeyIds = new Set<string>();
  for (const log of activity) {
    if (!log.key_id) continue;
    const t = new Date(log.timestamp).getTime();
    if (t >= cutoff) activeKeyIds.add(log.key_id);
  }
  const unused = keys.filter((k) => !activeKeyIds.has(k.id));
  if (unused.length) {
    findings.push({
      severity: 'info',
      category: 'unused',
      summary: `${unused.length} key${unused.length !== 1 ? 's' : ''} with no activity in 30+ days`,
      details: unused.map((k) => k.name),
    });
  }

  // 3. Stale devices (60+ days since last use)
  const staleDevices = devices.filter((d) => {
    const days = daysSince(d.last_used_at);
    return days != null && days >= 60;
  });
  if (staleDevices.length) {
    findings.push({
      severity: 'warn',
      category: 'devices',
      summary: `${staleDevices.length} device${staleDevices.length !== 1 ? 's' : ''} not seen in 60+ days`,
      details: staleDevices.map(
        (d) => `${d.name} — ${daysSince(d.last_used_at)} days`,
      ),
    });
  }

  // 4. Paused credentials
  const paused = keys.filter((k) => k.paused_at);
  if (paused.length) {
    findings.push({
      severity: 'info',
      category: 'paused',
      summary: `${paused.length} credential${paused.length !== 1 ? 's' : ''} currently paused`,
      details: paused.map((k) => k.name),
    });
  }

  // 5. Compromised tokens (reuse detected)
  const compromised = tokens.filter((t) => t.compromised);
  if (compromised.length) {
    findings.push({
      severity: 'warn',
      category: 'tokens',
      summary: `${compromised.length} token${compromised.length !== 1 ? 's' : ''} with reuse detected — possibly compromised`,
      details: compromised.map((t) => t.name),
    });
  }

  return findings;
}
