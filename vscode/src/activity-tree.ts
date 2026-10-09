import * as vscode from 'vscode';
import { ActivityEntry, getActivity, isConfigured } from './api';

export class ActivityItem extends vscode.TreeItem {
  constructor(entry: ActivityEntry) {
    const time = new Date(entry.timestamp);
    const timeStr = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const label = entry.provider || entry.forward_path || 'unknown';

    super(label, vscode.TreeItemCollapsibleState.None);

    this.description = `${entry.forward_path ?? ''}  ${timeStr}`;
    this.tooltip = this.buildTooltip(entry, time);
    this.contextValue = 'activity';

    const action = entry.forward_path ?? '';
    const iconMap: Record<string, string> = {
      '/proxy': 'arrow-swap',
      '/reveal': 'eye',
      '/rotate': 'sync',
      '/rename': 'edit',
      '/pause': 'debug-pause',
      '/resume': 'debug-start',
      '/delete': 'trash',
      '/store': 'add',
      '/vault-fetch': 'database',
    };
    const iconId = Object.entries(iconMap).find(([prefix]) => action.startsWith(prefix))?.[1] ?? 'pulse';
    this.iconPath = new vscode.ThemeIcon(iconId);
  }

  private buildTooltip(entry: ActivityEntry, time: Date): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${entry.provider ?? 'unknown'}** — \`${entry.forward_path ?? ''}\`\n\n`);
    md.appendMarkdown(`Time: ${time.toLocaleString()}\n\n`);
    if (entry.status_code) md.appendMarkdown(`Status: \`${entry.status_code}\`\n\n`);
    if (entry.latency_ms) md.appendMarkdown(`Latency: ${entry.latency_ms}ms\n\n`);
    if (entry.country) md.appendMarkdown(`Country: ${entry.country}\n\n`);
    if (entry.source_ip) md.appendMarkdown(`IP: \`${entry.source_ip}\``);
    return md;
  }
}

export class ActivityTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(): Promise<vscode.TreeItem[]> {
    if (!isConfigured()) return [];

    try {
      const entries = await getActivity(30);
      if (entries.length === 0) {
        const empty = new vscode.TreeItem('No recent activity');
        empty.iconPath = new vscode.ThemeIcon('info');
        return [empty];
      }
      return entries.map((e) => new ActivityItem(e));
    } catch (err: any) {
      const errorItem = new vscode.TreeItem('Failed to load activity');
      errorItem.description = err.message;
      errorItem.iconPath = new vscode.ThemeIcon('error');
      return [errorItem];
    }
  }
}
