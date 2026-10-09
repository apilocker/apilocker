import * as vscode from 'vscode';
import { DeviceInfo, listDevices, isConfigured } from './api';

export class DeviceItem extends vscode.TreeItem {
  constructor(public readonly device: DeviceInfo) {
    super(device.name, vscode.TreeItemCollapsibleState.None);

    const parts: string[] = [];
    if (device.hostname) parts.push(device.hostname);
    if (device.platform) parts.push(device.platform);
    if (device.current) parts.push('(this device)');
    this.description = parts.join(' · ') || undefined;

    this.tooltip = this.buildTooltip();
    this.contextValue = device.current ? 'device-current' : 'device';

    if (device.current) {
      this.iconPath = new vscode.ThemeIcon('vm-active', new vscode.ThemeColor('testing.iconPassed'));
    } else {
      this.iconPath = new vscode.ThemeIcon('vm');
    }
  }

  private buildTooltip(): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${this.device.name}**\n\n`);
    if (this.device.hostname) md.appendMarkdown(`Hostname: \`${this.device.hostname}\`\n\n`);
    if (this.device.platform) {
      md.appendMarkdown(`Platform: \`${this.device.platform}${this.device.platform_version ? ' ' + this.device.platform_version : ''}\`\n\n`);
    }
    if (this.device.cli_version) md.appendMarkdown(`CLI: \`v${this.device.cli_version}\`\n\n`);
    md.appendMarkdown(`Registered: ${new Date(this.device.registered_at).toLocaleDateString()}\n\n`);
    md.appendMarkdown(`Last used: ${new Date(this.device.last_used_at).toLocaleString()}`);
    if (this.device.current) {
      md.appendMarkdown(`\n\n$(check) **Current device**`);
    }
    return md;
  }
}

export class DevicesTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
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
      const devices = await listDevices();
      if (devices.length === 0) {
        const empty = new vscode.TreeItem('No devices registered');
        empty.iconPath = new vscode.ThemeIcon('info');
        return [empty];
      }
      return devices.map((d) => new DeviceItem(d));
    } catch (err: any) {
      const errorItem = new vscode.TreeItem('Failed to load devices');
      errorItem.description = err.message;
      errorItem.iconPath = new vscode.ThemeIcon('error');
      return [errorItem];
    }
  }
}
