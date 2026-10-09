import * as vscode from 'vscode';
import { TokenInfo, listTokens, isConfigured } from './api';

export class TokenItem extends vscode.TreeItem {
  constructor(public readonly token: TokenInfo) {
    super(token.name, vscode.TreeItemCollapsibleState.None);

    this.description = `${token.rotation_type} · ${token.allowed_keys.length} key${token.allowed_keys.length !== 1 ? 's' : ''}`;
    this.tooltip = this.buildTooltip();

    if (token.compromised) {
      this.contextValue = 'token-compromised';
      this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
    } else if (token.paused) {
      this.contextValue = 'token-paused';
      this.iconPath = new vscode.ThemeIcon('debug-pause', new vscode.ThemeColor('disabledForeground'));
    } else {
      this.contextValue = 'token';
      this.iconPath = new vscode.ThemeIcon('key');
    }
  }

  private buildTooltip(): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${this.token.name}**\n\n`);
    md.appendMarkdown(`Rotation: \`${this.token.rotation_type}\`\n\n`);
    md.appendMarkdown(`Keys: ${this.token.allowed_keys.join(', ')}\n\n`);
    md.appendMarkdown(`Created: ${new Date(this.token.created_at).toLocaleDateString()}\n\n`);
    if (this.token.expires_at) {
      md.appendMarkdown(`Expires: ${new Date(this.token.expires_at).toLocaleString()}\n\n`);
    }
    if (this.token.last_refreshed_at) {
      md.appendMarkdown(`Last refreshed: ${new Date(this.token.last_refreshed_at).toLocaleString()}\n\n`);
    }
    if (this.token.compromised) {
      md.appendMarkdown(`$(error) **Reuse detected — compromised**\n\n`);
    }
    if (this.token.paused) {
      md.appendMarkdown(`$(warning) **Paused**\n\n`);
    }
    return md;
  }
}

export class TokensTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
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
      const tokens = await listTokens();
      if (tokens.length === 0) {
        const empty = new vscode.TreeItem('No scoped tokens');
        empty.description = 'Create one from the dashboard';
        empty.iconPath = new vscode.ThemeIcon('info');
        return [empty];
      }
      return tokens.map((t) => new TokenItem(t));
    } catch (err: any) {
      const errorItem = new vscode.TreeItem('Failed to load tokens');
      errorItem.description = err.message;
      errorItem.iconPath = new vscode.ThemeIcon('error');
      return [errorItem];
    }
  }
}
