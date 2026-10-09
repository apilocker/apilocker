import * as vscode from 'vscode';
import { KeyMetadata, listKeys, isConfigured } from './api';

type CategoryLabel = 'LLM API Keys' | 'Service API Keys' | 'OAuth Credentials';

const CATEGORY_ORDER: { key: string; label: CategoryLabel; icon: string }[] = [
  { key: 'llm', label: 'LLM API Keys', icon: 'hubot' },
  { key: 'service', label: 'Service API Keys', icon: 'plug' },
  { key: 'oauth', label: 'OAuth Credentials', icon: 'key' },
];

// ── Tree items ──

export class CategoryItem extends vscode.TreeItem {
  constructor(
    public readonly category: string,
    public readonly label: CategoryLabel,
    public readonly count: number,
    iconId: string,
  ) {
    super(label, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${count}`;
    this.iconPath = new vscode.ThemeIcon(iconId);
    this.contextValue = 'category';
  }
}

export class KeyItem extends vscode.TreeItem {
  constructor(public readonly key: KeyMetadata) {
    super(key.name, vscode.TreeItemCollapsibleState.None);

    this.description = key.provider;
    this.tooltip = this.buildTooltip();
    this.contextValue = key.paused_at ? 'key-paused' : 'key';

    if (key.paused_at) {
      this.iconPath = new vscode.ThemeIcon('debug-pause', new vscode.ThemeColor('disabledForeground'));
    } else if (key.credential_type === 'oauth2') {
      this.iconPath = new vscode.ThemeIcon('shield');
    } else {
      this.iconPath = new vscode.ThemeIcon('lock');
    }
  }

  private buildTooltip(): vscode.MarkdownString {
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${this.key.name}**\n\n`);
    md.appendMarkdown(`Provider: \`${this.key.provider}\`\n\n`);
    md.appendMarkdown(`Type: \`${this.key.credential_type}\`\n\n`);
    if (this.key.base_url) {
      md.appendMarkdown(`Base URL: \`${this.key.base_url}\`\n\n`);
    }
    if (this.key.tags) {
      md.appendMarkdown(`Tags: ${this.key.tags}\n\n`);
    }
    if (this.key.paused_at) {
      md.appendMarkdown(`$(warning) **Paused**\n\n`);
    }
    md.appendMarkdown(`Created: ${new Date(this.key.created_at).toLocaleDateString()}`);
    if (this.key.rotated_at) {
      md.appendMarkdown(`\n\nLast rotated: ${new Date(this.key.rotated_at).toLocaleDateString()}`);
    }
    return md;
  }
}

// ── Not-configured placeholder ──

class SetupItem extends vscode.TreeItem {
  constructor() {
    super('Set up API Locker', vscode.TreeItemCollapsibleState.None);
    this.description = 'Run: apilocker register';
    this.iconPath = new vscode.ThemeIcon('plug');
    this.command = {
      command: 'apilocker.openSetupHelp',
      title: 'Set up API Locker',
    };
  }
}

// ── Provider ──

export class KeysTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private keys: KeyMetadata[] = [];
  private grouped: Map<string, KeyMetadata[]> = new Map();
  private error: string | null = null;

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
    if (!isConfigured()) {
      return element ? [] : [new SetupItem()];
    }

    // Root level — category groups
    if (!element) {
      try {
        this.keys = await listKeys();
        this.error = null;
        this.grouped = new Map();
        for (const key of this.keys) {
          const cat = key.category || 'service';
          if (!this.grouped.has(cat)) this.grouped.set(cat, []);
          this.grouped.get(cat)!.push(key);
        }
      } catch (err: any) {
        this.error = err.message;
        const errorItem = new vscode.TreeItem('Failed to load keys');
        errorItem.description = this.error ?? undefined;
        errorItem.iconPath = new vscode.ThemeIcon('error');
        return [errorItem];
      }

      if (this.keys.length === 0) {
        const empty = new vscode.TreeItem('No credentials stored');
        empty.description = 'Click + to add one';
        empty.iconPath = new vscode.ThemeIcon('info');
        return [empty];
      }

      return CATEGORY_ORDER
        .filter((c) => (this.grouped.get(c.key)?.length ?? 0) > 0)
        .map((c) => new CategoryItem(c.key, c.label, this.grouped.get(c.key)!.length, c.icon));
    }

    // Category children — key items
    if (element instanceof CategoryItem) {
      const items = this.grouped.get(element.category) ?? [];
      return items
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((k) => new KeyItem(k));
    }

    return [];
  }
}
