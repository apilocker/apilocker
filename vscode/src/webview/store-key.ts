import * as vscode from 'vscode';
import { storeKey } from '../api';
import { KeysTreeProvider } from '../keys-tree';

export function registerStoreCommand(
  context: vscode.ExtensionContext,
  keysTree: KeysTreeProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.storeKey', () => {
      StoreKeyPanel.createOrShow(context.extensionUri, keysTree);
    }),
  );
}

class StoreKeyPanel {
  static currentPanel: StoreKeyPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposed = false;

  static createOrShow(extensionUri: vscode.Uri, keysTree: KeysTreeProvider): void {
    if (StoreKeyPanel.currentPanel) {
      StoreKeyPanel.currentPanel.panel.reveal();
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'apilocker.storeKey',
      'Store Credential — API Locker',
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    StoreKeyPanel.currentPanel = new StoreKeyPanel(panel, keysTree);
  }

  private constructor(panel: vscode.WebviewPanel, keysTree: KeysTreeProvider) {
    this.panel = panel;
    this.panel.webview.html = this.getHtml();

    this.panel.onDidDispose(() => {
      this.disposed = true;
      StoreKeyPanel.currentPanel = undefined;
    });

    this.panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === 'store') {
        try {
          await storeKey(msg.payload);
          if (!this.disposed) {
            this.panel.webview.postMessage({ type: 'success' });
          }
          vscode.window.showInformationMessage(`Stored ${msg.payload.name}.`);
          keysTree.refresh();
        } catch (err: any) {
          if (!this.disposed) {
            this.panel.webview.postMessage({ type: 'error', message: err.message });
          }
        }
      }
    });
  }

  private getHtml(): string {
    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 20px;
      max-width: 500px;
    }
    h2 { margin-top: 0; font-weight: 500; }
    label { display: block; margin-top: 12px; font-size: 12px; opacity: 0.8; }
    input, select, textarea {
      width: 100%;
      padding: 6px 8px;
      margin-top: 4px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, transparent);
      border-radius: 2px;
      font-family: var(--vscode-editor-font-family);
      font-size: 13px;
      box-sizing: border-box;
    }
    input:focus, select:focus, textarea:focus {
      outline: 1px solid var(--vscode-focusBorder);
    }
    .tabs {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--vscode-panel-border, #444);
      margin-bottom: 16px;
    }
    .tab {
      padding: 8px 16px;
      cursor: pointer;
      background: none;
      border: none;
      color: var(--vscode-foreground);
      opacity: 0.6;
      border-bottom: 2px solid transparent;
      font-size: 13px;
    }
    .tab.active {
      opacity: 1;
      border-bottom-color: var(--vscode-focusBorder);
    }
    .tab:hover { opacity: 1; }
    .section { display: none; }
    .section.active { display: block; }
    button.primary {
      margin-top: 20px;
      padding: 8px 20px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: 2px;
      cursor: pointer;
      font-size: 13px;
    }
    button.primary:hover { background: var(--vscode-button-hoverBackground); }
    button.primary:disabled { opacity: 0.5; cursor: default; }
    .status { margin-top: 12px; font-size: 12px; }
    .status.error { color: var(--vscode-errorForeground); }
    .status.success { color: var(--vscode-testing-iconPassed); }
  </style>
</head>
<body>
  <h2>Store Credential</h2>

  <div class="tabs">
    <button class="tab active" data-tab="apikey" onclick="switchTab('apikey')">API Key</button>
    <button class="tab" data-tab="oauth" onclick="switchTab('oauth')">OAuth</button>
  </div>

  <!-- API Key form -->
  <div class="section active" id="section-apikey">
    <label>Name (alias)
      <input id="ak-name" placeholder="e.g. openai-prod" />
    </label>
    <label>Provider
      <input id="ak-provider" placeholder="e.g. openai, stripe, custom" />
    </label>
    <label>Secret value
      <textarea id="ak-value" rows="3" placeholder="sk-…"></textarea>
    </label>
    <label>Base URL (optional — leave blank for vault-only)
      <input id="ak-baseurl" placeholder="https://api.openai.com/v1" />
    </label>
    <label>Tags (comma-separated, optional)
      <input id="ak-tags" placeholder="prod, gpt-4" />
    </label>
  </div>

  <!-- OAuth form -->
  <div class="section" id="section-oauth">
    <label>Name (alias)
      <input id="oa-name" placeholder="e.g. Google - MyApp" />
    </label>
    <label>Provider
      <input id="oa-provider" placeholder="e.g. google-oauth, github-oauth" />
    </label>
    <label>Client ID
      <input id="oa-clientid" />
    </label>
    <label>Client Secret
      <textarea id="oa-secret" rows="2"></textarea>
    </label>
    <label>Refresh Token (optional)
      <textarea id="oa-refresh" rows="2"></textarea>
    </label>
    <label>Authorize URL
      <input id="oa-authurl" placeholder="https://accounts.google.com/o/oauth2/v2/auth" />
    </label>
    <label>Token URL
      <input id="oa-tokenurl" placeholder="https://oauth2.googleapis.com/token" />
    </label>
    <label>Scopes (space-separated)
      <input id="oa-scopes" placeholder="openid email profile" />
    </label>
    <label>Redirect URI
      <input id="oa-redirect" />
    </label>
  </div>

  <button class="primary" id="btn-store" onclick="doStore()">Store</button>
  <div class="status" id="status"></div>

  <script>
    const vscode = acquireVsCodeApi();
    let activeTab = 'apikey';

    function switchTab(tab) {
      activeTab = tab;
      document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
      document.querySelectorAll('.section').forEach(s => s.classList.toggle('active', s.id === 'section-' + tab));
    }

    function doStore() {
      const btn = document.getElementById('btn-store');
      const status = document.getElementById('status');
      btn.disabled = true;
      status.textContent = 'Storing…';
      status.className = 'status';

      let payload;
      if (activeTab === 'apikey') {
        payload = {
          name: document.getElementById('ak-name').value.trim(),
          provider: document.getElementById('ak-provider').value.trim() || 'custom',
          key: document.getElementById('ak-value').value,
          base_url: document.getElementById('ak-baseurl').value.trim(),
          tags: document.getElementById('ak-tags').value.trim(),
        };
        if (!payload.name || !payload.key) {
          status.textContent = 'Name and secret value are required.';
          status.className = 'status error';
          btn.disabled = false;
          return;
        }
      } else {
        payload = {
          name: document.getElementById('oa-name').value.trim(),
          provider: document.getElementById('oa-provider').value.trim() || 'custom-oauth',
          credential_type: 'oauth2',
          client_id: document.getElementById('oa-clientid').value.trim(),
          client_secret: document.getElementById('oa-secret').value.trim(),
          refresh_token: document.getElementById('oa-refresh').value.trim() || undefined,
          authorize_url: document.getElementById('oa-authurl').value.trim(),
          token_url: document.getElementById('oa-tokenurl').value.trim(),
          scopes: document.getElementById('oa-scopes').value.trim(),
          redirect_uri: document.getElementById('oa-redirect').value.trim(),
        };
        if (!payload.name || !payload.client_id || !payload.client_secret) {
          status.textContent = 'Name, client ID, and client secret are required.';
          status.className = 'status error';
          btn.disabled = false;
          return;
        }
      }

      vscode.postMessage({ type: 'store', payload });
    }

    window.addEventListener('message', (e) => {
      const msg = e.data;
      const btn = document.getElementById('btn-store');
      const status = document.getElementById('status');
      btn.disabled = false;
      if (msg.type === 'success') {
        status.textContent = 'Stored successfully!';
        status.className = 'status success';
      } else if (msg.type === 'error') {
        status.textContent = msg.message;
        status.className = 'status error';
      }
    });
  </script>
</body>
</html>`;
  }
}
