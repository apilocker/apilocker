import * as vscode from 'vscode';
import { KeysTreeProvider } from './keys-tree';
import { ActivityTreeProvider } from './activity-tree';
import { TokensTreeProvider, TokenItem } from './tokens-tree';
import { DevicesTreeProvider, DeviceItem } from './devices-tree';
import { HealthTreeProvider } from './health-tree';
import { registerCommands } from './commands';
import { registerStoreCommand } from './webview/store-key';
import {
  listKeys,
  createToken,
  pauseToken,
  resumeToken,
  revokeToken,
  revokeDevice,
} from './api';

export function activate(context: vscode.ExtensionContext): void {
  const keysTree = new KeysTreeProvider();
  const activityTree = new ActivityTreeProvider();
  const tokensTree = new TokensTreeProvider();
  const devicesTree = new DevicesTreeProvider();
  const healthTree = new HealthTreeProvider();

  vscode.window.registerTreeDataProvider('apilocker.keys', keysTree);
  vscode.window.registerTreeDataProvider('apilocker.activity', activityTree);
  vscode.window.registerTreeDataProvider('apilocker.tokens', tokensTree);
  vscode.window.registerTreeDataProvider('apilocker.devices', devicesTree);
  vscode.window.registerTreeDataProvider('apilocker.health', healthTree);

  registerCommands(context, keysTree);
  registerStoreCommand(context, keysTree);

  // ── Activity ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.refreshActivity', () => {
      activityTree.refresh();
    }),
  );

  // ── Tokens ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.refreshTokens', () => {
      tokensTree.refresh();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.createToken', async () => {
      // 1. Token name
      const name = await vscode.window.showInputBox({
        prompt: 'Token name',
        placeHolder: 'e.g. my-app-prod',
        ignoreFocusOut: true,
      });
      if (!name) return;

      // 2. Pick rotation type
      const rotation = await vscode.window.showQuickPick(
        ['daily', 'hourly', 'weekly', 'monthly', 'static'],
        { placeHolder: 'Rotation schedule (default: daily)', ignoreFocusOut: true },
      );
      if (!rotation) return;

      // 3. Pick which keys this token can access
      let keys: { label: string }[];
      try {
        const allKeys = await listKeys();
        keys = allKeys.map((k) => ({ label: k.name }));
      } catch (err: any) {
        vscode.window.showErrorMessage(`Failed to load keys: ${err.message}`);
        return;
      }
      if (keys.length === 0) {
        vscode.window.showWarningMessage('No credentials in your vault. Store one first.');
        return;
      }
      const selected = await vscode.window.showQuickPick(keys, {
        canPickMany: true,
        placeHolder: 'Select which credentials this token can access',
        ignoreFocusOut: true,
      });
      if (!selected || selected.length === 0) return;

      // 4. Create
      try {
        const result = await createToken(name, selected.map((s) => s.label), rotation);
        tokensTree.refresh();

        // Show the token — this is the only time the user sees it
        const output = vscode.window.createOutputChannel('API Locker');
        output.clear();
        output.appendLine('New Scoped Token Created');
        output.appendLine('─'.repeat(40));
        output.appendLine(`Name:         ${result.name}`);
        output.appendLine(`Rotation:     ${result.rotation_type}`);
        output.appendLine(`Access Token: ${result.access_token}`);
        if (result.refresh_token) {
          output.appendLine(`Refresh Token: ${result.refresh_token}`);
        }
        if (result.access_token_expires_at) {
          output.appendLine(`Expires:      ${new Date(result.access_token_expires_at).toLocaleString()}`);
        }
        output.appendLine('');
        output.appendLine('Copy these now — they will not be shown again.');
        output.show();

        vscode.window.showInformationMessage(`Token "${name}" created. See Output panel for the token value.`);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Create failed: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.pauseToken', async (item: unknown) => {
      if (!(item instanceof TokenItem)) return;
      try {
        await pauseToken(item.token.id);
        vscode.window.showInformationMessage(`Paused token "${item.token.name}".`);
        tokensTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Pause failed: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.resumeToken', async (item: unknown) => {
      if (!(item instanceof TokenItem)) return;
      try {
        await resumeToken(item.token.id);
        vscode.window.showInformationMessage(`Resumed token "${item.token.name}".`);
        tokensTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Resume failed: ${err.message}`);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.revokeToken', async (item: unknown) => {
      if (!(item instanceof TokenItem)) return;
      const confirm = await vscode.window.showWarningMessage(
        `Revoke token "${item.token.name}" permanently? Apps using this token will stop working.`,
        { modal: true },
        'Revoke',
      );
      if (confirm !== 'Revoke') return;
      try {
        await revokeToken(item.token.id);
        vscode.window.showInformationMessage(`Revoked token "${item.token.name}".`);
        tokensTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Revoke failed: ${err.message}`);
      }
    }),
  );

  // ── Vault Health ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.refreshHealth', () => {
      healthTree.refresh();
    }),
  );

  // ── Devices ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.refreshDevices', () => {
      devicesTree.refresh();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.revokeDevice', async (item: unknown) => {
      if (!(item instanceof DeviceItem)) return;
      const confirm = await vscode.window.showWarningMessage(
        `Revoke device "${item.device.name}"? It will need to re-register.`,
        { modal: true },
        'Revoke',
      );
      if (confirm !== 'Revoke') return;
      try {
        await revokeDevice(item.device.id);
        vscode.window.showInformationMessage(`Revoked device "${item.device.name}".`);
        devicesTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Revoke failed: ${err.message}`);
      }
    }),
  );
}

export function deactivate(): void {}
