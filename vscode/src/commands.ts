import * as vscode from 'vscode';
import {
  revealKey,
  rotateKey,
  renameKey,
  pauseKey,
  resumeKey,
  deleteKey,
  runDoctor,
  RevealedKey,
} from './api';
import { KeyItem, KeysTreeProvider } from './keys-tree';

function requireKeyItem(item: unknown): KeyItem {
  if (!(item instanceof KeyItem)) {
    throw new Error('This command must be run from a credential in the sidebar.');
  }
  return item;
}

export function registerCommands(
  context: vscode.ExtensionContext,
  keysTree: KeysTreeProvider,
): void {

  // ── Refresh ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.refreshKeys', () => {
      keysTree.refresh();
    }),
  );

  // ── Reveal ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.revealKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      try {
        const result = await revealKey(keyItem.key.name);
        if (!result) {
          vscode.window.showWarningMessage(`Key "${keyItem.key.name}" not found in vault.`);
          return;
        }
        showRevealResult(keyItem.key.name, result);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Reveal failed: ${err.message}`);
      }
    }),
  );

  // ── Copy to clipboard ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.copyKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      try {
        const result = await revealKey(keyItem.key.name);
        if (!result) {
          vscode.window.showWarningMessage(`Key "${keyItem.key.name}" not found in vault.`);
          return;
        }
        const text =
          result.credential_type === 'oauth2' && result.fields
            ? JSON.stringify(result.fields, null, 2)
            : result.value ?? '';
        await vscode.env.clipboard.writeText(text);
        vscode.window.showInformationMessage(`Copied ${keyItem.key.name} to clipboard.`);
      } catch (err: any) {
        vscode.window.showErrorMessage(`Copy failed: ${err.message}`);
      }
    }),
  );

  // ── Rotate ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.rotateKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      const newValue = await vscode.window.showInputBox({
        prompt: `New secret value for "${keyItem.key.name}"`,
        password: true,
        placeHolder: 'Paste new secret…',
        ignoreFocusOut: true,
      });
      if (!newValue) return;

      try {
        await rotateKey(keyItem.key.id, newValue);
        vscode.window.showInformationMessage(`Rotated ${keyItem.key.name}.`);
        keysTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Rotate failed: ${err.message}`);
      }
    }),
  );

  // ── Rename ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.renameKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      const newName = await vscode.window.showInputBox({
        prompt: `New name for "${keyItem.key.name}"`,
        value: keyItem.key.name,
        ignoreFocusOut: true,
      });
      if (!newName || newName === keyItem.key.name) return;

      try {
        await renameKey(keyItem.key.id, newName);
        vscode.window.showInformationMessage(`Renamed to ${newName}.`);
        keysTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Rename failed: ${err.message}`);
      }
    }),
  );

  // ── Pause ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.pauseKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      try {
        await pauseKey(keyItem.key.id);
        vscode.window.showInformationMessage(`Paused ${keyItem.key.name}.`);
        keysTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Pause failed: ${err.message}`);
      }
    }),
  );

  // ── Resume ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.resumeKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      try {
        await resumeKey(keyItem.key.id);
        vscode.window.showInformationMessage(`Resumed ${keyItem.key.name}.`);
        keysTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Resume failed: ${err.message}`);
      }
    }),
  );

  // ── Delete ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.deleteKey', async (item: unknown) => {
      const keyItem = requireKeyItem(item);
      const confirm = await vscode.window.showWarningMessage(
        `Delete "${keyItem.key.name}" permanently?`,
        { modal: true },
        'Delete',
      );
      if (confirm !== 'Delete') return;

      try {
        await deleteKey(keyItem.key.id);
        vscode.window.showInformationMessage(`Deleted ${keyItem.key.name}.`);
        keysTree.refresh();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Delete failed: ${err.message}`);
      }
    }),
  );

  // ── Open dashboard ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.openDashboard', () => {
      vscode.env.openExternal(vscode.Uri.parse('https://www.apilocker.app/dashboard'));
    }),
  );

  // ── Setup help (shown when not configured) ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.openSetupHelp', async () => {
      const choice = await vscode.window.showInformationMessage(
        'Install the API Locker CLI and run `apilocker register` to connect your vault.',
        'Install CLI',
        'Open Docs',
      );
      if (choice === 'Install CLI') {
        const terminal = vscode.window.createTerminal('API Locker');
        terminal.show();
        terminal.sendText('npm install -g apilocker && apilocker register');
      } else if (choice === 'Open Docs') {
        vscode.env.openExternal(vscode.Uri.parse('https://www.apilocker.app'));
      }
    }),
  );

  // ── Doctor ──
  context.subscriptions.push(
    vscode.commands.registerCommand('apilocker.runDoctor', async () => {
      try {
        const result = await runDoctor();
        const output = vscode.window.createOutputChannel('API Locker');
        output.clear();
        output.appendLine('API Locker — Doctor Report');
        output.appendLine('─'.repeat(40));
        output.appendLine(JSON.stringify(result, null, 2));
        output.show();
      } catch (err: any) {
        vscode.window.showErrorMessage(`Doctor failed: ${err.message}`);
      }
    }),
  );
}

// ── Reveal display ──

function showRevealResult(name: string, result: RevealedKey): void {
  const output = vscode.window.createOutputChannel('API Locker');
  output.clear();
  output.appendLine(`🔓 ${name}`);
  output.appendLine('─'.repeat(40));

  if (result.credential_type === 'oauth2' && result.fields) {
    for (const [field, value] of Object.entries(result.fields)) {
      output.appendLine(`${field}: ${value}`);
    }
    if (result.env_names) {
      output.appendLine('');
      output.appendLine('Environment variables:');
      for (const [field, envName] of Object.entries(result.env_names)) {
        output.appendLine(`  ${envName}=${result.fields[field] ?? ''}`);
      }
    }
  } else if (result.value) {
    output.appendLine(result.value);
  }

  output.show();
}
