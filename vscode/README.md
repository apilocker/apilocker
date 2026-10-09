# API Locker for VS Code

Manage your encrypted credential vault directly from the editor. Store, reveal, rotate, and proxy API keys, service credentials, and OAuth secrets — without leaving your IDE.

**Works in VS Code, Cursor, Windsurf, and any VS Code fork.**

## Features

### Credential Management

Browse your vault organized by category — **LLM API Keys**, **Service API Keys**, and **OAuth Credentials**. Right-click any credential to reveal, copy, rotate, rename, pause/resume, or delete it.

- **Store** new API keys or OAuth credentials with the + button
- **Reveal** secrets in a secure output panel
- **Copy** values to clipboard with one click
- **Rotate** secrets in-place with full audit trail
- **Rename** credentials with lossless alias fallback
- **Pause/Resume** keys without deleting them

### Scoped Tokens

Create and manage scoped access tokens that limit which credentials an app can use. Choose rotation schedules (hourly, daily, weekly, monthly, or static) and select exactly which keys each token can access.

### Device Management

See every device registered to your vault — hostname, platform, CLI version, and last activity. Revoke access to any device instantly.

### Vault Health

Built-in security health check that flags:
- Keys not rotated in 90+ days
- Credentials with no activity in 30+ days
- Stale devices not seen in 60+ days
- Paused credentials you may have forgotten about
- Tokens with reuse detection (possible compromise)

### Activity Feed

Live audit log showing every reveal, proxy call, rotation, and management action across your vault.

## Getting Started

1. **Install the CLI**

   ```
   npm install -g apilocker
   ```

2. **Register your device**

   ```
   apilocker register
   ```

   This opens your browser to authenticate and links your device to your vault.

3. **Open the sidebar**

   Click the lock icon in the activity bar, or run `API Locker: Focus on Credentials View` from the Command Palette.

Your vault loads automatically — every credential, token, and device you've set up via the CLI or web dashboard appears instantly.

## Commands

All commands are available from the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---------|-------------|
| API Locker: Store Credential | Add a new API key or OAuth credential |
| API Locker: Reveal | Decrypt and display a secret |
| API Locker: Copy to Clipboard | Copy a secret value |
| API Locker: Rotate Secret | Replace a secret with a new value |
| API Locker: Rename | Rename a credential alias |
| API Locker: Pause / Resume | Temporarily disable or re-enable a key |
| API Locker: Delete | Permanently remove a credential |
| API Locker: Create Token | Create a new scoped access token |
| API Locker: Run Doctor | Run a vault security health check |
| API Locker: Open Dashboard | Open the web dashboard |

## How It Works

The extension reads your device credentials from `~/.apilocker/config.json` (the same file the CLI writes during `apilocker register`) and calls the API Locker backend directly. No secrets are stored by the extension — everything lives in the encrypted vault.

This extension is a **visual companion** to the [API Locker CLI](https://www.npmjs.com/package/apilocker) and [MCP server](https://www.apilocker.app/docs/mcp). The CLI gives you terminal workflows (`apilocker run`, `apilocker env`), the MCP server gives AI agents tool access, and this extension gives you a GUI — all backed by the same vault.

## Links

- [Website](https://www.apilocker.app)
- [Dashboard](https://www.apilocker.app/dashboard)
- [CLI on npm](https://www.npmjs.com/package/apilocker)
- [MCP Docs](https://www.apilocker.app/docs/mcp)
- [GitHub](https://github.com/apilocker/apilocker)

## License

MIT
