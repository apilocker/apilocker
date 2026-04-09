# API Locker

> **One vault, three types of credentials.** LLM API keys, service API keys, and OAuth credentials — all encrypted, all injectable into your code with a single command.

API Locker replaces the `.env` file with one encrypted vault. Store your OpenAI key, your Stripe secret, your Google OAuth client — all in one place — and inject them into any command with `apilocker run -- npm start`. Your raw credentials never touch disk, never live in shell history, never get committed to git.

This is the command-line interface. [Website](https://www.apilocker.app) · [Dashboard](https://www.apilocker.app/dashboard)

## Install

```bash
npm install -g apilocker
```

Requires Node.js 18 or newer.

## Get started in three commands

```bash
# 1. Install the CLI (above)

# 2. Register this device — opens your browser for a one-click confirmation
apilocker register

# 3. Run any command with your vault secrets injected as env vars
apilocker run -- npm start
```

That's it. Your `process.env.OPENAI_API_KEY`, `process.env.STRIPE_SECRET_KEY`, `process.env.GOOGLE_OAUTH_CLIENT_SECRET` — everything you'd normally drop in a `.env` file — is now injected into the subprocess for exactly the duration of that command. When the command exits, the secrets are gone.

## One vault, three types of credentials

### 🧠 LLM API Keys
OpenAI, Anthropic, Gemini, Groq, Mistral.

```bash
apilocker store --name OPENAI_API_KEY --provider openai --key sk-proj-xxxxx
apilocker run -- node my-ai-app.js
```

### ⚡ Service API Keys
Stripe, Twilio, Resend, ElevenLabs, Cloudflare, GitHub, Clerk, Sentry, PostHog, Cloudinary, Mux, SendGrid, Vercel, Upstash, LemonSqueezy — plus custom for anything else.

```bash
apilocker store --name STRIPE_SECRET_KEY --provider stripe --key sk_live_xxxxx
apilocker run -- npm start
```

### 🔗 OAuth Credentials
Google, GitHub, Slack, Microsoft, Notion, Spotify, Twitter/X, LinkedIn, Discord, Zoom, Dropbox, Salesforce, HubSpot — plus custom OAuth for anything else.

```bash
apilocker store --oauth \
  --name google-oauth \
  --provider google-oauth \
  --client-id 856449...apps.googleusercontent.com \
  --client-secret GOCSPX-xxxxx \
  --scopes "openid email profile"

# Injects GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, etc.
apilocker run -- node oauth-app.js
```

## The full command set

| Command | What it does |
|---|---|
| `apilocker register` | Register this device via browser confirmation. No pasted tokens. |
| `apilocker store` | Store a credential. `--oauth` for multi-field OAuth, otherwise `--key`. |
| `apilocker list` | List credentials grouped into LLM / Service / OAuth buckets. Filter with `--tag`, `--provider`, `--category`, `--search`. |
| `apilocker run -- <cmd>` | Run any command with vault secrets injected as environment variables. |
| `apilocker get <alias>` | Print a single secret value to stdout (for scripting). `--field` for OAuth fields. |
| `apilocker env` | Emit shell-eval-able `export` statements. `eval "$(apilocker env)"` to load into current shell. |
| `apilocker init` | Pin specific keys to a project directory via a committable `.apilockerrc` file. |
| `apilocker import .env` | Migrate an existing `.env` file into the vault. Pattern-matches provider prefixes and offers to replace the `.env` with an `.apilockerrc`. |
| `apilocker rotate <alias>` | Replace a credential's value. Scoped tokens keep working; rotation is transparent to consumers. |
| `apilocker rename <old> <new>` | Rename a credential alias. **Lossless** — existing `.apilockerrc` files that reference the old name keep working via transparent fallback. |
| `apilocker pause <alias>` / `resume <alias>` | Freeze proxy access without deleting. Reveal / run / get / env still work on paused credentials. |
| `apilocker delete <keyId>` | Permanently delete a credential. |
| `apilocker devices list` / `revoke <id>` | Manage devices registered to your account. |
| `apilocker token create/list/pause/resume/delete` | Manage scoped access tokens for app/proxy use. |
| `apilocker activity` | View the audit log. Add `--follow` / `-f` to stream new events live. |
| `apilocker doctor` | Security health check: stale rotations, unused keys, expiring tokens, local config permissions. |
| `apilocker update` | Check npm for a newer version. |

## The `.apilockerrc` file

Pin a project to a specific set of credentials with a committable config file. `apilocker init` walks you through creating one:

```yaml
# .apilockerrc — safe to commit to git, contains only pointers
keys:
  - OPENAI_API_KEY
  - STRIPE_SECRET_KEY
  - google-oauth
```

After `apilocker init`, anyone cloning your repo who runs `apilocker run -- npm start` gets the same env vars — assuming they have access to those aliases in their own vault. It's like a `package.json` for credentials: the file declares what the project needs, each developer has their own vault.

## Why the CLI doesn't ask for a pasted master token

Unlike most developer tools, `apilocker register` doesn't want you to paste a secret from the dashboard. Instead:

1. You run `apilocker register`
2. Your browser opens to a single-card confirmation page
3. You click "Authorize"
4. The CLI receives a per-device master token over an authenticated polling channel — it never touches your clipboard, shell history, or screen

This is the RFC 8628 device authorization flow (the same pattern `gh`, `vercel`, `wrangler`, `flyctl`, and `gcloud` use). It's strictly safer than pasted tokens because the secret never appears anywhere a human can accidentally leak it.

New users? The same flow handles signup — your first OAuth click with GitHub/Google creates the account automatically. No separate visit to the web portal required.

## MCP integration — connect your AI assistant

API Locker exposes a full **Model Context Protocol** server with 21 tools so Claude Code, Claude Desktop, Cursor, Zed, Continue, and any other MCP-compatible client can read and manage your vault directly.

### Claude Code — one command

```bash
claude mcp add apilocker -- apilocker mcp
```

Verify with `claude mcp list`. You should see `apilocker: apilocker mcp - ✓ Connected`. The server is available in your next Claude Code session automatically.

### Claude Desktop, Cursor, Zed, Continue

The CLI ships with `apilocker mcp` — a stdio bridge that handles the connection automatically. Configure any MCP client with:

```json
{
  "mcpServers": {
    "apilocker": {
      "command": "apilocker",
      "args": ["mcp"]
    }
  }
}
```

The bridge reads your master token from `~/.apilocker/config.json` automatically. No credentials go in the client config itself.

**Print client-specific config** with the built-in helper:

```bash
apilocker mcp config --client claude-desktop   # or claude-code, cursor, continue, zed, generic
```

**Full docs:** https://www.apilocker.app/docs/mcp — includes config file locations for each client, troubleshooting, and the full 21-tool catalog.

**Visual status:** the dashboard has a dedicated MCP panel at https://www.apilocker.app/dashboard#mcp showing server status, a test-connection button, copy-pasteable config for every major client, and a live feed of recent MCP activity.

## Security posture

- **AES-256-GCM** encryption on every stored credential. Keys never leave the vault in plaintext except when revealed to an authenticated master-token holder (you).
- **Per-device tokens** with independent revocation. Stolen a laptop? Revoke that one device; every other device keeps working.
- **OAuth CSRF protection** with state tokens bound to a 10-minute KV window.
- **Strict file permissions** (`0600`) on `~/.apilocker/config.json`.
- **Audit-logged everywhere**: every reveal, every proxy call, every rename, every rotation. Watch them live with `apilocker activity --follow`.
- **Lossless rename with previous_names fallback**: renaming a credential never breaks existing code. Old aliases transparently resolve to the current credential with a gentle nudge to update configs.
- **Pause/resume** to freeze proxy access during incident response without losing the credential itself.

## Configuration

Config lives at `~/.apilocker/config.json` (mode `0600`). Don't check it in.

Override the API endpoint for self-hosted deployments:

```bash
apilocker register --url https://api.your-locker.example.com
```

## Status

API Locker is in **public beta**. Free forever during beta with unlimited keys, unlimited tokens, and unlimited proxy calls. Beta users get grandfathered into free Pro permanently when pricing kicks in.

## Links

- **Website:** [www.apilocker.app](https://www.apilocker.app)
- **Dashboard:** [www.apilocker.app/dashboard](https://www.apilocker.app/dashboard)
- **API:** [api.apilocker.app](https://api.apilocker.app)
- **Changelog:** [www.apilocker.app/changelog](https://www.apilocker.app/changelog)

## License

MIT © 2026 API Locker
