<div align="center">

<img src="https://www.apilocker.app/brand/logo-256.png?v=2" alt="API Locker mascot" width="180" height="180" />

# API Locker

**One vault, three types of credentials. Replace your `.env` file with one token.**

[![npm](https://img.shields.io/npm/v/apilocker?color=0ea5e9&label=npm)](https://www.npmjs.com/package/apilocker)
[![license](https://img.shields.io/badge/license-MIT-0ea5e9)](./LICENSE)
[![website](https://img.shields.io/badge/website-apilocker.app-0ea5e9)](https://www.apilocker.app)
[![mcp](https://img.shields.io/badge/MCP-compatible-10b981)](https://www.apilocker.app/docs/mcp)

</div>

API Locker is an encrypted credential vault for developers. Store your LLM API keys, service API keys, and OAuth credentials in one place — then inject them into any command with `apilocker run -- npm start`. Your raw credentials never touch disk, never live in shell history, never get committed to git.

Free public beta. [Try it →](https://www.apilocker.app)

---

## What it does

```bash
# Install
npm install -g apilocker

# One-click browser confirmation — no pasted tokens
apilocker register

# Store a credential (for any of 34 provider templates, plus "custom")
apilocker store --name OPENAI_API_KEY --provider openai --key sk-proj-...

# Run any command with your vault secrets injected as env vars
apilocker run -- npm start
#  ↑
#  process.env.OPENAI_API_KEY is populated for the lifetime of this command,
#  then gone. No .env file. Nothing on disk. Nothing in shell history.
```

That's the whole pitch. Everything else in this repo is making that flow work for every kind of credential a developer has to deal with.

## One vault, three types of credentials

API Locker distinguishes three credential types because they're used differently:

<table>
<tr>
<td width="33%" valign="top">

### 🧠 LLM API Keys
Single opaque tokens for model APIs.

OpenAI, Anthropic, Gemini, Groq, Mistral.

```bash
apilocker store --name OPENAI_API_KEY \
  --provider openai \
  --key sk-proj-xxxxx
```

</td>
<td width="33%" valign="top">

### ⚡ Service API Keys
Single tokens for everyday SaaS.

Stripe, Twilio, Resend, ElevenLabs, Cloudflare, GitHub, Clerk, Sentry, PostHog, Cloudinary, Mux, SendGrid, Vercel, Upstash, LemonSqueezy.

```bash
apilocker store --name STRIPE_SECRET_KEY \
  --provider stripe \
  --key sk_live_xxxxx
```

</td>
<td width="33%" valign="top">

### 🔗 OAuth Credentials
Multi-field credentials for sign-in flows.

Google, GitHub, Slack, Microsoft, Notion, Spotify, Twitter/X, LinkedIn, Discord, Zoom, Dropbox, Salesforce, HubSpot.

```bash
apilocker store --oauth \
  --name google-oauth \
  --provider google-oauth \
  --client-id ... \
  --client-secret ...
```

</td>
</tr>
</table>

Under the hood, LLM and Service credentials share the same single-string encrypted storage. OAuth is a multi-field encrypted JSON blob. Users experience three product surfaces; implementation shares one foundation.

## Why not just use `.env` files?

| Problem | `.env` file | API Locker |
|---|---|---|
| Secrets on disk | ✅ (plaintext) | ❌ (encrypted, AES-256-GCM) |
| Secrets in git history if misconfigured | ✅ | ❌ |
| Secrets in shell history when debugging | ✅ | ❌ |
| Sharing across machines | Manual copy-paste | ✅ (one `apilocker register` per device) |
| Rotation | Manual edit in every copy | One dashboard click |
| Audit log of who accessed what | ❌ | ✅ (every reveal + proxy call) |
| Revocation of a specific device | Nuke every local copy | One `apilocker devices revoke` |
| AI agent access (Claude, Cursor, etc.) | "Paste this into Cursor settings" | Native MCP integration |

## Features

- **Encrypted vault** — AES-256-GCM on every stored credential. Keys never leave the vault in plaintext except when explicitly revealed to an authenticated master-token holder.
- **Runtime injection** — `apilocker run -- cmd` injects your vault secrets as env vars for the duration of one command, then clears them.
- **Smart proxy** — `POST /v1/proxy/:keyId` forwards authenticated calls upstream (Stripe, OpenAI, etc.) with the raw key injected server-side. Your app code never sees the secret.
- **Scoped tokens with rotation** — OAuth2 refresh-token flow with reuse detection. Static, hourly, daily, weekly, monthly rotation cadences. Scoped tokens can only call a pre-approved subset of keys.
- **Per-device master tokens** — RFC 8628 device authorization flow. Each machine gets its own token; revoke one without affecting others.
- **Lossless rename** — Renaming a credential never breaks existing `.apilockerrc` files. Old aliases transparently resolve via a `previous_names` fallback.
- **Pause / resume** — Freeze proxy access without losing the credential. Useful for incident response.
- **Audit logs** — Every reveal, every proxy call, every rotation, every rename logged with source IP, country, and timestamp. Stream live with `apilocker activity --follow`.
- **Vault health check** — `apilocker doctor` surfaces stale rotations, unused keys, expiring tokens, and local config permission issues.
- **Import from `.env`** — `apilocker import .env` migrates an existing project into the vault in one command.
- **First-class MCP server** — Works with Claude Code, Claude Desktop, Cursor, Zed, Continue, and any other MCP-compatible client. 21 tools give your AI agent the same surface as the CLI.

## Connect your AI assistant (MCP)

API Locker exposes a full [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents can read and manage your vault directly.

**Claude Code** (one command):
```bash
claude mcp add apilocker -- apilocker mcp
```

**Claude Desktop, Cursor, Zed, Continue** — use the `apilocker mcp` stdio bridge in your client's config:
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

**Full MCP docs with the 21-tool catalog and per-client setup instructions:** [apilocker.app/docs/mcp](https://www.apilocker.app/docs/mcp)

## Repository layout

This is a monorepo. The three surfaces are kept together because they share types, provider templates, and product conventions.

```
apilocker/
├── cli/         # The `apilocker` npm package (published as apilocker)
├── api/         # Cloudflare Worker backend (api.apilocker.app)
├── site/        # Marketing site + dashboard + docs (www.apilocker.app)
└── README.md    # You are here
```

- **[`cli/`](./cli)** — The published `apilocker` npm package. Built with Node 18+ and Commander. See [`cli/README.md`](./cli/README.md) for the full command reference.
- **[`api/`](./api)** — The Cloudflare Worker that powers everything: D1 for metadata, KV for encrypted blobs, a Durable Object for rate limiting, and a fully-featured MCP server at `/v1/mcp`.
- **[`site/`](./site)** — The static marketing site, the dashboard, the `/docs/mcp` integration guide, and a hidden admin analytics page.

## How it works (one minute)

1. **You register a device.** `apilocker register` opens your browser, you click Authorize once, the CLI writes a per-device master token to `~/.apilocker/config.json` (mode 0600).
2. **You store credentials via the CLI or dashboard.** Each credential is encrypted with AES-256-GCM and the ciphertext lives in Cloudflare KV. Only metadata (name, provider, tags, rotation status) lives in D1.
3. **Your app uses credentials in one of three ways:**
   - **Runtime injection:** `apilocker run -- npm start` reveals the needed credentials for one command and exports them as env vars.
   - **Proxy:** Your app holds a scoped token, calls `POST /v1/proxy/:keyId`, and the API Locker Worker injects the raw key into the upstream call server-side. Your app never sees the secret.
   - **AI agent:** An MCP-compatible client (Claude Code, Cursor, etc.) connects through the `apilocker mcp` stdio bridge and gets the same 21-tool surface as the CLI.
4. **Rotation, rename, pause, revoke are all one-click.** Credentials in use stay in use — scoped tokens are unaffected by rotation, `.apilockerrc` files are unaffected by rename, and revoking a device never touches any other device.

## Security posture

- **Per-credential AES-256-GCM encryption** with a unique IV per blob
- **Encryption key** lives as a Worker secret, never in source
- **Session cookies:** HttpOnly, Secure, SameSite=Lax, domain-scoped to `.apilocker.app`
- **CSRF protection** on all OAuth flows via single-use state tokens (10-minute TTL in KV)
- **RFC 8628 device authorization flow** for CLI sign-in — no pasted master tokens
- **Per-device master tokens** with independent revocation
- **Audit log on every access** — reveal, rotate, rename, pause, resume, proxy, MCP call
- **Rate limiting** via Cloudflare Durable Objects (TrafficMonitor)
- **Worker self-hosts its own OAuth secrets in its own vault** — vault is the source of truth even for the app's own sign-in credentials (meta-dogfooding)

## Status

**Free public beta.** Unlimited keys, unlimited tokens, unlimited proxy calls. Beta users get grandfathered into free Pro permanently when pricing kicks in.

- **CLI:** [v1.0.2](https://www.npmjs.com/package/apilocker) on npm
- **API:** live at `api.apilocker.app`
- **Dashboard:** live at `www.apilocker.app/dashboard`
- **Docs:** [`/docs/mcp`](https://www.apilocker.app/docs/mcp)
- **MCP Registry:** [`io.github.apilocker/apilocker`](https://registry.modelcontextprotocol.io)

## Contributing

Issues and PRs welcome. The repo is intentionally kept as a monorepo so a single PR can touch the CLI, API, and site in coordinated steps.

## Contact

The right address depends on what you want to talk about:

- **Bugs & reproducible issues:** [open a GitHub issue](https://github.com/apilocker/apilocker/issues)
- **Feature requests, ideas, advice, what's missing:** [feedback@apilocker.app](mailto:feedback@apilocker.app)
- **General support, account questions:** [support@apilocker.app](mailto:support@apilocker.app)
- **Security disclosures:** [security@apilocker.app](mailto:security@apilocker.app) — please don't open public issues for security findings
- **Privacy questions:** [privacy@apilocker.app](mailto:privacy@apilocker.app)

## License

[MIT](./LICENSE)
