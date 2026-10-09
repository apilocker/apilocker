# API Locker for Claude

[API Locker](https://www.apilocker.app) is an encrypted vault for the credentials your projects depend on: LLM API keys, service API keys, and OAuth client credentials. This plugin connects Claude to your vault and teaches it to keep secrets out of your code, your `.env` files, and the conversation.

With the plugin installed, Claude can:

- Check which credentials you already have before asking you for one
- Store a key you paste into the vault instead of writing it into a file
- Set up your project so keys are injected at runtime with `apilocker run`
- Call a provider's API with a stored key without the raw key ever entering the conversation
- Walk you through freezing and rotating a leaked key, then review what used it
- Audit the vault for stale keys, unused keys, expiring tokens, and old devices

## What's included

**MCP connector.** The plugin adds API Locker's remote MCP server at `https://api.apilocker.app/v1/mcp`, with 25 tools for listing, storing, rotating, pausing, and auditing credentials, managing scoped tokens and devices, and proxying API calls. Read-only tools, including `proxy_get`, are marked read-only. Every tool that changes your vault or sends a write request to an external API is marked destructive, so Claude asks before running it. The full tool list is in the [MCP docs](https://www.apilocker.app/docs/mcp).

**Skills.**

| Skill | Use it when |
| --- | --- |
| `vault-first-secrets` | A task involves adding, using, or sharing an API key or other secret |
| `rotate-leaked-credential` | A key, token, or device may be compromised |
| `vault-health-check` | You want to audit or clean up your vault |

## Setup

1. Install the plugin.
2. The first time Claude uses an API Locker tool, it opens API Locker's sign-in page. Sign in with GitHub or Google (an account is created on first sign-in) and approve access. The consent screen lists the three scopes: `vault:read`, `vault:write`, and `vault:proxy`.
3. Optional, for running your own code with vault secrets: install the CLI with `npm install -g apilocker` and run `apilocker register`. The skills use `apilocker run`, `apilocker env`, `apilocker init`, and `apilocker import` when they're available.

You can disconnect Claude at any time from the [dashboard](https://www.apilocker.app/dashboard), or find the connection with `apilocker oauth grants list` and remove it with `apilocker oauth grants revoke <id>`.

## What the plugin runs, sends, and fetches

- The plugin runs no local code, hooks, or scripts. It contains an MCP server reference and three skill files.
- Every MCP tool call goes over HTTPS to `https://api.apilocker.app/v1/mcp`, authenticated with the OAuth token from setup. Only the tool's arguments are sent, never the rest of the conversation.
- Secrets you store are encrypted with AES-256-GCM before they're written to storage.
- The proxy tools (`proxy_get`, `proxy_post`, `proxy_put`, `proxy_patch`, `proxy_delete`) send your request to the provider the credential belongs to, such as the OpenAI or GitHub API. API Locker adds the stored key on its server, so the raw key isn't returned to Claude. Through these tools, payment APIs such as Stripe are read-only, and AI image, video, and audio generation and purchase endpoints are refused.
- `reveal_key` returns a raw secret value. The skills only call it when you explicitly ask to see a value.
- Every reveal, rotation, and proxied call is recorded in your vault's audit log, which only you can see.

## Privacy and support

- Privacy policy: https://www.apilocker.app/privacy
- Terms of service: https://www.apilocker.app/terms
- Support: support@apilocker.app or [GitHub Issues](https://github.com/apilocker/apilocker/issues)
- Security reports: security@apilocker.app

## License

MIT. See [LICENSE](LICENSE).
