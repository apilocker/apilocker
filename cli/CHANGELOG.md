# Changelog

All notable changes to the `apilocker` CLI are documented here.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] — 2026-04-09 — "MCP Registry publishing"

### Registry / discoverability

- **Published to the official MCP Registry** at `registry.modelcontextprotocol.io` under the namespace `io.github.apilocker/apilocker`. AI tools and MCP clients can now discover API Locker via the canonical registry.
- **Added `mcpName` field to `package.json`** — required by the MCP Registry's package ownership verification. No runtime impact; pure metadata.

No other changes. This is a metadata-only release to unlock registry publishing.

## [1.0.1] — 2026-04-09 — "Partial OAuth rotation + seamless vault-backed sign-in"

### CLI additions

- **`apilocker rotate <alias> --field <name>`** — partial rotation for OAuth credentials. You can now rotate just the `client_secret` or `refresh_token` field of an OAuth credential without touching `client_id`, `authorize_url`, `token_url`, `scopes`, or `redirect_uri`. The server decrypts the existing blob, merges the new field, re-encrypts, and bumps `rotated_at`. Scoped tokens keep working. Example:

  ```bash
  apilocker rotate "API Locker - Google" --field client_secret
  ```

  `--field` accepts `client_secret` or `refresh_token`. Passing `--field` to an `api_key`-type credential is rejected with a clear error.

### API additions (backend, CLI consumer)

- **`POST /v1/keys/:keyId/rotate`** now supports partial OAuth rotation. Body shape for `api_key` stays `{ key: "<new-value>" }`; for `oauth2` credentials the new body is `{ client_secret?: "...", refresh_token?: "..." }`. The response includes `rotated_fields` so the CLI and dashboard can show which fields changed.
- **Audit log format for OAuth rotations** now records which fields were swapped — e.g. `/rotate:client_secret` vs `/rotate:client_secret,refresh_token` — so the activity feed shows the exact scope of a rotation.

### Vault-backed OAuth sign-in (the big one)

- The API Worker now **reads its own Google and GitHub OAuth credentials from the vault at runtime**, via a new `src/vault-client.ts` helper that decrypts directly from KV + D1 with a 60s in-memory cache. This replaces the previous model of storing those credentials as wrangler-level secrets (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, etc.), which required a manual `wrangler secret put` after every rotation.
- After this change, rotating the Worker's own OAuth secrets is a one-paste operation: rotate in Google Cloud Console / GitHub, paste into the dashboard Rotate Secret modal, and production picks up the new value within 60 seconds. Zero manual sync. Zero shell pipes. Zero literal-vs-placeholder paste mistakes.
- **Dynamic OAuth sign-in provider registry** — new `src/oauth-providers.ts` file defines each supported provider (Google, GitHub, LinkedIn, Slack, Microsoft) with authorize URL, token URL, user-info URL, scopes, and user-info mapper. Routes `/v1/auth/:provider` and `/v1/auth/:provider/callback` are now generic — adding a new sign-in provider is (a) one object in `oauth-providers.ts`, (b) storing the credential in the vault under the matching `vault_key_name`, (c) deploy. No HTML edits anywhere — the login, signup, and CLI-auth pages all fetch `GET /v1/auth/providers` and render buttons dynamically.
- New discovery endpoint: **`GET /v1/auth/providers`** returns only the providers with a matching credential in the vault, so the login page never renders a broken button.

### Dashboard additions

- **Rotate Secret button on OAuth credential cards.** Previously OAuth cards only had Reveal. The new green rotate icon opens a modal with "New client secret" and optional "New refresh token" inputs, and submits a partial rotation via the new API endpoint. Other fields (client_id, authorize_url, etc.) are preserved untouched.
- **Dynamic login buttons.** `/login`, `/signup`, and `/cli-auth` pages now fetch `/v1/auth/providers` on load and render buttons dynamically. Old hardcoded Google/GitHub buttons removed.

### Packaging + repository

- **Monorepo on GitHub.** Source code now lives at https://github.com/apilocker/apilocker in a monorepo structure (`api/`, `cli/`, `site/`). `cli/package.json` `repository.url` updated to point at the monorepo with `directory: "cli"`. `homepage` and `bugs` links updated to the GitHub repo.
- **`apilocker get <alias> --field <name>`** is confirmed working for OAuth credentials — prints a single field value to stdout. Previously documented but users on stale CLI installs (<v1.0.0) saw "unknown option" errors; upgrading to v1.0.1 fixes it.

### Notes

- Wrangler secret cleanup: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` are no longer needed as wrangler secrets. They can be deleted (and already have been on production). The only Worker-level OAuth config is now `APILOCKER_SERVICE_USER_ID`, which identifies which vault user owns the sign-in credentials.

## [1.0.0] — 2026-04-08 — "One vault, three types of credentials"

### MCP server parity (the three-surface principle, honored)

- **MCP server now exposes 21 tools** mirroring the full CLI/dashboard capability set: `list_keys`, `get_key_metadata`, `reveal_key`, `list_providers`, `get_activity`, `run_doctor`, `proxy_request`, `store_key`, `store_oauth_credential`, `rotate_key`, `rename_key`, `pause_key`, `resume_key`, `delete_key`, `list_tokens`, `create_token`, `pause_token`, `resume_token`, `revoke_token`, `list_devices`, `revoke_device`. Every meaningful vault operation is now callable by AI agents via the Model Context Protocol.
- **Dual-token MCP auth**: scoped tokens still work for the existing `list_keys` and `proxy_request` (backwards compat) with their pre-approved key whitelist, AND master tokens can now be used for vault management operations. Write tools (store/rotate/rename/pause/delete/devices/tokens) require master-token auth and return a clear error if a scoped token is used.
- The three-surface parity principle is now fully honored: every feature exists in CLI, Dashboard, and MCP.

### Launch tracking analytics (admin dashboard)

- **`/v1/admin/metrics` endpoint** extended with seven new launch-tracking metric categories: onboarding funnel, time-to-value averages, DAU time series (last 30 days), weekly retention cohorts, three-pillar adoption percentages, activity heatmap (UTC, last 7 days), and geographic distribution.
- **`/admin` dashboard page** on the marketing site renders all the new sections with hand-rolled SVG charts (zero JS dependencies): funnel bars, sparkline DAU chart with gradient fill, colored pillar adoption bars, retention cohort grid with intensity-based coloring, 7×24 activity heatmap, geographic distribution with country flag emojis.
- **New `country` column on `audit_logs`** populated from Cloudflare's `CF-IPCountry` header on every audit event. Backwards-compatible (existing rows are NULL). Used by the geo distribution metric.

### Cleanup cron + admin gating

- **Hourly cron trigger** (`crons = ["0 * * * *"]` in wrangler.toml) runs a `scheduled()` handler that purges expired `device_codes` rows older than 24 hours. Prevents the table from accumulating stale OAuth-flow rows.
- **`ADMIN_USER_IDS` worker secret** (comma-separated list of allowed admin user IDs) gates the admin metrics endpoint. Non-admins see HTTP 404 (the endpoint pretends not to exist), not HTTP 403.

### Welcome modal + custom-OAuth UX polish

- **First-run welcome modal** on the dashboard introduces the three pillars (LLM / Service / OAuth) and shows the three-command CLI install flow. Dismissal tracked in `localStorage` under `apilocker_welcome_v1_seen`.
- **Custom-OAuth advanced fields** (authorize_url, token_url) now visible in the Add Key modal when "Custom OAuth" is selected. Hidden for known providers (where the backend auto-fills from the template).

### Backend bug fix found by ElevenLabs proxy verification

- **Fixed a CHECK constraint that would have silently broken ElevenLabs proxy support.** The `auth_header_type` constraint on `keys_metadata` only allowed `('bearer', 'x-api-key', 'basic', 'query')` and didn't include `'custom'`. Storing an ElevenLabs key (which uses `auth_header_type: 'custom'` to send the `xi-api-key` header) would have failed with a SQLite constraint error. Caught by the end-to-end proxy verification test and fixed via `schema_migration_auth_header_custom.sql` (table rebuild). The full proxy path is now verified end-to-end against httpbin.org — the `xi-api-key` header is correctly injected with the decrypted credential value.

### Marketing + docs

- **CLI README rewritten** for v1.0.0 with the three-pillar framing, full command table, security posture, and the new browser-based register flow. Updates on npmjs.com when the package is published.
- **Public `/changelog` page** at https://www.apilocker.app/changelog rendering the full release history with version badges and release taglines. Nav link added to the homepage.

### The 1.0.0 baseline

**This is the production release.** API Locker now supports three distinct credential types from a single vault: LLM API keys, service API keys, and OAuth credentials. Every existing CLI command continues to work unchanged.

### Added — OAuth credential support

- **New credential type: `oauth2`.** Store multi-field OAuth credentials (client_id, client_secret, refresh_token, authorize_url, token_url, scopes, redirect_uri) as a single named credential. All fields are encrypted together in KV with the same AES-GCM key that protects api_key credentials.
- **Six new OAuth provider templates** with pre-filled authorize/token URLs and default scopes:
  - **Google OAuth** (`google-oauth`) — Gmail, Drive, Calendar, YouTube
  - **GitHub OAuth App** (`github-oauth`) — repo/user access beyond personal tokens
  - **Slack OAuth** (`slack-oauth`) — bot tokens, webhook permissions
  - **Microsoft OAuth** (`microsoft-oauth`) — Graph API, Azure AD, Outlook
  - **Notion OAuth** (`notion-oauth`) — integration tokens for public integrations
  - **Custom OAuth** (`custom-oauth`) — catchall for anything else
- **`apilocker store --oauth`** — new mode flag that stores a multi-field OAuth credential. Requires `--client-id` and `--client-secret`. Optional: `--refresh-token`, `--authorize-url`, `--token-url`, `--scopes`, `--redirect-uri`.
- **`apilocker run` / `env` inject OAuth credentials as multiple env vars.** A credential named `google-oauth` contributes `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_REFRESH_TOKEN`, etc. — one env var per non-empty field, all with the same alias prefix.
- **`apilocker get <alias> --field <name>`** — extract a single OAuth field for scripting. Without `--field`, `get` on an OAuth credential returns the full field object as JSON.

### Added — vault management commands

- **`apilocker rename <old> <new>`** — **lossless rename**. The encrypted value and all metadata stay the same; scoped tokens referencing the key keep working because they bind by ID, not name. **Existing `.apilockerrc` files and app code that reference the old alias also keep working** — every rename appends the old name to a `previous_names` history on the row, and the reveal endpoint transparently falls back to that history when a direct name match fails. The CLI prints a gentle `ℹ` nudge to stderr each time a legacy alias is used, encouraging users to update their configs at their own pace. If you later store a new credential under an old name, the new credential cleanly reclaims it (name-recycling purges the alias from the old row's history automatically).
- **`apilocker pause <alias>`** — temporarily block proxy access without deleting the credential. Reveal / run / get / env continue to work, so you can still inspect and rotate the key while it's paused. The proxy returns HTTP 423 Locked with a clear message: `"Key <name> is paused. Run 'apilocker resume <name>' to reactivate."`
- **`apilocker resume <alias>`** — reactivate a paused credential.

### Added — ElevenLabs provider template

- **ElevenLabs** is now a first-class provider (category: service). Base URL, auth type, and the non-standard `xi-api-key` header are all pre-configured. Proxy support works out of the box.

### Added — custom header name support

- Provider templates now support an `auth_header_name` field for services that use non-standard header names. ElevenLabs uses this to send `xi-api-key` instead of `X-API-Key`. New `custom` auth header type for ad-hoc providers.

### Changed — three-bucket categorization

- Every provider template now has a **category**: `llm`, `service`, or `oauth`. The CLI `apilocker list` command groups credentials by category with three clearly labeled sections (LLM API Keys, Service API Keys, OAuth Credentials). The web dashboard does the same.
- **New `--category` filter** on `apilocker list` to show only credentials in one bucket.
- Five providers are classified as LLMs: OpenAI, Anthropic, Google AI (Gemini), Groq, Mistral. Fifteen are classified as services. Six are OAuth templates. "Custom" falls back to service.

### Changed — `base_url` is now optional

- **Vault-only credentials are now a first-class use case.** Storing a credential without a base URL puts it in the vault for retrieval via `apilocker run/get/env` only; it cannot be used via the proxy. Attempting to proxy a vault-only credential returns a clear error message explaining how to enable proxy access. This eliminates the friction where users would hit the old "base_url is required" error and pick a random provider template as a workaround.

### Changed — `apilocker list` output

- Now shows per-credential **TYPE** column (`key` vs `oauth`) and **STATUS** column (paused state).
- Three labeled sections: LLM API Keys, Service API Keys, OAuth Credentials.
- Empty categories are hidden from the output.

### Backend

- **New endpoint: `POST /v1/keys/:keyId/rename`** — session-authenticated. Validates the new name against the unique(user_id, name) constraint. Appends the old name to the row's `previous_names` history for lossless fallback. Purges the new name from any other row's `previous_names` to enforce name-recycling. Audit-logged.
- **New column: `keys_metadata.previous_names`** — JSON array of historical names per credential. Populated by the rename handler; queried by the reveal endpoint as a fallback when a direct name match fails. Migration is backwards-compatible: existing rows default to `'[]'`.
- **Reveal endpoint returns `deprecated_alias: true`** and `requested_as: "<old>"` when a credential was matched via its rename history. The env var name injected into `apilocker run` is derived from the REQUESTED alias (not the current name), so old `.apilockerrc` files and app code that expect the old env var continue to receive it unchanged.
- **New endpoint: `POST /v1/keys/:keyId/pause`** — session-authenticated. Sets `paused_at` on the metadata row.
- **New endpoint: `POST /v1/keys/:keyId/resume`** — session-authenticated. Clears `paused_at`.
- **Proxy handler refuses paused keys** with HTTP 423. Refuses OAuth credentials with a clear "use `apilocker run/get/env` instead" error (v1.0.0 does not proxy OAuth credentials; Level 2 OAuth orchestration is roadmap).
- **Proxy handler supports custom header names** declared on provider templates (used by ElevenLabs and any future provider with non-standard auth headers).
- **Store endpoint accepts `credential_type: 'oauth2'`** with OAuth field parameters. `base_url` is optional; missing or empty base URL means vault-only.
- **Reveal endpoint returns multi-field OAuth credentials** with per-field env var names.
- **Schema migration:** added `credential_type` and `paused_at` columns to `keys_metadata`. Migration is fully backwards-compatible — existing rows get `credential_type='api_key'` and `paused_at=NULL`.

### Compatibility

- Every 0.5.x CLI install continues to work unchanged. All existing endpoints keep the same shape; new fields are added but never removed. All existing credentials (api_key type, non-null base_url) are untouched by the migration. The CLI's validateMasterToken dual-path auth from v0.2.0 is also unchanged.

## [0.5.0] — 2026-04-08

### Added — the trust layer

This release turns API Locker from a storage product into a **security advisor**. Every command in this release is about giving you visibility into what's happening and surfacing things you should know before they become problems.

- **`apilocker doctor`** — run a security health report on your vault and surface actionable advice. Categories:
  - **Rotation hygiene:** flags credentials not rotated in 90+ days, with the exact key names and the number of days since last rotation.
  - **Unused keys:** cross-references your vault with the last 500 audit log entries and flags keys with no activity in the last 30 days (candidates for deletion). If there are fewer than 500 total audit entries, the check is fully reliable; if the lookback is truncated, the finding is downgraded to informational.
  - **Expiring scoped tokens:** notes any rotating tokens whose current access token expires in the next 48 hours. Usually handled automatically by rotation, but visible so you know.
  - **Stale devices:** flags devices with no activity in 60+ days and shows whether the stale device is the one you're currently using.
  - **Local config hygiene:** inspects `~/.apilocker/config.json` permissions and warns if group or other users can read it (your master token lives there).
  - Clean report with `⚠` for warnings, `ℹ` for informational findings, and `✓` for passing checks. Every warning comes with a concrete "run this to fix it" hint.

- **`apilocker activity --follow`** (alias: `-f`) — stream new proxy calls live as they happen, like `tail -f` for your audit log. Polls the existing `/v1/activity` endpoint every 2 seconds (configurable with `--interval`) and dedupes by log ID so you only see NEW activity after the command starts. Perfect for debugging during development: run `apilocker activity -f` in one terminal and your app in another and watch every call flow through the vault in real time. Filters (`--key`, `--token`) work in both snapshot and follow modes. Clean exit on Ctrl+C.

- **`apilocker update`** — check the npm registry for a newer version of the CLI and show you the exact upgrade command. Intentionally does NOT run `npm install -g apilocker@latest` itself — installing global packages from within a running global package is fragile and can leave you in a broken half-upgraded state. Shows current vs latest version, indicates whether you're up to date, and prints the upgrade command to copy-paste when you're ready.

### Changed

- **`apilocker activity`** now includes colorized status codes (green for 2xx, red for 4xx/5xx) and uses ISO timestamps instead of locale-formatted ones for consistency across machines. The old `--limit` flag now also accepts `-n`.

### Design notes

- All three commands are **purely client-side** — no new backend endpoints. Doctor calls `/v1/keys`, `/v1/tokens`, `/v1/devices`, and `/v1/activity` in parallel and computes findings locally. `--follow` polls the existing activity endpoint. `update` hits the public npm registry. This means anything you can do with doctor or follow, you could build yourself with the same existing APIs — no hidden server-side logic.

- The zero-dependency philosophy holds: no new npm deps introduced. All three commands use only Node stdlib and the existing `commander`.

## [0.4.0] — 2026-04-08

### Added — onboarding, organization, and hygiene

- **`apilocker import [file]`** — the "migrate an existing project in 30 seconds" command. Reads a `.env` file, pattern-matches each variable name against known provider prefixes (`OPENAI_*`, `STRIPE_*`, `ANTHROPIC_*`, etc.) to auto-detect providers, shows a preview table of what will be imported, then stores each credential in the vault with one API call each. Defaults to `./.env` but accepts any file path (e.g. `apilocker import .env.production`).
  - Handles collisions interactively — for each key that already exists in your vault, you can choose to **overwrite**, **skip**, or **rename**.
  - Supports `--yes` for non-interactive mode (CI, scripting). In non-interactive mode, collisions default to skip (safe).
  - Supports `--tag <t>` (repeatable) to apply one or more tags to every imported key at once.
  - After import, offers to **delete the original `.env` file and replace it with a committable `.apilockerrc`**. That moment — watching your `.env` disappear and a clean pointer file take its place — is the product promise made real in your own directory.
  - Parser handles quoted values (single and double), escape sequences (`\n`, `\t`, `\\`, `\"`), inline comments on unquoted lines, `export ` prefix, duplicate-key detection with later-wins semantics, and BOM stripping. Doesn't interpolate `${OTHER_VAR}` references — values are imported verbatim.

- **`apilocker rotate <alias>`** — replace a credential's value in place. Looks up the key by alias, prompts for the new value with **masked input** (your typing doesn't show on screen), overwrites the encrypted KV blob server-side, and stamps a `rotated_at` timestamp on the metadata row. The key's name, provider, tags, and all metadata stay the same. **Scoped tokens that reference the key continue to work** without reissue — they never held the raw value directly, so rotation is transparent to them.
  - Also accepts `--value <v>` for scripted use, though the interactive masked prompt is preferred for day-to-day use to avoid leaking the value into shell history.

- **List filters** — `apilocker list` now supports `--tag <t>` (repeatable, OR semantics), `--provider <p>`, `--search <q>` (case-insensitive substring match on name), and `--json` for scripting. The table output now includes columns for tags and last rotation time.

- **Repeatable `--tag` flag on `store`** — you can now write `apilocker store --tag prod --tag personal` in addition to the existing `--tags prod,personal` comma form. Both forms merge and dedupe.

### Backend

- **New endpoint: `POST /v1/keys/:keyId/rotate`** — master-token-authenticated. Accepts `{ "key": "<new-value>" }`, encrypts with the existing AES-GCM key, overwrites the KV blob at `keyId`, stamps `rotated_at=now()` on the metadata row, audit-logs the rotation. The response contains no secrets.
- **New `rotated_at` column on `keys_metadata`** — nullable timestamp, populated by the rotate endpoint. Will be surfaced in `apilocker doctor` (v0.5.0) to flag stale credentials (e.g. "your Stripe key hasn't been rotated in 180 days").

### Notes

- Import defaults to `custom` provider with a placeholder `base_url` for any variable name that doesn't match a known prefix. You can always refine the provider later via `apilocker delete` + `apilocker store --provider <correct>`.
- The import command makes one API call per credential (no batch endpoint yet). For very large `.env` files this means N round-trips; in practice, even a 50-secret `.env` imports in under a couple seconds.

## [0.3.0] — 2026-04-08

### Added — the ".env replacement" trio

This release is the one that earns the tagline. The vault stops being "a place secrets are stored" and starts being "a place secrets are *used from* directly."

- **`apilocker run -- <command>`** — run a subprocess with vault secrets injected as environment variables. Raw secrets never touch disk, never hit shell history, never get committed to git. When the subprocess exits, the env vars are gone. Ctrl+C, SIGTERM, and SIGHUP are forwarded to the child process cleanly.
- **`apilocker get <alias>`** — print a single secret value to stdout, for scripting. Output has no trailing newline so it drops cleanly into `$(...)` substitution. Prefer `apilocker run` for interactive use.
- **`apilocker env [--keys aliases] [--format sh|fish|powershell]`** — emit shell-eval-able export statements for the given keys. `eval "$(apilocker env)"` loads them into your current shell. Supports POSIX sh/bash/zsh (default), fish shell, and PowerShell output formats.
- **`apilocker init`** — interactive bootstrap for a project-level `.apilockerrc` file. Walks you through picking which vault keys your current project uses, then writes a committable pointer file. After that, `apilocker run -- <cmd>` and `apilocker env` in the project directory auto-use those keys without `--keys` flags.

### Added — `.apilockerrc` support

A new project-level config file that pins a list of key aliases to a directory. Safe to commit to git — contains only aliases (pointers), never the secrets themselves. Team members each have their own vault with their own keys at the same aliases, so `git clone && apilocker run -- npm start` works identically on every machine that has access.

Format is a minimal YAML subset:

```yaml
keys:
  - openai
  - anthropic
  - stripe-secret
```

A flat one-alias-per-line format is also accepted. No YAML parser dependency — parser is hand-rolled in ~30 lines.

`apilocker run` and `apilocker env` walk upward from the current directory looking for `.apilockerrc`, same way `git` locates `.git`. The search stops at the user's home directory or the filesystem root.

### Env variable name mapping

When `run` or `env` injects a secret, the environment variable name is derived from the key's **alias** (the `name` you gave it when storing):

- If the alias is already `SCREAMING_SNAKE_CASE` (e.g. `OPENAI_API_KEY`), it's used verbatim.
- Otherwise, it's uppercased and non-alphanumeric runs are replaced with underscores (e.g. `stripe-secret` → `STRIPE_SECRET`).

Recommended practice: name your keys after the environment variables your code expects. `apilocker store OPENAI_API_KEY sk-xxx --provider openai` is the cleanest pattern.

### Backend

- New endpoint: **`POST /v1/keys/reveal`** — master-token-authenticated, takes a list of aliases, returns decrypted plaintext values with normalized env var names. Scoped tokens are explicitly blocked from this endpoint — scoped tokens exist so app code can proxy calls without ever seeing raw credentials, and that invariant should not leak.
- Every reveal is audit-logged. One audit row per revealed key, with source IP. Shows up in `apilocker activity` and the dashboard activity feed so suspicious reveal bursts are visible.

### Security notes

- The reveal endpoint caps single-request exfiltration at 50 keys to blunt abuse from a compromised device token.
- `apilocker get` and `apilocker env` print secrets to stdout — putting them in shell history or log files is possible if the user pipes them unwisely. `apilocker run` is strictly safer for day-to-day use and is positioned as the default.

## [0.2.0] — 2026-04-08

### Changed — registration is now fully browser-based
- **`apilocker register` no longer asks for a pasted master token.** Instead, it runs an RFC 8628 device authorization flow: the CLI contacts the API, prints a short verification code (e.g. `ABCD-1234`), opens your default browser to `https://www.apilocker.app/cli-auth`, and waits while you confirm in the browser. The master token is delivered straight to the CLI over the polling endpoint — it never touches your clipboard or shell history.
- **Signup happens automatically.** If you've never used API Locker before, the same flow walks you through GitHub/Google OAuth and creates your account during the authorization click. No separate visit to the web portal required.
- **New flag: `--force`** — re-register this device even if it's already configured. Without this, `apilocker register` now refuses to re-register and prints the email the device is currently bound to (previously it would silently overwrite).
- **New flag: `--name <label>`** — set a custom label for this device that shows up in `apilocker devices list` and the dashboard. Defaults to `${hostname} · ${platform}`.
- **New flag: `--token <master-token>`** — headless escape hatch for CI and environments without a browser. Registers using a pre-issued master token, same as the old 0.1.x flow.

### Added — device management
- **`apilocker devices list`** — show every device registered to your account, with id/name/platform/last-seen and a marker for the device you're currently using.
- **`apilocker devices revoke <deviceId>`** — revoke a device from the CLI. Works on any device ID owned by your account, including this one (with a confirmation prompt that warns you you're about to log yourself out).

### Security
- **OAuth is now CSRF-protected.** The GitHub and Google OAuth callbacks require a valid state parameter bound to a 10-minute KV entry. Stale or forged callbacks are rejected with HTTP 400. (The old implementation had no state check at all.)
- **Per-device master tokens.** Device-auth registrations now issue tokens bound to a single `devices` row rather than a single user-scoped token shared across all registrations. Revoking a device takes effect immediately and affects only that device. Legacy 0.1.x installs continue to work unchanged via a fallback path.
- **Open-redirect protection.** The new `return_to` parameter on OAuth endpoints is validated against an allowlist of apilocker origins. External URLs are silently dropped and the flow falls back to the dashboard.
- **Config file permissions.** `~/.apilocker/config.json` is now written with mode `0600` and its parent directory with mode `0700`.

### Compatibility
- 0.1.x CLI installations and any existing master tokens continue to work. The worker's auth middleware tries per-device tokens first, then falls back to the legacy user-scoped path.

## [0.1.2] — 2026-04-08

### Changed
- **Welcome banner moved from postinstall to first-run.** In 0.1.1 the banner was wired to `npm install` via a `postinstall` hook, but npm 10+ defaults to `foreground-scripts=false` and silently discards postinstall stdout for installed dependencies — meaning the banner never printed for real users. The banner now prints the first time any `apilocker` command runs, tracked via a marker file at `~/.apilocker/.welcome-shown`. Shows exactly once per user per machine.
- `postinstall` script removed from `package.json` (it was a no-op for end users).
- Added `NO_COLOR` to the skip list, following the [widely-respected opt-out convention](https://no-color.org/).

### Why this is better than the postinstall approach
- Works on all npm versions regardless of `foreground-scripts` config.
- Prints when the user is actively looking at their terminal, not buried in install noise.
- Works the same whether installed via `npm`, a tarball, a local checkout, or any future distribution method.

## [0.1.1] — 2026-04-08

### Added
- **Post-install welcome banner.** Big block-letter "API Locker" ASCII art with a 🔑 badge intended to print right after `npm install -g apilocker`, rendered in a brand-blue gradient and followed by signup + first-command hints. _(Note: due to a TTY-detection bug fixed in 0.1.2, the banner never actually printed on this version. Upgrade to 0.1.2.)_
- Banner guards: skipped in CI environments (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `NETLIFY`, `VERCEL`), and wrapped in try/catch so it can never break an install.
- Narrow-terminal fallback: on terminals below 90 columns, the banner collapses to a single-line "API Locker 🔑" wordmark so the art never wraps into garbage.
- Zero new dependencies; the banner uses only Node stdlib and true-color (24-bit) ANSI escape codes.

## [0.1.0] — 2026-04-08

First public beta release.

### Added
- `apilocker register` — register this device against your API Locker account, binds a device fingerprint, stores a master token in `~/.apilocker/config.json`.
- `apilocker store <provider> <secret>` — store an encrypted credential in the vault. Supports pre-configured provider templates for OpenAI, Anthropic, Stripe, Twilio, SendGrid, Resend, Cloudflare, and more.
- `apilocker list` — list stored credentials (metadata only — raw secrets never leave the vault).
- `apilocker delete <keyId>` — permanently delete a stored credential.
- `apilocker token` — manage scoped access tokens. Supports rotation policies: `static`, `hourly`, `daily`, `weekly`, `monthly`.
- `apilocker activity` — view recent proxy calls with provider, path, status, and latency.
- Default API endpoint: `https://api.apilocker.app`. Override with `--url` on `register`.

### Notes
- Released under the MIT license.
- Requires Node.js 18+.
- Works on macOS, Linux, and Windows.
- Beta-only free tier is unlimited during the public beta. Early adopters get grandfathered access to Pro when paid plans arrive.
