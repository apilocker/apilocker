---
name: vault-first-secrets
description: Keep API keys and other secrets out of source code, .env files, shell profiles, and chat by storing them in the user's API Locker vault and injecting them at runtime. Use whenever a task involves adding, using, moving, or sharing an API key, access token, client secret, or other credential.
---

# Vault-first secrets with API Locker

The user's credentials live in their API Locker vault. Code and config refer to a credential by its alias, such as `OPENAI_API_KEY`, and the value is injected only when a program runs.

## Rules

1. Never write a secret value into source code, config files, `.env` files, shell profiles, commit messages, logs, or your replies.
2. Don't call `reveal_key` unless the user explicitly asks to see a raw value. If they do, show it once and don't copy it anywhere else.
3. Before asking the user for a key, check whether the vault already has one with `list_keys`, filtering by `provider` or `category` (`llm`, `service`, or `oauth`).

## Add a credential

- If the user pastes a secret into the conversation, store it right away with `store_key`, or `store_oauth_credential` for an OAuth client ID and secret. Then refer to it only by its alias.
- Name it after the environment variable the code expects, in UPPER_SNAKE_CASE, such as `OPENAI_API_KEY` or `STRIPE_SECRET_KEY`. `apilocker run` injects each credential as an environment variable with that name.
- Set `provider` to an id from `list_providers`, such as `openai` or `github`, so the proxy knows the provider's base URL.
- If the project already has a `.env` file, suggest the user run `apilocker import .env`. The CLI encrypts each entry into the vault, and the user can then delete the file. Don't read the file's values into the conversation yourself.

## Use a credential in code

- In code, read secrets from environment variables, such as `process.env.OPENAI_API_KEY` or `os.environ["OPENAI_API_KEY"]`, and never from a literal.
- Run the program with the vault injecting them:
  - `apilocker run --keys OPENAI_API_KEY,STRIPE_SECRET_KEY -- npm start`
  - Or pin the project's aliases once with `apilocker init --keys OPENAI_API_KEY,STRIPE_SECRET_KEY`. This writes a `.apilockerrc` that lists aliases only, so it's safe to commit, and plain `apilocker run -- npm start` then picks them up.
- For an interactive shell, `eval "$(apilocker env --keys OPENAI_API_KEY)"` exports the variables into the current session.
- If a tool can only read a `.env` file, ask the user before creating one. Generate it from the vault with `apilocker env --keys ... > .env` rather than typing values, make sure `.env` is in `.gitignore`, and tell the user you did it.
- If the CLI isn't installed, tell the user it's `npm install -g apilocker` followed by `apilocker register`.

## Call an API without exposing the key

Use the proxy tools when the user wants Claude to call a provider's API directly:

1. Find the credential's `key_id` with `list_keys`.
2. Check its `base_url` and `api_docs_url` with `get_key_metadata`. The `path` you pass is appended to the base URL, for example `/v1/models` for OpenAI.
3. Use `proxy_get` for reads. Use `proxy_post`, `proxy_put`, `proxy_patch`, or `proxy_delete` for writes; Claude asks the user before each one.

Through the proxy tools, payment APIs such as Stripe are read-only, purchase endpoints and AI image, video, and audio generation are refused, and credentials with a custom base URL are read-only. If a call is refused, tell the user, and suggest making that call from their own code with `apilocker run` instead.

## If a secret has leaked

Switch to the `rotate-leaked-credential` skill.
