---
name: rotate-leaked-credential
description: Respond to a leaked or possibly compromised API key, scoped token, or device with API Locker by freezing access, rotating the key, and reviewing what used it. Use when the user says a key leaked, was committed to git, showed up in logs or a screenshot, or a laptop with vault access was lost.
---

# Rotate a leaked credential

Work through these steps in order. Tell the user what each step changes before you run a tool that modifies the vault, because Claude will ask them to confirm it anyway.

## 1. Identify what leaked

- A credential: find it with `list_keys`, then `get_key_metadata` for its provider, `rotated_at`, and `api_docs_url`.
- A scoped token that an app uses: find it with `list_tokens`.
- A lost or compromised device: find it with `list_devices`.

## 2. Cut off access

- Credential: `pause_key` stops all proxy traffic for it immediately. Warn the user first that apps calling it through the API Locker proxy will get errors until it's resumed.
- Scoped token: `revoke_token`. Apps using it stop working until they get a new token from `create_token`.
- Device: `revoke_device`.

## 3. Replace the key at the provider

API Locker can't issue a new key for the provider. Ask the user to create a new key in the provider's dashboard and revoke the old one there. The `api_docs_url` from step 1 points to the provider's documentation.

## 4. Rotate and resume

- When the user pastes the new value, store it with `rotate_key`. The alias stays the same, so code that uses `apilocker run`, scoped tokens, and the proxy keep working with no changes.
- If you paused the key in step 2, run `resume_key`.

## 5. Review what used it

- Run `get_activity` with the credential's `key_id` and look at recent calls: time, source IP, country, and status code.
- Point out anything the user doesn't recognize, such as calls from an unfamiliar country or a burst of failed requests.

## 6. Close the leak

- If the key was committed to git, rotating it is the fix. The old value stays in git history, so rewriting history is optional and only worth doing if the repository is public.
- Search the project for other places the old key might be hard-coded and move them to environment variables, as the `vault-first-secrets` skill describes. Report file paths, not values.
- Finish with `run_doctor` to confirm nothing else needs attention.

Never call `reveal_key` during this process unless the user explicitly asks to see a value.
