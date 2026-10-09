---
name: vault-health-check
description: Audit the user's API Locker vault and produce a prioritized list of fixes, covering stale or unused keys, expiring scoped tokens, and devices that haven't been seen in a while. Use when the user asks to check, audit, review, or clean up their API keys, tokens, or vault security.
---

# Vault health check

The audit is read-only. Don't change anything until the user picks what to fix.

## Gather

1. `run_doctor` returns API Locker's own warnings about stale rotations, unused keys, expiring tokens, and stale devices.
2. `list_keys` shows every credential with its provider, category, and paused state. Use `get_key_metadata` for the `rotated_at` date of any key that needs a closer look.
3. `get_activity` with `limit: 200` shows which credentials are actually used.
4. `list_tokens` and `list_devices` cover scoped tokens and registered devices. They need write access; if they return a permissions error, say so and continue with the rest.

## Report

Group findings by priority, and give each one the credential alias, what's wrong, and the fix:

1. **Paused or possibly leaked**: use the `rotate-leaked-credential` skill.
2. **Not rotated in 90+ days**: rotate at the provider, then `rotate_key`.
3. **Scoped tokens expiring within 7 days**: replace with `create_token` before they lapse.
4. **Keys with no activity in 30+ days**: confirm with the user, then `pause_key` or `delete_key`.
5. **Devices not seen in 60+ days**: `revoke_device`.

End with a one-line summary, such as "14 credentials, 3 need attention", and ask which fixes to make. Run the fixes one at a time. `delete_key`, `revoke_token`, and `revoke_device` can't be undone, so name exactly what each one removes before you call it.

Never call `reveal_key` during an audit.
