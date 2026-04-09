import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { apiRequest } from '../api';

/**
 * `apilocker doctor` — run a security health report on your vault and
 * surface actionable advice. This is the command that positions API
 * Locker as a *security advisor*, not just a storage layer.
 *
 * All checks run against the existing `/v1/keys`, `/v1/tokens`,
 * `/v1/devices`, and `/v1/activity` endpoints — no new backend API is
 * needed. A future version might move some of this server-side to
 * support a doctor panel on the dashboard, but the CLI can already
 * produce an identical report today.
 *
 * Check categories:
 *   1. Rotation hygiene — credentials not rotated in 90+ days
 *   2. Unused keys — zero activity in the last 30 days
 *   3. Expiring tokens — scoped tokens expiring in the next 48 hours
 *   4. Stale devices — no activity in 60+ days
 *   5. Local config hygiene — file permissions on ~/.apilocker/config.json
 *
 * Each finding is printed with ⚠ (attention) or ℹ (info) and a concrete
 * next-step command.
 */

interface KeyListItem {
  id: string;
  name: string;
  provider: string;
  created_at: string;
  rotated_at: string | null;
}

interface TokenListItem {
  id: string;
  name: string;
  rotation_type: string;
  current_token_expires_at: string | null;
  revoked_at: string | null;
  paused_at: string | null;
}

interface DeviceListItem {
  id: string;
  name: string;
  last_used_at: string;
  current: boolean;
}

interface AuditLog {
  id: string;
  key_id: string | null;
  timestamp: string;
}

// ---- Thresholds (expose as flags later if users want to tune) ----
const ROTATION_STALE_DAYS = 90;
const ACTIVITY_STALE_DAYS = 30;
const TOKEN_EXPIRY_WARN_HOURS = 48;
const DEVICE_STALE_DAYS = 60;
const ACTIVITY_LOOKBACK_LIMIT = 500; // how many recent audit logs to pull for freshness checks

type Severity = 'warn' | 'info' | 'ok';

interface Finding {
  severity: Severity;
  category: string;
  summary: string;
  details: string[];
  remedy?: string;
}

export const doctorCommand = new Command('doctor')
  .description('Run a security health check on your vault and surface actionable advice')
  .action(async () => {
    console.log('');
    console.log('  \x1b[1m🩺  API Locker Doctor\x1b[0m');
    console.log('  Running health checks…');
    console.log('');

    const findings: Finding[] = [];

    // Fetch everything we need in parallel
    let keys: KeyListItem[] = [];
    let tokens: TokenListItem[] = [];
    let devices: DeviceListItem[] = [];
    let logs: AuditLog[] = [];

    try {
      const [keysRes, tokensRes, devicesRes, logsRes] = await Promise.all([
        apiRequest<{ keys: KeyListItem[] }>('/v1/keys'),
        apiRequest<{ tokens: TokenListItem[] }>('/v1/tokens').catch(() => ({ tokens: [] })),
        apiRequest<{ devices: DeviceListItem[] }>('/v1/devices').catch(() => ({ devices: [] })),
        apiRequest<{ logs: AuditLog[] }>(`/v1/activity?limit=${ACTIVITY_LOOKBACK_LIMIT}`).catch(
          () => ({ logs: [] })
        ),
      ]);
      keys = keysRes.keys || [];
      tokens = tokensRes.tokens || [];
      devices = devicesRes.devices || [];
      logs = logsRes.logs || [];
    } catch (e: any) {
      console.error(`Failed to fetch vault state: ${e.message}`);
      process.exit(1);
    }

    // ---- Check 1: rotation hygiene ----
    const staleRotation = keys.filter((k) => {
      const lastRotation = k.rotated_at || k.created_at;
      const ageDays = daysSince(lastRotation);
      return ageDays != null && ageDays >= ROTATION_STALE_DAYS;
    });
    if (staleRotation.length > 0) {
      findings.push({
        severity: 'warn',
        category: 'Rotation',
        summary: `${staleRotation.length} key${staleRotation.length === 1 ? '' : 's'} not rotated in ${ROTATION_STALE_DAYS}+ days`,
        details: staleRotation.slice(0, 10).map((k) => {
          const ref = k.rotated_at || k.created_at;
          return `${k.name} — last rotated ${daysSince(ref)} days ago`;
        }),
        remedy: `Run 'apilocker rotate <alias>' to rotate`,
      });
    } else if (keys.length > 0) {
      findings.push({
        severity: 'ok',
        category: 'Rotation',
        summary: `All ${keys.length} key${keys.length === 1 ? '' : 's'} rotated within the last ${ROTATION_STALE_DAYS} days`,
        details: [],
      });
    }

    // ---- Check 2: unused keys ----
    // Build a set of keyIds that have had activity in the lookback window
    const cutoff = Date.now() - ACTIVITY_STALE_DAYS * 86400 * 1000;
    const activeKeyIds = new Set<string>();
    for (const log of logs) {
      if (!log.key_id) continue;
      const t = new Date(log.timestamp).getTime();
      if (t >= cutoff) activeKeyIds.add(log.key_id);
    }
    const unused = keys.filter((k) => !activeKeyIds.has(k.id));

    // Caveat: if the audit log has fewer than ACTIVITY_LOOKBACK_LIMIT entries
    // total, we're seeing the full history and the "unused" call is reliable.
    // If we're at the limit, some keys might look unused that actually aren't.
    // Flag this as info-only.
    const atLimit = logs.length >= ACTIVITY_LOOKBACK_LIMIT;
    if (unused.length > 0 && keys.length > 0) {
      findings.push({
        severity: atLimit ? 'info' : 'warn',
        category: 'Unused keys',
        summary: atLimit
          ? `${unused.length} key${unused.length === 1 ? '' : 's'} may be unused (based on the last ${ACTIVITY_LOOKBACK_LIMIT} audit log entries)`
          : `${unused.length} key${unused.length === 1 ? '' : 's'} with no activity in ${ACTIVITY_STALE_DAYS}+ days`,
        details: unused.slice(0, 10).map((k) => k.name),
        remedy: "If truly unused: run 'apilocker delete <keyId>' to remove",
      });
    }

    // ---- Check 3: expiring scoped tokens ----
    const expiringSoon = tokens.filter((t) => {
      if (t.revoked_at || t.paused_at) return false;
      if (!t.current_token_expires_at) return false;
      const hoursUntil = hoursUntilISO(t.current_token_expires_at);
      return hoursUntil != null && hoursUntil >= 0 && hoursUntil <= TOKEN_EXPIRY_WARN_HOURS;
    });
    if (expiringSoon.length > 0) {
      findings.push({
        severity: 'info',
        category: 'Expiring tokens',
        summary: `${expiringSoon.length} scoped token${expiringSoon.length === 1 ? '' : 's'} expiring in the next ${TOKEN_EXPIRY_WARN_HOURS} hours`,
        details: expiringSoon.slice(0, 10).map((t) => {
          const hrs = hoursUntilISO(t.current_token_expires_at!);
          return `${t.name} — expires in ${hrs}h (${t.rotation_type} rotation)`;
        }),
        remedy: 'Rotating tokens auto-refresh; no action needed unless they stop working',
      });
    }

    // ---- Check 4: stale devices ----
    const staleDevices = devices.filter((d) => {
      const age = daysSince(d.last_used_at);
      return age != null && age >= DEVICE_STALE_DAYS;
    });
    if (staleDevices.length > 0) {
      findings.push({
        severity: 'warn',
        category: 'Stale devices',
        summary: `${staleDevices.length} device${staleDevices.length === 1 ? '' : 's'} not seen in ${DEVICE_STALE_DAYS}+ days`,
        details: staleDevices.slice(0, 10).map((d) => {
          const age = daysSince(d.last_used_at);
          return `${d.name} — last seen ${age} days ago${d.current ? ' (this device!)' : ''}`;
        }),
        remedy: "Run 'apilocker devices revoke <deviceId>' to revoke",
      });
    } else if (devices.length > 0) {
      findings.push({
        severity: 'ok',
        category: 'Devices',
        summary: `${devices.length} active device${devices.length === 1 ? '' : 's'}, all recently used`,
        details: [],
      });
    }

    // ---- Check 5: local config file permissions ----
    const configPath = path.join(os.homedir(), '.apilocker', 'config.json');
    if (fs.existsSync(configPath)) {
      try {
        const stat = fs.statSync(configPath);
        // Mode's lower 9 bits are the rwx triples. 0o600 = owner read+write only.
        const modeBits = stat.mode & 0o777;
        const groupOther = stat.mode & 0o077;
        if (groupOther !== 0) {
          findings.push({
            severity: 'warn',
            category: 'Local config',
            summary: `~/.apilocker/config.json is readable by other users (mode 0${modeBits.toString(8)})`,
            details: [
              'Your master token is in this file. On a shared machine, other users could read it.',
            ],
            remedy: `Run: chmod 600 ${configPath}`,
          });
        } else {
          findings.push({
            severity: 'ok',
            category: 'Local config',
            summary: `~/.apilocker/config.json has secure permissions (0${modeBits.toString(8)})`,
            details: [],
          });
        }
      } catch {
        // Non-fatal
      }
    }

    // ---- Print the report ----
    const warnings = findings.filter((f) => f.severity === 'warn');
    const infos = findings.filter((f) => f.severity === 'info');
    const oks = findings.filter((f) => f.severity === 'ok');

    for (const f of warnings) {
      printFinding(f);
    }
    for (const f of infos) {
      printFinding(f);
    }
    for (const f of oks) {
      printFinding(f);
    }

    console.log('');
    const warnCount = warnings.length;
    const infoCount = infos.length;
    if (warnCount === 0 && infoCount === 0) {
      console.log(`  \x1b[32m✓\x1b[0m All checks passing. Your vault looks healthy.`);
    } else {
      console.log(
        `  ${warnCount} warning${warnCount === 1 ? '' : 's'}, ${infoCount} informational note${infoCount === 1 ? '' : 's'}.`
      );
    }
    console.log('');
  });

function printFinding(f: Finding): void {
  const icon =
    f.severity === 'warn' ? '\x1b[33m⚠\x1b[0m' : f.severity === 'info' ? '\x1b[36mℹ\x1b[0m' : '\x1b[32m✓\x1b[0m';
  console.log(`  ${icon}  \x1b[1m${f.category}\x1b[0m — ${f.summary}`);
  for (const line of f.details) {
    console.log(`       ${line}`);
  }
  if (f.remedy) {
    console.log(`       \x1b[2m→ ${f.remedy}\x1b[0m`);
  }
  console.log('');
}

function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / (86400 * 1000));
}

function hoursUntilISO(iso: string): number | null {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / (3600 * 1000));
}
