import { Env } from './types';
import { generateId, hashToken } from './crypto';
import {
  insertDevice,
  listDevices,
  getDeviceById,
  revokeDevice,
} from './db';
import { jsonOk, jsonError } from './responses';

// ---- Legacy register endpoint (v0.1.x "paste master token" flow) ----
//
// Kept for backwards compatibility with CLI 0.1.x users. New installs
// (0.2.0+) use the device authorization flow in cli-auth.ts instead.

export async function handleRegisterDevice(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  let body: { name: string; fingerprint: string };
  try {
    body = await request.json();
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  if (!body.name || !body.fingerprint) {
    return jsonError('Missing required fields: name, fingerprint', 400);
  }

  const fingerprintHash = await hashToken(body.fingerprint);
  const deviceId = generateId('dev');

  await insertDevice(env, {
    id: deviceId,
    user_id: userId,
    name: body.name,
    hardware_fingerprint_hash: fingerprintHash,
  });

  return jsonOk({ id: deviceId, name: body.name, registered_at: new Date().toISOString() }, 201);
}

// ---- GET /v1/devices ----

export async function handleListDevices(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const devices = await listDevices(env, userId);

  // Identify the "current" device — the one whose token_hash matches the
  // bearer token the caller used. Session-based callers (dashboard) don't
  // have a bearer token, so nothing is marked current for them.
  let currentDeviceId: string | null = null;
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const callerHash = await hashToken(authHeader.slice(7));
    for (const d of devices) {
      if (d.token_hash === callerHash) {
        currentDeviceId = d.id;
        break;
      }
    }
  }

  const result = devices.map((d) => ({
    id: d.id,
    name: d.name,
    hostname: d.hostname,
    platform: d.platform,
    platform_version: d.platform_version,
    cli_version: d.cli_version,
    registered_at: d.registered_at,
    last_used_at: d.last_used_at,
    current: d.id === currentDeviceId,
  }));

  return jsonOk({ devices: result });
}

// ---- POST /v1/devices/:id/revoke ----

export async function handleRevokeDevice(
  _request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const deviceId = params.deviceId;
  if (!deviceId) return jsonError('Missing device id', 400);

  const device = await getDeviceById(env, deviceId, userId);
  if (!device) return jsonError('Device not found', 404);
  if (device.revoked_at) return jsonError('Device already revoked', 410);

  const ok = await revokeDevice(env, deviceId, userId);
  if (!ok) return jsonError('Failed to revoke device', 500);

  return jsonOk({ ok: true, device_id: deviceId });
}
