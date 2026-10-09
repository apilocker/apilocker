import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const CONFIG_DIR = path.join(os.homedir(), '.apilocker');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const DEFAULT_API_URL = 'https://api.apilocker.app';

export interface Config {
  api_url: string;
  master_token: string;
  fingerprint?: string;
  email?: string;
  device_id?: string;
  device_name?: string;
  registered_at?: string;
}

export interface KeyMetadata {
  id: string;
  name: string;
  provider: string;
  base_url: string;
  auth_header_type: string;
  credential_type: 'api_key' | 'oauth2';
  category: 'llm' | 'service' | 'oauth';
  tags: string;
  created_at: string;
  rotated_at: string | null;
  paused_at: string | null;
}

export interface ActivityEntry {
  id: string;
  key_id: string | null;
  provider: string | null;
  forward_path: string | null;
  source_ip: string | null;
  country: string | null;
  timestamp: string;
  status_code: number | null;
  latency_ms: number | null;
}

export interface RevealedKey {
  name: string;
  provider: string;
  credential_type: 'api_key' | 'oauth2';
  value?: string;
  env_name?: string;
  fields?: Record<string, string | undefined>;
  env_names?: Record<string, string>;
}

export interface RevealResponse {
  keys: RevealedKey[];
  missing: string[];
}

export function getConfig(): Config | null {
  if (!fs.existsSync(CONFIG_FILE)) return null;
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

export function isConfigured(): boolean {
  return getConfig() !== null;
}

export async function apiRequest<T>(
  urlPath: string,
  options?: RequestInit,
): Promise<T> {
  const config = getConfig();
  if (!config) {
    throw new Error('Not configured. Run `apilocker register` in your terminal first.');
  }

  const baseUrl = config.api_url || DEFAULT_API_URL;
  const url = `${baseUrl}${urlPath}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${config.master_token}`,
    ...(options?.headers as Record<string, string> | undefined),
  };

  const res = await fetch(url, { ...options, headers });
  const text = await res.text();

  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Invalid JSON from ${urlPath} (status ${res.status})`);
    }
  }

  if (!res.ok) {
    throw new Error(data.error || `Request failed: ${res.status}`);
  }

  return data as T;
}

// ── Key operations ──

export async function listKeys(): Promise<KeyMetadata[]> {
  const data = await apiRequest<{ keys: KeyMetadata[] }>('/v1/keys');
  return data.keys;
}

export async function revealKey(keyName: string): Promise<RevealedKey | null> {
  const data = await apiRequest<RevealResponse>('/v1/keys/reveal', {
    method: 'POST',
    body: JSON.stringify({ keys: [keyName] }),
  });
  return data.keys[0] ?? null;
}

export async function rotateKey(keyId: string, newValue: string): Promise<void> {
  await apiRequest('/v1/keys/' + keyId + '/rotate', {
    method: 'POST',
    body: JSON.stringify({ value: newValue }),
  });
}

export async function renameKey(keyId: string, newName: string): Promise<void> {
  await apiRequest('/v1/keys/' + keyId + '/rename', {
    method: 'POST',
    body: JSON.stringify({ name: newName }),
  });
}

export async function pauseKey(keyId: string): Promise<void> {
  await apiRequest('/v1/keys/' + keyId + '/pause', { method: 'POST' });
}

export async function resumeKey(keyId: string): Promise<void> {
  await apiRequest('/v1/keys/' + keyId + '/resume', { method: 'POST' });
}

export async function deleteKey(keyId: string): Promise<void> {
  await apiRequest('/v1/keys/' + keyId, { method: 'DELETE' });
}

export async function storeKey(body: Record<string, unknown>): Promise<void> {
  await apiRequest('/v1/keys', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function getActivity(limit = 50): Promise<ActivityEntry[]> {
  const data = await apiRequest<{ logs: ActivityEntry[] }>(
    '/v1/activity?limit=' + limit,
  );
  return data.logs;
}

export async function runDoctor(): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>('/v1/doctor');
}

// ── Token operations ──

export interface TokenInfo {
  id: string;
  name: string;
  allowed_keys: string[];
  rotation_type: string;
  expires_at: string | null;
  created_at: string;
  last_refreshed_at: string | null;
  revoked: boolean;
  paused: boolean;
  compromised: boolean;
}

export async function listTokens(): Promise<TokenInfo[]> {
  const data = await apiRequest<{ tokens: TokenInfo[] }>('/v1/tokens');
  return data.tokens;
}

export interface CreateTokenResponse {
  id: string;
  name: string;
  access_token: string;
  access_token_expires_at: string | null;
  refresh_token: string | null;
  rotation_type: string;
  created_at: string;
}

export async function createToken(
  name: string,
  allowedKeys: string[],
  rotationType: string = 'daily',
): Promise<CreateTokenResponse> {
  return apiRequest<CreateTokenResponse>('/v1/tokens', {
    method: 'POST',
    body: JSON.stringify({
      name,
      allowed_keys: allowedKeys,
      rotation_type: rotationType,
    }),
  });
}

export async function pauseToken(tokenId: string): Promise<void> {
  await apiRequest('/v1/tokens/' + tokenId + '/pause', { method: 'POST' });
}

export async function resumeToken(tokenId: string): Promise<void> {
  await apiRequest('/v1/tokens/' + tokenId + '/resume', { method: 'POST' });
}

export async function revokeToken(tokenId: string): Promise<void> {
  await apiRequest('/v1/tokens/' + tokenId, { method: 'DELETE' });
}

// ── Device operations ──

export interface DeviceInfo {
  id: string;
  name: string;
  hostname: string | null;
  platform: string | null;
  platform_version: string | null;
  cli_version: string | null;
  registered_at: string;
  last_used_at: string;
  current: boolean;
}

export async function listDevices(): Promise<DeviceInfo[]> {
  const data = await apiRequest<{ devices: DeviceInfo[] }>('/v1/devices');
  return data.devices;
}

export async function revokeDevice(deviceId: string): Promise<void> {
  await apiRequest('/v1/devices/' + deviceId + '/revoke', { method: 'POST' });
}
