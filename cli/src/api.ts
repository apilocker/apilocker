import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const CONFIG_DIR = path.join(os.homedir(), '.apilocker');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

export const DEFAULT_API_URL = 'https://api.apilocker.app';

export interface Config {
  api_url: string;
  master_token: string;
  fingerprint?: string;
  email?: string;
  device_id?: string;
  device_name?: string;
  registered_at?: string;
}

/**
 * Load config from disk. Exits the process if not configured (used by
 * commands that require an authenticated CLI).
 */
export function getConfig(): Config {
  if (!fs.existsSync(CONFIG_FILE)) {
    console.error('Not configured. Run `apilocker register` first.');
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
}

/**
 * Load config from disk without exiting on failure. Returns null if the
 * config file does not exist. Used by commands that want to check if the
 * CLI is already configured without dying.
 */
export function tryGetConfig(): Config | null {
  if (!fs.existsSync(CONFIG_FILE)) return null;
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Persist config to disk with restrictive permissions.
 * The master token is secret — file mode 0600 (owner read/write only).
 */
export function saveConfig(config: Config): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  // fs.writeFileSync's `mode` option is ignored if the file already
  // exists — explicitly chmod it to make sure permissions are tight.
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch {
    // Non-fatal
  }
}

/**
 * Authenticated request — requires config to exist and sends the master
 * token as a Bearer header.
 */
export async function apiRequest<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const config = getConfig();
  return requestRaw<T>(config.api_url, path, options, config.master_token);
}

/**
 * Unauthenticated request — for endpoints like /cli-auth/start, /info,
 * and /poll that don't require credentials (the whole point is that the
 * CLI has none yet). Caller supplies the base URL.
 */
export async function unauthRequest<T>(
  baseUrl: string,
  path: string,
  options?: RequestInit
): Promise<T> {
  return requestRaw<T>(baseUrl, path, options);
}

async function requestRaw<T>(
  baseUrl: string,
  path: string,
  options?: RequestInit,
  bearerToken?: string
): Promise<T> {
  const url = `${baseUrl}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string> | undefined),
  };
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }

  const res = await fetch(url, { ...options, headers });

  const text = await res.text();
  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Invalid JSON response from ${path} (status ${res.status})`);
    }
  }

  if (!res.ok) {
    throw new Error(data.error || `Request failed with status ${res.status}`);
  }

  return data as T;
}
