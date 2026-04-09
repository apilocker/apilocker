import { Command } from 'commander';
import { collectDeviceInfo } from '../fingerprint';
import {
  saveConfig,
  tryGetConfig,
  unauthRequest,
  apiRequest,
  DEFAULT_API_URL,
  Config,
} from '../api';
import { openBrowser } from '../browser';

// Version comes from the package.json and is set at build-time by Commander
// (see index.ts). We also inline-require it here for the /cli-auth/start
// payload so the server knows which CLI version is registering.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json') as { version: string };

interface StartResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface PollPending {
  status: 'pending';
}
interface PollSlowDown {
  status: 'slow_down';
  interval: number;
}
interface PollAuthorized {
  status: 'authorized';
  master_token: string;
  user_id: string;
  email: string | null;
  device_id: string;
}
interface PollExpired {
  status: 'expired';
}
interface PollDenied {
  status: 'denied';
}
type PollResponse = PollPending | PollSlowDown | PollAuthorized | PollExpired | PollDenied;

interface MeResponse {
  id: string;
  email: string;
  name: string | null;
}

export const registerCommand = new Command('register')
  .description('Register this device with your API Locker account')
  .option('--url <url>', 'API Locker URL', DEFAULT_API_URL)
  .option('--force', 'Re-register even if this device is already configured')
  .option('--name <label>', 'Custom label for this device (shown in the dashboard)')
  .option('--token <token>', 'Headless escape hatch: register with a pre-issued master token instead of the browser flow')
  .action(async (opts) => {
    try {
      // ---- Already-registered guard ----
      if (!opts.force) {
        const existing = tryGetConfig();
        if (existing?.master_token) {
          const identity = existing.email || existing.device_name || 'this device';
          console.log(`Already registered as ${identity}.`);
          console.log("Run 'apilocker register --force' to re-register.");
          return;
        }
      }

      // ---- Token escape hatch (CI / headless) ----
      if (opts.token) {
        await registerWithToken(opts.url, opts.token, opts.name);
        return;
      }

      // ---- Browser device-authorization flow (primary path) ----
      await registerWithBrowser(opts.url, opts.name);
    } catch (e: any) {
      console.error(`\nRegistration failed: ${e.message}`);
      process.exit(1);
    }
  });

/**
 * Primary registration path: RFC 8628 device authorization flow.
 *
 *   1. POST /v1/cli-auth/start → receive device_code + user_code + URL
 *   2. Open the browser to the verification URL (best effort)
 *   3. Poll /v1/cli-auth/poll every `interval` seconds until authorized
 *   4. Save the master token returned by poll to ~/.apilocker/config.json
 */
async function registerWithBrowser(apiUrl: string, name?: string): Promise<void> {
  const device = collectDeviceInfo();

  // Kick off the flow
  const start = await unauthRequest<StartResponse>(apiUrl, '/v1/cli-auth/start', {
    method: 'POST',
    body: JSON.stringify({
      client_metadata: {
        hostname: device.hostname,
        platform: device.platform,
        platform_version: device.platform_version,
        cli_version: pkg.version,
      },
      name: name || undefined,
    }),
  });

  // Print the UX
  console.log();
  console.log('  Opening browser to authorize this device…');
  console.log();
  console.log(`  Verification code:  \x1b[1m${start.user_code}\x1b[0m`);
  console.log('  If your browser didn\'t open, visit:');
  console.log(`  \x1b[4m${start.verification_uri_complete}\x1b[0m`);
  console.log();

  const opened = openBrowser(start.verification_uri_complete);
  if (!opened) {
    console.log('  (Could not open browser automatically — copy the URL above.)');
    console.log();
  }

  // Poll loop
  const deadlineMs = Date.now() + start.expires_in * 1000;
  let intervalSeconds = Math.max(2, start.interval);
  const spinnerFrames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let spinnerFrame = 0;
  const isTTY = Boolean(process.stdout.isTTY);
  let spinnerInterval: NodeJS.Timeout | null = null;
  const redrawSpinner = () => {
    if (!isTTY) return;
    const secondsLeft = Math.max(0, Math.floor((deadlineMs - Date.now()) / 1000));
    const mm = Math.floor(secondsLeft / 60);
    const ss = (secondsLeft % 60).toString().padStart(2, '0');
    process.stdout.write(
      `\r  ${spinnerFrames[spinnerFrame]} Waiting for authorization (${mm}:${ss})…  `
    );
    spinnerFrame = (spinnerFrame + 1) % spinnerFrames.length;
  };
  const clearSpinner = () => {
    if (spinnerInterval) {
      clearInterval(spinnerInterval);
      spinnerInterval = null;
    }
    if (isTTY) {
      process.stdout.write('\r\x1b[K');
    }
  };
  if (isTTY) {
    redrawSpinner();
    spinnerInterval = setInterval(redrawSpinner, 120);
  } else {
    console.log('  Waiting for authorization…');
  }

  // Graceful Ctrl+C
  const onInterrupt = () => {
    clearSpinner();
    console.log('\n  Cancelled.');
    process.exit(130);
  };
  process.on('SIGINT', onInterrupt);

  try {
    while (Date.now() < deadlineMs) {
      await sleep(intervalSeconds * 1000);

      let result: PollResponse;
      try {
        result = await unauthRequest<PollResponse>(apiUrl, '/v1/cli-auth/poll', {
          method: 'POST',
          body: JSON.stringify({ device_code: start.device_code }),
        });
      } catch (e: any) {
        // Transient network errors — keep polling
        if (e.message?.includes('fetch')) continue;
        // Backend returned an error status — surface it
        const msg = String(e.message || '');
        if (msg.includes('slow_down')) {
          intervalSeconds += 3;
          continue;
        }
        throw e;
      }

      if (result.status === 'pending') {
        continue;
      }
      if (result.status === 'slow_down') {
        intervalSeconds = Math.max(intervalSeconds, result.interval);
        continue;
      }
      if (result.status === 'denied') {
        clearSpinner();
        console.log();
        console.log('  Authorization denied.');
        console.log("  Run 'apilocker register' again if you'd like to try once more.");
        process.exit(1);
      }
      if (result.status === 'expired') {
        clearSpinner();
        console.log();
        console.log('  Authorization timed out.');
        console.log("  Run 'apilocker register' again to get a fresh code.");
        process.exit(1);
      }
      if (result.status === 'authorized') {
        clearSpinner();
        process.off('SIGINT', onInterrupt);

        const config: Config = {
          api_url: apiUrl,
          master_token: result.master_token,
          fingerprint: device.fingerprint,
          email: result.email ?? undefined,
          device_id: result.device_id,
          device_name: friendlyName(device, name),
          registered_at: new Date().toISOString(),
        };
        saveConfig(config);

        console.log();
        console.log(`  \x1b[32m✓\x1b[0m Registered${result.email ? ' as ' + result.email : ''}`);
        console.log(`  \x1b[32m✓\x1b[0m Device: ${config.device_name}`);
        console.log();
        console.log('  Next: apilocker store openai sk-...');
        console.log();
        return;
      }
    }

    // Loop exited because deadline passed
    clearSpinner();
    console.log();
    console.log('  Authorization timed out.');
    console.log("  Run 'apilocker register' again to get a fresh code.");
    process.exit(1);
  } finally {
    clearSpinner();
    process.off('SIGINT', onInterrupt);
  }
}

/**
 * Escape hatch: register with a pre-issued master token instead of running
 * the browser flow. Used for CI, headless servers, or any environment
 * where opening a browser isn't possible.
 */
async function registerWithToken(apiUrl: string, token: string, name?: string): Promise<void> {
  const device = collectDeviceInfo();

  // Save the config optimistically so apiRequest can pick it up
  const tentative: Config = {
    api_url: apiUrl,
    master_token: token,
    fingerprint: device.fingerprint,
  };
  saveConfig(tentative);

  // Verify the token works by fetching /auth/me
  let me: MeResponse;
  try {
    me = await apiRequest<MeResponse>('/v1/auth/me');
  } catch (e: any) {
    throw new Error(`Could not verify master token: ${e.message}`);
  }

  // Register device fingerprint via the legacy endpoint (still in place
  // for backwards compatibility). This creates a devices row linked to
  // the user.
  const deviceName = friendlyName(device, name);
  await apiRequest<{ id: string; name: string }>('/v1/devices/register', {
    method: 'POST',
    body: JSON.stringify({
      name: deviceName,
      fingerprint: device.fingerprint,
    }),
  });

  const config: Config = {
    api_url: apiUrl,
    master_token: token,
    fingerprint: device.fingerprint,
    email: me.email,
    device_name: deviceName,
    registered_at: new Date().toISOString(),
  };
  saveConfig(config);

  console.log();
  console.log(`  \x1b[32m✓\x1b[0m Registered as ${me.email}`);
  console.log(`  \x1b[32m✓\x1b[0m Device: ${deviceName}`);
  console.log();
  console.log('  Next: apilocker store openai sk-...');
  console.log();
}

function friendlyName(
  device: { hostname: string; platform: string },
  label: string | undefined
): string {
  if (label) return label;
  return `${device.hostname} · ${device.platform}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
