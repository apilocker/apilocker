import { spawn } from 'child_process';

/**
 * Best-effort attempt to open a URL in the user's default browser.
 * Returns true if the command was spawned, false otherwise. Never throws.
 *
 * On macOS:  `open <url>`
 * On Linux:  `xdg-open <url>`
 * On Windows: `start "" "<url>"` via cmd.exe
 *
 * Headless environments (CI, Docker, SSH without X forwarding) typically
 * fail silently — the caller should always also print the URL as a
 * copy-paste fallback.
 */
export function openBrowser(url: string): boolean {
  const platform = process.platform;
  try {
    if (platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
      return true;
    }
    if (platform === 'linux') {
      spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
      return true;
    }
    if (platform === 'win32') {
      // On Windows, `start` is a cmd.exe builtin, not a separate binary.
      // The empty string is the window title (required when the URL has
      // spaces or special characters).
      spawn('cmd', ['/c', 'start', '""', url], { detached: true, stdio: 'ignore' }).unref();
      return true;
    }
  } catch {
    // Fall through
  }
  return false;
}
