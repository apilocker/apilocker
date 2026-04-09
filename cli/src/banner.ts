/**
 * First-run welcome banner for the apilocker CLI.
 *
 * Printed the first time a user runs any `apilocker` command (register, list,
 * store, etc.). Shows once per user per machine, tracked via a marker file
 * at `~/.apilocker/.welcome-shown`.
 *
 * Why first-run instead of postinstall:
 *   npm 10+ runs `postinstall` scripts for installed dependencies with
 *   `foreground-scripts=false` by default, which captures their stdout and
 *   only shows it on error. A postinstall banner silently never prints for
 *   real users. First-run fires when the user is actively looking at their
 *   terminal, so it's strictly better UX anyway.
 *
 * Safety guarantees (do not remove):
 *   1. Wrapped in try/catch so any failure silently returns.
 *      The banner must NEVER block the user from running their command.
 *   2. Skipped in CI environments (GitHub Actions, GitLab, Vercel, Netlify,
 *      CircleCI, etc.) so automated runs stay quiet.
 *   3. Skipped when NO_COLOR is set (widely-respected opt-out convention).
 *   4. Uses only Node stdlib — zero extra deps.
 *   5. On terminals narrower than the ASCII-art needs (< 90 columns), falls
 *      back to a compact one-line wordmark so it never wraps into garbage.
 *   6. Marker file write failures are caught — if `~/.apilocker/` isn't
 *      writable, the banner just prints every run, which is acceptable.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const MARKER_FILENAME = '.welcome-shown';

export function maybeShowFirstRunBanner(): void {
  try {
    const homedir = os.homedir();
    if (!homedir) return;

    const markerDir = path.join(homedir, '.apilocker');
    const markerFile = path.join(markerDir, MARKER_FILENAME);

    // Already shown — silent no-op on every subsequent run.
    if (fs.existsSync(markerFile)) return;

    const isCI = Boolean(
      process.env.CI ||
        process.env.GITHUB_ACTIONS ||
        process.env.GITLAB_CI ||
        process.env.CIRCLECI ||
        process.env.NETLIFY ||
        process.env.VERCEL ||
        process.env.NO_COLOR
    );

    if (isCI) {
      // Still mark as shown so we don't check on every CI run.
      writeMarker(markerDir, markerFile);
      return;
    }

    renderBanner();
    writeMarker(markerDir, markerFile);
  } catch {
    // Never block the user from running their command.
  }
}

function writeMarker(markerDir: string, markerFile: string): void {
  try {
    fs.mkdirSync(markerDir, { recursive: true });
    fs.writeFileSync(markerFile, new Date().toISOString() + '\n');
  } catch {
    // Permission denied, read-only FS, whatever — swallow. Worst case the
    // banner prints on every run, which is annoying but not broken.
  }
}

function renderBanner(): void {
  // ---- ANSI helpers ----
  const ESC = '\x1b';
  const reset = `${ESC}[0m`;
  const bold = `${ESC}[1m`;
  const dim = `${ESC}[2m`;
  const underline = `${ESC}[4m`;
  const rgb = (r: number, g: number, b: number) => `${ESC}[38;2;${r};${g};${b}m`;

  // Brand palette — matches https://www.apilocker.app
  const BLUE_LIGHT = rgb(96, 165, 250); // #60A5FA
  const BLUE = rgb(59, 130, 246); // #3B82F6
  const BLUE_DEEP = rgb(30, 58, 138); // #1E3A8A
  const WHITE = rgb(248, 250, 252); // #F8FAFC
  const MUTED = rgb(148, 163, 184); // #94A3B8

  // ---- Big block-letter art (figlet "banner3" style) ----
  // 7 rows, ~84 columns wide. Rendered in a top-to-bottom blue gradient.
  // Regenerate with: figlet -w 120 -f banner3 "API Locker"
  const art: string[] = [
    '   ###    ########  ####    ##        #######   ######  ##    ## ######## ########  ',
    '  ## ##   ##     ##  ##     ##       ##     ## ##    ## ##   ##  ##       ##     ## ',
    ' ##   ##  ##     ##  ##     ##       ##     ## ##       ##  ##   ##       ##     ## ',
    '##     ## ########   ##     ##       ##     ## ##       #####    ######   ########  ',
    '######### ##         ##     ##       ##     ## ##       ##  ##   ##       ##   ##   ',
    '##     ## ##         ##     ##       ##     ## ##    ## ##   ##  ##       ##    ##  ',
    '##     ## ##        ####    ########  #######   ######  ##    ## ######## ##     ## ',
  ];

  const artColors = [
    BLUE_LIGHT,
    BLUE_LIGHT,
    BLUE,
    BLUE,
    BLUE,
    BLUE_DEEP,
    BLUE_DEEP,
  ];

  // When running a real interactive command, `process.stdout.columns` is
  // populated (unlike during npm install). Fall back to 100 as a sane
  // default if it's somehow missing.
  const cols = process.stdout.columns ?? 100;
  const ART_MIN_COLS = 90;

  const println = (s: string = '') => process.stdout.write(s + '\n');

  if (cols >= ART_MIN_COLS) {
    // ---- Full block-letter banner ----
    println();
    for (let i = 0; i < art.length; i++) {
      // Put the key 🔑 on the middle row so it reads as a badge next to
      // the wordmark.
      const keyTrail = i === 3 ? '  🔑' : '';
      println('  ' + artColors[i] + art[i] + reset + keyTrail);
    }
    println();
  } else {
    // ---- Narrow-terminal fallback ----
    println();
    println(`  ${bold}${WHITE}API Locker${reset} 🔑`);
    println();
  }

  // ---- Tagline + quick start ----
  println(`  ${MUTED}Replace your .env file with one token${reset}`);
  println();
  println(
    `  ${BLUE}→${reset}  ${bold}Sign up${reset}     ${MUTED}·${reset}  ${underline}${BLUE}https://www.apilocker.app/signup${reset}`
  );
  println(
    `  ${BLUE}→${reset}  ${bold}Then run${reset}    ${MUTED}·${reset}  ${bold}apilocker register${reset}`
  );
  println();
  println(
    `  ${dim}${MUTED}Free unlimited usage during public beta. Beta users get grandfathered into Pro.${reset}`
  );
  println();
}
