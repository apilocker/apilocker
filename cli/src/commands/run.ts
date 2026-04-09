import { Command } from 'commander';
import { spawn } from 'child_process';
import { revealKeys, flattenToEnv, getDeprecationNudges } from '../reveal';
import { loadRcFile } from '../rcfile';

/**
 * `apilocker run [-- command]` — the killer feature.
 *
 * Fetches the requested secrets from the vault, injects them into a
 * subprocess's environment, runs the subprocess, cleans up on exit.
 * The raw secret values never touch disk, never appear in shell history,
 * never get committed to git.
 *
 * Key source precedence:
 *   1. --keys flag (explicit)
 *   2. .apilockerrc (project-local, walks up from CWD)
 *   3. Error (with a helpful message)
 *
 * Usage examples:
 *   apilocker run -- npm start
 *   apilocker run -- node server.js
 *   apilocker run --keys openai,stripe -- python app.py
 *   apilocker run --keys openai -- curl https://api.openai.com/v1/models \
 *     -H "Authorization: Bearer $OPENAI"
 */

export const runCommand = new Command('run')
  .description('Run a command with vault secrets injected as environment variables')
  .option('--keys <aliases>', 'Comma-separated list of key aliases to inject (overrides .apilockerrc)')
  .allowUnknownOption(true)
  .allowExcessArguments(true)
  .helpOption(false)
  .action(async (opts, command) => {
    // Commander's action signature here gives us the subcommand's extra
    // args in `command.args`. We need to pull the user's target command
    // out of there — everything after `--` in the invocation.
    const argv: string[] = command.args || [];

    if (argv.length === 0) {
      console.error('Usage: apilocker run [--keys <aliases>] -- <command> [args...]');
      console.error('');
      console.error('Examples:');
      console.error('  apilocker run -- npm start');
      console.error('  apilocker run --keys openai,stripe -- python app.py');
      process.exit(64); // EX_USAGE
    }

    // Determine which key aliases to fetch
    let aliases: string[];
    if (opts.keys) {
      aliases = String(opts.keys)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else {
      const rc = loadRcFile();
      if (!rc.path) {
        console.error("No --keys specified and no .apilockerrc found in this directory or any parent.");
        console.error('');
        console.error("Either:");
        console.error("  apilocker run --keys openai,stripe -- <command>");
        console.error("or:");
        console.error("  apilocker init    # then run again");
        process.exit(1);
      }
      aliases = rc.keys;
      if (aliases.length === 0) {
        console.error(`The .apilockerrc at ${rc.path} is empty. Add aliases or pass --keys.`);
        process.exit(1);
      }
    }

    // Fetch decrypted secrets from the vault
    let result;
    try {
      result = await revealKeys(aliases);
    } catch (e: any) {
      console.error(`Failed to fetch secrets: ${e.message}`);
      process.exit(1);
    }

    if (result.missing.length > 0) {
      console.error(`Missing keys in vault: ${result.missing.join(', ')}`);
      console.error("Run 'apilocker list' to see what's available.");
      process.exit(1);
    }

    // Lossless-rename nudges: if any credentials were matched via their
    // previous_names history, tell the user on stderr so their code /
    // subprocess output (on stdout) stays clean.
    const nudges = getDeprecationNudges(result);
    for (const msg of nudges) {
      process.stderr.write(`  \x1b[36mℹ\x1b[0m  ${msg}\n`);
    }

    // Build the child process environment. Start from the parent's env,
    // then overlay the revealed secrets. If a secret's env var name
    // collides with an existing variable, the secret wins.
    //
    // flattenToEnv handles both api_key (single env var per credential)
    // and oauth2 (multiple env vars per credential, one per field)
    // transparently.
    const childEnv: Record<string, string> = {
      ...(process.env as Record<string, string>),
      ...flattenToEnv(result),
    };

    // Spawn the subprocess with stdio inherited so the user sees the
    // child's output live and can interact with it as if they ran it
    // directly.
    const [cmd, ...cmdArgs] = argv;
    const child = spawn(cmd, cmdArgs, {
      env: childEnv,
      stdio: 'inherit',
    });

    // Forward signals so Ctrl+C / SIGTERM propagate to the child
    const forwardSignal = (sig: NodeJS.Signals) => {
      if (!child.killed) child.kill(sig);
    };
    process.on('SIGINT', () => forwardSignal('SIGINT'));
    process.on('SIGTERM', () => forwardSignal('SIGTERM'));
    process.on('SIGHUP', () => forwardSignal('SIGHUP'));

    child.on('error', (err: any) => {
      if (err.code === 'ENOENT') {
        console.error(`Command not found: ${cmd}`);
        process.exit(127);
      }
      console.error(`Failed to run ${cmd}: ${err.message}`);
      process.exit(1);
    });

    child.on('exit', (code, signal) => {
      if (signal) {
        // Child was killed by signal — exit with the conventional
        // 128 + signal number code
        const sigNum = (process as any).constants?.os?.signals?.[signal] ?? 0;
        process.exit(128 + sigNum);
      }
      process.exit(code ?? 0);
    });
  });
