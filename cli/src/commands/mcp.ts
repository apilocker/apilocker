import { Command } from 'commander';
import * as readline from 'readline';
import * as os from 'os';
import { getConfig } from '../api';

/**
 * `apilocker mcp` — run as an MCP (Model Context Protocol) stdio server
 * for AI clients like Claude Desktop, Claude Code, Cursor, Zed, and
 * anything else that supports the MCP stdio transport.
 *
 * This command:
 *   1. Reads line-delimited JSON-RPC messages from stdin
 *   2. Forwards each message to the HTTPS MCP backend at
 *      https://api.apilocker.app/v1/mcp using the stored master token
 *      from ~/.apilocker/config.json as the Authorization header
 *   3. Writes the backend's response to stdout as a single line
 *   4. Continues until stdin closes (the parent MCP client disconnects)
 *
 * The command is typically invoked by the MCP client as a subprocess.
 * Configuration in the client looks like:
 *
 *     {
 *       "mcpServers": {
 *         "apilocker": {
 *           "command": "apilocker",
 *           "args": ["mcp"]
 *         }
 *       }
 *     }
 *
 * The stored master token is used for authentication, so the agent
 * inherits the same permissions as the CLI user on this machine. For
 * restricted access, use a dedicated scoped token via `apilocker mcp
 * --token <scoped-token>`.
 *
 * STARTUP output is written to STDERR, never stdout — stdout is
 * reserved for MCP protocol messages only.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json') as { version: string };

// Nested subcommand: `apilocker mcp config` prints client configs
const mcpConfigCommand = new Command('config')
  .description('Print copy-pasteable MCP client configuration snippets')
  .option(
    '--client <name>',
    'MCP client name: claude-desktop, claude-code, cursor, continue, zed, generic',
    'claude-desktop'
  )
  .action((opts) => {
    const client = String(opts.client || 'claude-desktop').toLowerCase();
    const snippet = getConfigSnippet(client);
    if (!snippet) {
      console.error(`Unknown client: ${client}`);
      console.error('Known clients: claude-desktop, claude-code, cursor, continue, zed, generic');
      process.exit(1);
    }
    // Print the snippet directly to stdout so users can pipe it:
    //   apilocker mcp config --client claude-desktop > claude_config.json
    console.log(snippet.content);
    if (snippet.instructions) {
      process.stderr.write('\n');
      process.stderr.write(snippet.instructions + '\n');
    }
  });

export const mcpCommand = new Command('mcp')
  .description('MCP integration — run as stdio server or print client config')
  .action(async () => {
    // Default action (no subcommand): run the stdio bridge
    await runStdioBridge();
  });

mcpCommand.addCommand(mcpConfigCommand);

// ---- The stdio bridge ----

async function runStdioBridge(): Promise<void> {
  let config;
  try {
    config = getConfig();
  } catch {
    // getConfig() will have already exited; unreachable
    return;
  }

  // Startup banner on stderr (stdout is reserved for MCP protocol)
  process.stderr.write(
    `API Locker MCP bridge v${pkg.version}\n` +
      `  Backend: ${config.api_url}/v1/mcp\n` +
      `  Auth:    ${config.email || 'master token'}\n` +
      `  Ready for MCP client on stdin.\n`
  );

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  // Track in-flight forwarded requests so we can drain them before
  // exiting. Without this, piping input + EOF causes the 'close'
  // event to fire before the async fetches resolve, and any responses
  // never get written to stdout. This bit me in local testing.
  const pending = new Set<Promise<void>>();

  const handleLine = async (trimmed: string, parsedRequest: { id?: string | number }) => {
    try {
      const res = await fetch(`${config.api_url}/v1/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.master_token}`,
          'User-Agent': `apilocker-cli/${pkg.version} mcp-bridge (${os.platform()} ${os.release()})`,
        },
        body: trimmed,
      });

      const body = await res.text();

      if (!res.ok) {
        writeResponse({
          jsonrpc: '2.0',
          id: parsedRequest.id ?? null,
          error: {
            code: -32000,
            message: `Backend returned HTTP ${res.status}: ${body.slice(0, 200)}`,
          },
        });
        return;
      }

      // Write the raw backend response (already JSON-RPC formatted)
      // to stdout. Notifications return empty/minimal bodies; we still
      // write them but MCP clients ignore responses to notifications.
      if (body && body.trim()) {
        process.stdout.write(body.trim() + '\n');
      }
    } catch (err: any) {
      writeResponse({
        jsonrpc: '2.0',
        id: parsedRequest.id ?? null,
        error: {
          code: -32000,
          message: `Bridge error: ${err.message}`,
        },
      });
    }
  };

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let request: { id?: string | number; method?: string } = {};
    try {
      request = JSON.parse(trimmed);
    } catch (err: any) {
      writeResponse({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: `Parse error: ${err.message}` },
      });
      return;
    }

    // Fire-and-track the forwarded request
    const promise = handleLine(trimmed, request);
    pending.add(promise);
    promise.finally(() => pending.delete(promise));
  });

  rl.on('close', async () => {
    // Drain any in-flight requests before exiting so their responses
    // actually make it to stdout.
    if (pending.size > 0) {
      process.stderr.write(
        `API Locker MCP bridge: draining ${pending.size} in-flight request(s)...\n`
      );
      await Promise.allSettled(Array.from(pending));
    }
    process.stderr.write('API Locker MCP bridge: stdin closed, exiting.\n');
    process.exit(0);
  });
}

function writeResponse(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// ---- Config snippets ----

interface ConfigSnippet {
  content: string;
  instructions: string;
}

function getConfigSnippet(client: string): ConfigSnippet | null {
  const baseConfig = {
    command: 'apilocker',
    args: ['mcp'],
  };

  switch (client) {
    case 'claude-desktop':
      return {
        content: JSON.stringify(
          {
            mcpServers: {
              apilocker: baseConfig,
            },
          },
          null,
          2
        ),
        instructions: `Paste this into your Claude Desktop config file:

  macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json
  Windows: %APPDATA%\\Claude\\claude_desktop_config.json
  Linux:   ~/.config/Claude/claude_desktop_config.json

If the file already has an "mcpServers" key, merge the "apilocker" entry
into it. Restart Claude Desktop after saving.

Once connected, Claude Desktop will have all 21 API Locker tools
available (list_keys, reveal_key, run_doctor, proxy_request, etc.).`,
      };

    case 'claude-code':
      return {
        content: 'claude mcp add apilocker -- apilocker mcp',
        instructions: `Run the command above in your shell. That's it — Claude Code will
pick up the MCP server on the next session.

Verify with: claude mcp list`,
      };

    case 'cursor':
      return {
        content: JSON.stringify(
          {
            mcpServers: {
              apilocker: baseConfig,
            },
          },
          null,
          2
        ),
        instructions: `Open Cursor Settings (Cmd/Ctrl + ,), search for "MCP", and either:

  1. Paste the JSON above into the Cursor MCP config, OR
  2. Click "Add Server" and enter:
       Name:    apilocker
       Command: apilocker
       Args:    mcp

Restart Cursor after saving.`,
      };

    case 'continue':
      return {
        content: JSON.stringify(
          {
            mcpServers: {
              apilocker: baseConfig,
            },
          },
          null,
          2
        ),
        instructions: `Paste this into your Continue config file (~/.continue/config.json)
under the "mcpServers" key. Restart VS Code after saving.`,
      };

    case 'zed':
      return {
        content: JSON.stringify(
          {
            context_servers: {
              apilocker: {
                command: {
                  path: 'apilocker',
                  args: ['mcp'],
                  env: {},
                },
              },
            },
          },
          null,
          2
        ),
        instructions: `Paste this into your Zed settings.json under the "context_servers"
key. Reload Zed after saving.`,
      };

    case 'generic':
      return {
        content: JSON.stringify(
          {
            mcpServers: {
              apilocker: baseConfig,
            },
          },
          null,
          2
        ),
        instructions: `This is the generic MCP stdio server config. Most MCP-compatible
clients accept this shape. Consult your client's documentation for
the exact key name (sometimes "mcpServers", "context_servers", or
"tools.servers").

The bridge uses your stored master token from ~/.apilocker/config.json
as the Authorization header, so no credentials need to go in the client
config itself.`,
      };

    default:
      return null;
  }
}
