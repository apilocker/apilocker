/**
 * MCP server for AI agents (v1.0.0 — full parity with CLI / dashboard).
 *
 * Implements the Model Context Protocol so agents can interact with API
 * Locker the same way the CLI and dashboard do. Every meaningful vault
 * operation is exposed as an MCP tool.
 *
 * # Auth model (dual-path, v1.0.0)
 *
 * MCP requests authenticate via the Authorization Bearer header. We
 * accept TWO token types:
 *
 *   1. **Scoped tokens** — same kind apps use for the proxy. Has a
 *      pre-approved `allowedKeys` whitelist. Agents using a scoped
 *      token can only call read tools (list_keys, get_key_metadata,
 *      reveal_key, proxy_request) and only for keys in their scope.
 *      All write/management tools are rejected.
 *
 *   2. **Master tokens** — same kind the CLI uses. Full account access.
 *      Agents using a master token can call every tool, including
 *      management operations (store, rotate, rename, pause, devices,
 *      tokens, etc.).
 *
 * The threat model: scoped tokens for untrusted/shared agents, master
 * tokens for trusted agents the user owns (e.g., Claude Desktop bound
 * to your own account). Both work simultaneously.
 *
 * # Tool catalog
 *
 * Read tools (any token type):
 *   - list_keys, get_key_metadata, reveal_key, list_providers,
 *     get_activity, run_doctor, proxy_request
 *
 * Write tools (master token only):
 *   - store_key, store_oauth_credential, rotate_key, rename_key,
 *     pause_key, resume_key, delete_key
 *   - list_tokens, create_token, pause_token, resume_token,
 *     revoke_token
 *   - list_devices, revoke_device
 *
 * Every tool returns MCP-format responses: { content: [{type:'text', text:...}] }.
 */

import {
  Env,
  EncryptedKeyRecord,
  KeyMetadata,
  OAuthCredentialFields,
  CredentialType,
} from './types';
import { decrypt, encrypt, generateId, generateToken, hashToken } from './crypto';
import {
  listKeyMetadata,
  getKeyMetadata,
  getKeyMetadataByName,
  insertKeyMetadata,
  deleteKeyMetadata,
  renameKeyMetadata,
  pauseKeyMetadata,
  resumeKeyMetadata,
  markKeyRotated,
  insertAuditLog,
  purgeFromPreviousNames,
  listTokens,
  insertToken,
  pauseToken,
  resumeToken,
  hardDeleteToken,
  getTokenById,
  listDevices,
  revokeDevice,
  queryAuditLogs,
} from './db';
import { validateScopedToken, validateSession } from './auth';
import { getProviderTemplate, listProviders, listProvidersByCategory } from './providers';
import { jsonOk, jsonError } from './responses';

// ==================== TYPES ====================

interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: any;
}

interface MCPResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: any;
  error?: { code: number; message: string };
}

interface MCPAuthContext {
  userId: string;
  tokenId: string | null; // null = master token
  /** null = all keys (master token); array = scoped allowedKeys */
  allowedKeys: string[] | null;
}

// ==================== TOOL CATALOG ====================

const TOOLS = [
  // ---- Read tools ----
  {
    name: 'list_keys',
    description:
      'List credentials in the user\'s vault grouped by category (LLM / Service / OAuth). Returns metadata only — never raw secret values. Optionally filter by category, provider, or tag.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          enum: ['llm', 'service', 'oauth'],
          description: 'Filter by category. Omit to return all.',
        },
        provider: {
          type: 'string',
          description: 'Filter by provider id (e.g. openai, stripe, google-oauth).',
        },
        tag: {
          type: 'string',
          description: 'Filter by a tag.',
        },
      },
    },
  },
  {
    name: 'get_key_metadata',
    description:
      'Get full metadata for one credential by its alias (name). Returns provider, type, tags, paused state, rotation history. Does not reveal the secret value.',
    inputSchema: {
      type: 'object',
      properties: {
        alias: { type: 'string', description: 'The credential alias (name).' },
      },
      required: ['alias'],
    },
  },
  {
    name: 'reveal_key',
    description:
      'Reveal the decrypted value of a credential by alias. For api_key credentials, returns the single secret string. For oauth2 credentials, returns the full multi-field object (client_id, client_secret, refresh_token, etc.). The agent should treat the response as sensitive — log it, store it, or pass it carefully.',
    inputSchema: {
      type: 'object',
      properties: {
        alias: { type: 'string', description: 'The credential alias (name).' },
      },
      required: ['alias'],
    },
  },
  {
    name: 'list_providers',
    description:
      'List all available provider templates. Useful for discovering what providers can be used when storing new credentials.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          enum: ['llm', 'service', 'oauth'],
          description: 'Filter by category. Omit to return all.',
        },
      },
    },
  },
  {
    name: 'get_activity',
    description:
      'Get recent audit log entries showing how credentials have been used. Returns proxy calls, reveals, rotations, renames, pauses, etc. Each entry includes timestamp, status code, latency, and the credential involved.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max entries to return (default 50, max 200).' },
        key_id: { type: 'string', description: 'Filter by a specific key ID.' },
        token_id: { type: 'string', description: 'Filter by a specific token ID.' },
      },
    },
  },
  {
    name: 'run_doctor',
    description:
      'Run a security health check on the vault. Returns warnings about stale rotations, unused keys, expiring tokens, stale devices. The same checks the CLI `apilocker doctor` command runs.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'proxy_request',
    description:
      'Make an API request through the locker proxy. The real API key is injected automatically — the agent never sees the raw secret. Use this when you need to call an external API (OpenAI, Stripe, etc.) using a stored credential.',
    inputSchema: {
      type: 'object',
      properties: {
        key_id: { type: 'string', description: 'The key ID to use for this request (e.g. key_abc123).' },
        path: { type: 'string', description: 'The API path to call (e.g. /v1/chat/completions).' },
        method: { type: 'string', description: 'HTTP method (GET, POST, PUT, DELETE).', default: 'POST' },
        body: { type: 'object', description: 'Request body (will be JSON-encoded).' },
        headers: { type: 'object', description: 'Additional headers to include.' },
      },
      required: ['key_id', 'path'],
    },
  },

  // ---- Write tools (master token only) ----
  {
    name: 'store_key',
    description:
      'Store a new api_key credential in the vault. The secret is encrypted with AES-GCM before being stored. Use store_oauth_credential for multi-field OAuth credentials. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Credential alias (e.g. OPENAI_API_KEY). Must be unique.' },
        provider: { type: 'string', description: 'Provider id (e.g. openai, stripe). Use list_providers to discover available providers.' },
        key: { type: 'string', description: 'The raw secret value.' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags for organization.' },
        base_url: { type: 'string', description: 'Optional base URL for proxy access. Omit for vault-only credentials.' },
      },
      required: ['name', 'provider', 'key'],
    },
  },
  {
    name: 'store_oauth_credential',
    description:
      'Store a new OAuth multi-field credential (client_id, client_secret, refresh_token, etc.). For OAuth providers like Google, GitHub, Slack, Microsoft, Notion, Spotify, Twitter, LinkedIn, Discord, Zoom, Dropbox, Salesforce, HubSpot. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Credential alias (e.g. google-oauth).' },
        provider: { type: 'string', description: 'OAuth provider id (e.g. google-oauth, github-oauth).' },
        client_id: { type: 'string' },
        client_secret: { type: 'string' },
        refresh_token: { type: 'string', description: 'Optional.' },
        authorize_url: { type: 'string', description: 'Optional override of the template default.' },
        token_url: { type: 'string', description: 'Optional override of the template default.' },
        scopes: { type: 'string', description: 'Space-separated OAuth scopes.' },
        redirect_uri: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
      },
      required: ['name', 'provider', 'client_id', 'client_secret'],
    },
  },
  {
    name: 'rotate_key',
    description:
      'Replace a credential\'s value in place with a new one. The credential\'s name, provider, and all metadata stay the same. Scoped tokens that reference the key continue to work. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: {
        alias: { type: 'string', description: 'The credential alias to rotate.' },
        new_value: { type: 'string', description: 'The new secret value.' },
      },
      required: ['alias', 'new_value'],
    },
  },
  {
    name: 'rename_key',
    description:
      'Rename a credential alias. The old name is remembered as a legacy alias forever, so existing references to the old name continue to work transparently. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: {
        old_alias: { type: 'string' },
        new_alias: { type: 'string' },
      },
      required: ['old_alias', 'new_alias'],
    },
  },
  {
    name: 'pause_key',
    description:
      'Pause proxy access for a credential without deleting it. Reveal/run/get/env operations still work on paused credentials. The proxy returns HTTP 423 for paused keys until they are resumed. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { alias: { type: 'string' } },
      required: ['alias'],
    },
  },
  {
    name: 'resume_key',
    description: 'Resume proxy access for a paused credential. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { alias: { type: 'string' } },
      required: ['alias'],
    },
  },
  {
    name: 'delete_key',
    description:
      'Permanently delete a credential. The encrypted blob is removed from KV and the metadata row is removed from D1. This cannot be undone. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { alias: { type: 'string', description: 'The credential alias to delete.' } },
      required: ['alias'],
    },
  },
  {
    name: 'list_tokens',
    description:
      'List scoped access tokens for the user\'s account. Each token authorizes proxy/MCP access to a specific subset of credentials. Requires master token auth.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_token',
    description:
      'Create a new scoped access token. Returns the access token and (for rotating tokens) the refresh token. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        allowed_keys: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of key IDs (not aliases) the token can access.',
        },
        rotation_type: {
          type: 'string',
          enum: ['static', 'hourly', 'daily', 'weekly', 'monthly'],
          description: 'How often the access token rotates. Defaults to static.',
        },
      },
      required: ['name', 'allowed_keys'],
    },
  },
  {
    name: 'pause_token',
    description: 'Pause a scoped token. Paused tokens cannot be used until resumed. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { token_id: { type: 'string' } },
      required: ['token_id'],
    },
  },
  {
    name: 'resume_token',
    description: 'Resume a paused scoped token. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { token_id: { type: 'string' } },
      required: ['token_id'],
    },
  },
  {
    name: 'revoke_token',
    description: 'Permanently revoke (delete) a scoped token. Cannot be undone. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { token_id: { type: 'string' } },
      required: ['token_id'],
    },
  },
  {
    name: 'list_devices',
    description: 'List all devices registered to the user\'s account. Requires master token auth.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'revoke_device',
    description:
      'Revoke a registered device. The device\'s master token immediately stops working. Requires master token auth.',
    inputSchema: {
      type: 'object',
      properties: { device_id: { type: 'string' } },
      required: ['device_id'],
    },
  },
];

// ==================== AUTH ====================

async function validateMCPAuth(request: Request, env: Env): Promise<MCPAuthContext | null> {
  // Try scoped token first (existing path; preserves backwards compat)
  const scoped = await validateScopedToken(request, env);
  if (scoped) {
    return {
      userId: scoped.userId,
      tokenId: scoped.tokenId,
      allowedKeys: scoped.allowedKeys,
    };
  }
  // Fall back to master token via validateSession (cookie OR Bearer master token)
  const userId = await validateSession(request, env);
  if (userId) {
    return {
      userId,
      tokenId: null,
      allowedKeys: null, // null = full account access
    };
  }
  return null;
}

function isMasterToken(auth: MCPAuthContext): boolean {
  return auth.allowedKeys === null;
}

function requireMasterToken(rpcId: string | number): Response {
  return jsonOk(
    rpcResult(rpcId, {
      content: [
        {
          type: 'text',
          text: 'Error: this tool requires a master token. Scoped tokens cannot perform vault management operations.',
        },
      ],
      isError: true,
    })
  );
}

// ==================== ENTRY POINT ====================

export async function handleMCP(
  request: Request,
  env: Env,
  _params: Record<string, string>
): Promise<Response> {
  // GET = server info / discovery (unauthenticated)
  if (request.method === 'GET') {
    return jsonOk({
      name: 'apilocker',
      version: '1.0.0',
      description:
        'API Locker — one vault for LLM keys, service API keys, and OAuth credentials. Manage credentials, run health checks, and proxy API calls.',
      tools: TOOLS,
    });
  }

  if (request.method !== 'POST') {
    return jsonError('Method not allowed', 405);
  }

  // Auth — accepts either scoped or master tokens
  const auth = await validateMCPAuth(request, env);
  if (!auth) {
    return jsonError(
      'Unauthorized — provide a scoped token or master token via Authorization: Bearer header',
      401
    );
  }

  let rpc: MCPRequest;
  try {
    rpc = await request.json();
  } catch {
    return jsonOk(rpcError(0, -32700, 'Parse error'));
  }

  if (rpc.jsonrpc !== '2.0' || !rpc.method) {
    return jsonOk(rpcError(rpc.id || 0, -32600, 'Invalid request'));
  }

  switch (rpc.method) {
    // Protocol lifecycle methods
    case 'initialize':
      return jsonOk(
        rpcResult(rpc.id, {
          protocolVersion: '2024-11-05',
          serverInfo: {
            name: 'apilocker',
            version: '1.0.0',
          },
          capabilities: {
            tools: {},
          },
        })
      );
    case 'notifications/initialized':
      // Notification (no id) — return empty success for HTTP transport.
      // stdio transport clients ignore this response entirely.
      return jsonOk({ jsonrpc: '2.0' });
    case 'ping':
      return jsonOk(rpcResult(rpc.id, {}));

    // Unsupported but spec-defined methods — return empty lists so
    // compliant clients don't error out
    case 'resources/list':
      return jsonOk(rpcResult(rpc.id, { resources: [] }));
    case 'prompts/list':
      return jsonOk(rpcResult(rpc.id, { prompts: [] }));

    // Core MCP methods
    case 'tools/list':
      return jsonOk(rpcResult(rpc.id, { tools: TOOLS }));
    case 'tools/call':
      return handleToolCall(rpc, env, auth, request);

    default:
      return jsonOk(rpcError(rpc.id, -32601, `Method not found: ${rpc.method}`));
  }
}

// ==================== TOOL DISPATCH ====================

async function handleToolCall(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  originalRequest: Request
): Promise<Response> {
  const toolName = rpc.params?.name;
  const args = rpc.params?.arguments || {};

  try {
    switch (toolName) {
      // ---- Read tools (any auth) ----
      case 'list_keys':
        return await toolListKeys(rpc, env, auth, args);
      case 'get_key_metadata':
        return await toolGetKeyMetadata(rpc, env, auth, args);
      case 'reveal_key':
        return await toolRevealKey(rpc, env, auth, args, originalRequest);
      case 'list_providers':
        return toolListProviders(rpc, args);
      case 'get_activity':
        return await toolGetActivity(rpc, env, auth, args);
      case 'run_doctor':
        return await toolRunDoctor(rpc, env, auth);
      case 'proxy_request':
        return await toolProxyRequest(rpc, env, auth, args, originalRequest);

      // ---- Write tools (master token required) ----
      case 'store_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolStoreKey(rpc, env, auth, args);
      case 'store_oauth_credential':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolStoreOAuthCredential(rpc, env, auth, args);
      case 'rotate_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolRotateKey(rpc, env, auth, args, originalRequest);
      case 'rename_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolRenameKey(rpc, env, auth, args);
      case 'pause_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolPauseKey(rpc, env, auth, args);
      case 'resume_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolResumeKey(rpc, env, auth, args);
      case 'delete_key':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolDeleteKey(rpc, env, auth, args);
      case 'list_tokens':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolListTokens(rpc, env, auth);
      case 'create_token':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolCreateToken(rpc, env, auth, args);
      case 'pause_token':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolPauseToken(rpc, env, auth, args);
      case 'resume_token':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolResumeToken(rpc, env, auth, args);
      case 'revoke_token':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolRevokeToken(rpc, env, auth, args);
      case 'list_devices':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolListDevices(rpc, env, auth);
      case 'revoke_device':
        if (!isMasterToken(auth)) return requireMasterToken(rpc.id);
        return await toolRevokeDevice(rpc, env, auth, args);

      default:
        return mcpText(rpc.id, `Unknown tool: ${toolName}`, true);
    }
  } catch (e: any) {
    console.error(`MCP tool ${toolName} error:`, e);
    return mcpText(rpc.id, `Error in ${toolName}: ${e.message}`, true);
  }
}

// ==================== TOOL IMPLEMENTATIONS ====================

async function toolListKeys(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const keys = await listKeyMetadata(env, auth.userId);
  let filtered = keys;
  if (auth.allowedKeys !== null) {
    const allowed = new Set(auth.allowedKeys);
    filtered = filtered.filter((k) => allowed.has(k.id));
  }
  if (args.category) {
    filtered = filtered.filter((k) => {
      const cat = getProviderTemplate(k.provider)?.category ?? 'service';
      return cat === args.category;
    });
  }
  if (args.provider) {
    filtered = filtered.filter((k) => k.provider === args.provider);
  }
  if (args.tag) {
    filtered = filtered.filter((k) => {
      try {
        const tags = JSON.parse(k.tags || '[]');
        return Array.isArray(tags) && tags.includes(args.tag);
      } catch {
        return false;
      }
    });
  }

  const result = filtered.map((k) => ({
    id: k.id,
    name: k.name,
    provider: k.provider,
    category: getProviderTemplate(k.provider)?.category ?? 'service',
    credential_type: k.credential_type ?? 'api_key',
    tags: safeParseJSON(k.tags, []),
    base_url: k.base_url || null,
    paused: k.paused_at != null,
    rotated_at: k.rotated_at,
    created_at: k.created_at,
  }));

  return mcpJSON(rpc.id, { count: result.length, keys: result });
}

async function toolGetKeyMetadata(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  if (auth.allowedKeys !== null && !auth.allowedKeys.includes(row.id)) {
    return mcpText(rpc.id, `Token does not have access to "${args.alias}"`, true);
  }
  return mcpJSON(rpc.id, {
    id: row.id,
    name: row.name,
    provider: row.provider,
    category: getProviderTemplate(row.provider)?.category ?? 'service',
    credential_type: row.credential_type ?? 'api_key',
    tags: safeParseJSON(row.tags, []),
    base_url: row.base_url || null,
    paused: row.paused_at != null,
    rotated_at: row.rotated_at,
    created_at: row.created_at,
    previous_names: safeParseJSON(row.previous_names, []),
  });
}

async function toolRevealKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any,
  request: Request
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  if (auth.allowedKeys !== null && !auth.allowedKeys.includes(row.id)) {
    return mcpText(rpc.id, `Token does not have access to "${args.alias}"`, true);
  }

  const blob = await env.KEYS.get(row.id);
  if (!blob) return mcpText(rpc.id, 'Encrypted blob missing', true);
  const encrypted: EncryptedKeyRecord = JSON.parse(blob);
  const plaintext = await decrypt(encrypted, env);

  // Audit log
  insertAuditLog(env, {
    id: generateId('log'),
    user_id: auth.userId,
    token_id: auth.tokenId,
    key_id: row.id,
    provider: row.provider,
    forward_path: '/reveal',
    source_ip: request.headers.get('CF-Connecting-IP'),
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
    country: request.headers.get('CF-IPCountry') || null,
  }).catch(() => {});

  if (row.credential_type === 'oauth2') {
    let fields: OAuthCredentialFields;
    try {
      fields = JSON.parse(plaintext) as OAuthCredentialFields;
    } catch {
      return mcpText(rpc.id, 'Corrupt OAuth credential blob', true);
    }
    return mcpJSON(rpc.id, {
      name: row.name,
      provider: row.provider,
      credential_type: 'oauth2',
      fields,
    });
  }

  return mcpJSON(rpc.id, {
    name: row.name,
    provider: row.provider,
    credential_type: 'api_key',
    value: plaintext,
  });
}

function toolListProviders(rpc: MCPRequest, args: any): Response {
  const providers =
    args.category && ['llm', 'service', 'oauth'].includes(args.category)
      ? listProvidersByCategory(args.category)
      : listProviders();
  return mcpJSON(rpc.id, {
    count: providers.length,
    providers: providers.map((p) => ({
      id: p.id,
      name: p.name,
      category: p.category,
      credential_type: p.credential_type,
      base_url: p.base_url,
      auth_header_type: p.auth_header_type,
      auth_header_name: p.auth_header_name,
      authorize_url: p.authorize_url,
      token_url: p.token_url,
      default_scopes: p.default_scopes,
    })),
  });
}

async function toolGetActivity(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const limit = Math.min(args.limit || 50, 200);
  const logs = await queryAuditLogs(env, auth.userId, {
    key_id: args.key_id,
    token_id: args.token_id,
    limit,
  });
  return mcpJSON(rpc.id, { count: logs.length, logs });
}

async function toolRunDoctor(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext
): Promise<Response> {
  // Reuse the same checks the CLI doctor command runs (computed server-side
  // here for the agent's convenience).
  const keys = await listKeyMetadata(env, auth.userId);
  const tokens = await listTokens(env, auth.userId);
  const devices = await listDevices(env, auth.userId);
  const recentActivity = await queryAuditLogs(env, auth.userId, { limit: 500 });

  const findings: Array<{ severity: string; category: string; summary: string; details: string[] }> = [];
  const now = Date.now();
  const daysSince = (iso: string | null) => {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (isNaN(t)) return null;
    return Math.floor((now - t) / 86400000);
  };

  // 1. Stale rotations (90+ days)
  const staleRotations = keys.filter((k) => {
    const ref = k.rotated_at || k.created_at;
    const d = daysSince(ref);
    return d != null && d >= 90;
  });
  if (staleRotations.length) {
    findings.push({
      severity: 'warn',
      category: 'rotation',
      summary: `${staleRotations.length} key(s) not rotated in 90+ days`,
      details: staleRotations.slice(0, 10).map((k) => `${k.name} — ${daysSince(k.rotated_at || k.created_at)} days`),
    });
  }

  // 2. Unused keys
  const cutoff = now - 30 * 86400000;
  const activeKeyIds = new Set<string>();
  for (const log of recentActivity) {
    if (!log.key_id) continue;
    const t = new Date(log.timestamp).getTime();
    if (t >= cutoff) activeKeyIds.add(log.key_id);
  }
  const unused = keys.filter((k) => !activeKeyIds.has(k.id));
  if (unused.length) {
    findings.push({
      severity: 'info',
      category: 'unused',
      summary: `${unused.length} key(s) with no activity in 30+ days`,
      details: unused.slice(0, 10).map((k) => k.name),
    });
  }

  // 3. Stale devices
  const staleDevices = devices.filter((d) => {
    const days = daysSince(d.last_used_at);
    return days != null && days >= 60;
  });
  if (staleDevices.length) {
    findings.push({
      severity: 'warn',
      category: 'devices',
      summary: `${staleDevices.length} device(s) not seen in 60+ days`,
      details: staleDevices.slice(0, 10).map((d) => `${d.name} — ${daysSince(d.last_used_at)} days`),
    });
  }

  // 4. Paused credentials
  const paused = keys.filter((k) => k.paused_at);
  if (paused.length) {
    findings.push({
      severity: 'info',
      category: 'paused',
      summary: `${paused.length} credential(s) currently paused`,
      details: paused.slice(0, 10).map((k) => k.name),
    });
  }

  return mcpJSON(rpc.id, {
    findings,
    summary: {
      warnings: findings.filter((f) => f.severity === 'warn').length,
      info: findings.filter((f) => f.severity === 'info').length,
    },
  });
}

async function toolProxyRequest(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any,
  request: Request
): Promise<Response> {
  const { key_id, path, method = 'POST', body, headers: extraHeaders } = args;
  if (!key_id || !path) return mcpText(rpc.id, 'Error: key_id and path are required', true);

  if (auth.allowedKeys !== null && !auth.allowedKeys.includes(key_id)) {
    return mcpText(rpc.id, 'Token does not have access to this key', true);
  }

  const metadata = await getKeyMetadata(env, key_id, auth.userId);
  if (!metadata) return mcpText(rpc.id, 'Key not found', true);
  if (metadata.paused_at)
    return mcpText(rpc.id, `Key "${metadata.name}" is paused. Resume it before proxying.`, true);
  if (!metadata.base_url)
    return mcpText(rpc.id, 'This credential has no base_url configured (vault-only).', true);
  if (metadata.credential_type === 'oauth2')
    return mcpText(
      rpc.id,
      'OAuth credentials cannot be proxied yet. Use reveal_key to fetch the fields and call the provider directly.',
      true
    );

  const blob = await env.KEYS.get(key_id);
  if (!blob) return mcpText(rpc.id, 'Encrypted blob missing', true);
  const encrypted: EncryptedKeyRecord = JSON.parse(blob);
  const realKey = await decrypt(encrypted, env);

  const targetUrl = `${metadata.base_url}${path}`;
  const outgoingHeaders = new Headers();
  outgoingHeaders.set('Content-Type', 'application/json');
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) outgoingHeaders.set(k, v as string);
  }

  // Inject auth header (respecting custom header name from template)
  const template = getProviderTemplate(metadata.provider);
  if (template?.auth_header_name) {
    outgoingHeaders.set(template.auth_header_name, realKey);
  } else {
    switch (metadata.auth_header_type) {
      case 'bearer':
        outgoingHeaders.set('Authorization', `Bearer ${realKey}`);
        break;
      case 'x-api-key':
        outgoingHeaders.set('X-API-Key', realKey);
        break;
      case 'basic':
        outgoingHeaders.set('Authorization', `Basic ${realKey}`);
        break;
    }
  }

  const finalUrl =
    metadata.auth_header_type === 'query'
      ? `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${
          template?.query_param_name ?? 'api_key'
        }=${encodeURIComponent(realKey)}`
      : targetUrl;

  const startTime = Date.now();
  let providerResponse: Response;
  let statusCode: number;
  try {
    providerResponse = await fetch(finalUrl, {
      method,
      headers: outgoingHeaders,
      body: body ? JSON.stringify(body) : undefined,
    });
    statusCode = providerResponse.status;
  } catch (e: any) {
    insertAuditLog(env, {
      id: generateId('log'),
      user_id: auth.userId,
      token_id: auth.tokenId,
      key_id,
      provider: metadata.provider,
      forward_path: path,
      source_ip: request.headers.get('CF-Connecting-IP'),
      country: request.headers.get('CF-IPCountry') || null,
      status_code: 502,
      latency_ms: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    }).catch(() => {});
    return mcpText(rpc.id, `Failed to reach provider — ${e.message}`, true);
  }

  insertAuditLog(env, {
    id: generateId('log'),
    user_id: auth.userId,
    token_id: auth.tokenId,
    key_id,
    provider: metadata.provider,
    forward_path: path,
    source_ip: request.headers.get('CF-Connecting-IP'),
    country: request.headers.get('CF-IPCountry') || null,
    status_code: statusCode,
    latency_ms: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  }).catch(() => {});

  const responseText = await providerResponse.text();
  return mcpText(rpc.id, `Status: ${statusCode}\n\n${responseText}`, false);
}

async function toolStoreKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  if (!args.name || !args.provider || !args.key) {
    return mcpText(rpc.id, 'Missing required fields: name, provider, key', true);
  }
  const template = getProviderTemplate(args.provider);
  const baseUrl = args.base_url ?? template?.base_url ?? '';
  const authHeaderType = template?.auth_header_type || 'bearer';

  const keyId = generateId('key');
  const encrypted = await encrypt(args.key, env);
  await env.KEYS.put(keyId, JSON.stringify(encrypted));

  try {
    await insertKeyMetadata(env, {
      id: keyId,
      user_id: auth.userId,
      name: args.name,
      provider: args.provider,
      tags: JSON.stringify(args.tags || []),
      base_url: baseUrl,
      auth_header_type: authHeaderType,
      created_at: new Date().toISOString(),
      rotated_at: null,
      credential_type: 'api_key',
      paused_at: null,
      previous_names: '[]',
    });
  } catch (e: any) {
    await env.KEYS.delete(keyId);
    if (e.message?.includes('UNIQUE')) {
      return mcpText(rpc.id, `A credential named "${args.name}" already exists`, true);
    }
    throw e;
  }

  await purgeFromPreviousNames(env, auth.userId, args.name).catch(() => {});

  return mcpJSON(rpc.id, {
    id: keyId,
    name: args.name,
    provider: args.provider,
    credential_type: 'api_key',
    proxy_endpoint: baseUrl ? `/v1/proxy/${keyId}` : null,
  });
}

async function toolStoreOAuthCredential(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  if (!args.name || !args.provider || !args.client_id || !args.client_secret) {
    return mcpText(rpc.id, 'Missing required fields: name, provider, client_id, client_secret', true);
  }
  const template = getProviderTemplate(args.provider);

  const fields: OAuthCredentialFields = {
    client_id: args.client_id,
    client_secret: args.client_secret,
    refresh_token: args.refresh_token,
    authorize_url: args.authorize_url || template?.authorize_url,
    token_url: args.token_url || template?.token_url,
    scopes: args.scopes || template?.default_scopes,
    redirect_uri: args.redirect_uri || template?.default_redirect_uri,
  };

  const keyId = generateId('key');
  const encrypted = await encrypt(JSON.stringify(fields), env);
  await env.KEYS.put(keyId, JSON.stringify(encrypted));

  try {
    await insertKeyMetadata(env, {
      id: keyId,
      user_id: auth.userId,
      name: args.name,
      provider: args.provider,
      tags: JSON.stringify(args.tags || []),
      base_url: '',
      auth_header_type: 'bearer',
      created_at: new Date().toISOString(),
      rotated_at: null,
      credential_type: 'oauth2',
      paused_at: null,
      previous_names: '[]',
    });
  } catch (e: any) {
    await env.KEYS.delete(keyId);
    if (e.message?.includes('UNIQUE')) {
      return mcpText(rpc.id, `A credential named "${args.name}" already exists`, true);
    }
    throw e;
  }

  await purgeFromPreviousNames(env, auth.userId, args.name).catch(() => {});

  return mcpJSON(rpc.id, {
    id: keyId,
    name: args.name,
    provider: args.provider,
    credential_type: 'oauth2',
  });
}

async function toolRotateKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any,
  request: Request
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  if (!args.new_value) return mcpText(rpc.id, 'Missing required field: new_value', true);

  const encrypted = await encrypt(args.new_value, env);
  await env.KEYS.put(row.id, JSON.stringify(encrypted));
  await markKeyRotated(env, row.id, auth.userId);

  insertAuditLog(env, {
    id: generateId('log'),
    user_id: auth.userId,
    token_id: null,
    key_id: row.id,
    provider: row.provider,
    forward_path: '/rotate',
    source_ip: request.headers.get('CF-Connecting-IP'),
    country: request.headers.get('CF-IPCountry') || null,
    status_code: 200,
    latency_ms: null,
    timestamp: new Date().toISOString(),
  }).catch(() => {});

  return mcpJSON(rpc.id, {
    id: row.id,
    name: row.name,
    rotated_at: new Date().toISOString(),
  });
}

async function toolRenameKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.old_alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.old_alias}`, true);
  if (!args.new_alias) return mcpText(rpc.id, 'Missing required field: new_alias', true);

  // Collision check
  const existing = await getKeyMetadataByName(env, auth.userId, args.new_alias);
  if (existing && existing.id !== row.id) {
    return mcpText(rpc.id, `A credential named "${args.new_alias}" already exists`, true);
  }

  const ok = await renameKeyMetadata(env, row.id, auth.userId, args.new_alias);
  if (!ok) return mcpText(rpc.id, 'Rename failed', true);

  return mcpJSON(rpc.id, {
    id: row.id,
    old_name: args.old_alias,
    new_name: args.new_alias,
    note: 'Lossless rename: existing references to the old name continue to work via previous_names fallback.',
  });
}

async function toolPauseKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  if (row.paused_at) return mcpText(rpc.id, 'Key is already paused', true);
  const ok = await pauseKeyMetadata(env, row.id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Pause failed', true);
  return mcpJSON(rpc.id, { id: row.id, name: row.name, paused: true });
}

async function toolResumeKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  if (!row.paused_at) return mcpText(rpc.id, 'Key is not paused', true);
  const ok = await resumeKeyMetadata(env, row.id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Resume failed', true);
  return mcpJSON(rpc.id, { id: row.id, name: row.name, paused: false });
}

async function toolDeleteKey(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const row = await getKeyMetadataByName(env, auth.userId, args.alias);
  if (!row) return mcpText(rpc.id, `Credential not found: ${args.alias}`, true);
  await env.KEYS.delete(row.id);
  await deleteKeyMetadata(env, row.id, auth.userId);
  return mcpJSON(rpc.id, { deleted: true, id: row.id, name: row.name });
}

async function toolListTokens(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext
): Promise<Response> {
  const tokens = await listTokens(env, auth.userId);
  const result = tokens.map((t) => ({
    id: t.id,
    name: t.name,
    rotation_type: t.rotation_type,
    allowed_keys: safeParseJSON(t.allowed_keys, []),
    revoked: t.revoked_at != null,
    paused: t.paused_at != null,
    current_token_expires_at: t.current_token_expires_at,
    created_at: t.created_at,
  }));
  return mcpJSON(rpc.id, { count: result.length, tokens: result });
}

async function toolCreateToken(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  if (!args.name || !Array.isArray(args.allowed_keys)) {
    return mcpText(rpc.id, 'Missing required fields: name, allowed_keys', true);
  }
  const tokenId = generateId('tok');
  const accessToken = generateToken();
  const accessHash = await hashToken(accessToken);
  const rotationType = args.rotation_type || 'static';

  // For non-static tokens, we'd also generate a refresh token, but for the
  // MCP MVP we'll keep it simple and only support static tokens.
  if (rotationType !== 'static') {
    return mcpText(
      rpc.id,
      'Only static rotation is supported via MCP for now. Use the dashboard or CLI for rotating tokens.',
      true
    );
  }

  await insertToken(env, {
    id: tokenId,
    user_id: auth.userId,
    name: args.name,
    hashed_token: accessHash,
    allowed_keys: JSON.stringify(args.allowed_keys),
    rotation_type: rotationType,
    current_token_expires_at: null,
    created_at: new Date().toISOString(),
    refresh_token_hash: null,
    refresh_token_family_id: null,
    paused_at: null,
  });

  return mcpJSON(rpc.id, {
    id: tokenId,
    name: args.name,
    access_token: accessToken,
    rotation_type: rotationType,
    note: 'Save the access_token now. It cannot be retrieved later.',
  });
}

async function toolPauseToken(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const t = await getTokenById(env, args.token_id, auth.userId);
  if (!t) return mcpText(rpc.id, 'Token not found', true);
  const ok = await pauseToken(env, args.token_id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Pause failed', true);
  return mcpJSON(rpc.id, { id: args.token_id, paused: true });
}

async function toolResumeToken(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const t = await getTokenById(env, args.token_id, auth.userId);
  if (!t) return mcpText(rpc.id, 'Token not found', true);
  const ok = await resumeToken(env, args.token_id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Resume failed', true);
  return mcpJSON(rpc.id, { id: args.token_id, paused: false });
}

async function toolRevokeToken(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const ok = await hardDeleteToken(env, args.token_id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Token not found', true);
  return mcpJSON(rpc.id, { deleted: true, id: args.token_id });
}

async function toolListDevices(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext
): Promise<Response> {
  const devices = await listDevices(env, auth.userId);
  return mcpJSON(rpc.id, {
    count: devices.length,
    devices: devices.map((d) => ({
      id: d.id,
      name: d.name,
      hostname: d.hostname,
      platform: d.platform,
      platform_version: d.platform_version,
      cli_version: d.cli_version,
      registered_at: d.registered_at,
      last_used_at: d.last_used_at,
    })),
  });
}

async function toolRevokeDevice(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any
): Promise<Response> {
  const ok = await revokeDevice(env, args.device_id, auth.userId);
  if (!ok) return mcpText(rpc.id, 'Device not found', true);
  return mcpJSON(rpc.id, { revoked: true, id: args.device_id });
}

// ==================== HELPERS ====================

function rpcResult(id: string | number, result: any): MCPResponse {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id: string | number, code: number, message: string): MCPResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function mcpText(id: string | number, text: string, isError = false): Response {
  return jsonOk(rpcResult(id, { content: [{ type: 'text', text }], isError }));
}

function mcpJSON(id: string | number, data: any): Response {
  return jsonOk(
    rpcResult(id, {
      content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
    })
  );
}

function safeParseJSON<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}
