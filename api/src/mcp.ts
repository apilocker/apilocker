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
 *      reveal_key, the proxy_* tools) and only for keys in their scope.
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
 *     get_activity, run_doctor
 *
 * Proxy tools (any token type; OAuth callers need vault:proxy):
 *   - proxy_get, proxy_post, proxy_put, proxy_patch, proxy_delete
 *     One tool per HTTP method so reads and writes are separate tools.
 *     proxy-policy.ts decides which hosts and endpoints each may reach.
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
import { validateOAuthAccessToken } from './oauth-server';
import { getOAuthAccessToken } from './oauth-proxy';
import { getProviderTemplate, listProviders, listProvidersByCategory } from './providers';
import { appendQueryParam, buildProxyTargetUrl, injectApiKey } from './proxy';
import { checkProxyPolicy, ProxyMethod, PROXY_PROVIDERS_DOCS_URL } from './proxy-policy';
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
  /**
   * OAuth 2.1 scopes if the caller authenticated via an OAuth
   * access token (Claude, other remote MCP clients). Undefined for
   * master-token / scoped-token callers. Individual tool handlers
   * can inspect this to enforce vault:write vs vault:read vs
   * vault:proxy granularity beyond the simple master-token gate.
   */
  oauthScopes?: string[];
}

// ==================== TOOL CATALOG ====================

/**
 * One proxy tool per HTTP method. Anthropic's directory rejects a single
 * tool that takes both safe and unsafe methods through a `method`
 * parameter, and separate tools let Claude auto-run reads while always
 * confirming writes. Its review criteria also require a custom query
 * tool's description to name or link the target API, hence the
 * provider examples and docs link.
 */
function proxyTool(
  method: ProxyMethod,
  title: string,
  summary: string,
  annotations: { readOnlyHint: boolean; destructiveHint?: boolean; idempotentHint?: boolean }
) {
  const properties: Record<string, unknown> = {
    key_id: { type: 'string', description: 'ID of the credential to use (e.g. key_abc123), from list_keys.' },
    path: {
      type: 'string',
      description: "Path and optional query string appended to the credential's base URL, starting with \"/\" (e.g. /v1/models).",
    },
  };
  if (method !== 'GET') {
    properties.body = { type: 'object', description: 'JSON request body.' };
  }
  properties.headers = {
    type: 'object',
    additionalProperties: { type: 'string' },
    description: 'Extra request headers, e.g. {"anthropic-version": "2023-06-01"}. API Locker adds the authentication header itself.',
  };

  const writeLimits =
    method === 'GET'
      ? ''
      : ' Writes only reach vetted provider APIs: payment APIs (such as Stripe), purchase endpoints, and AI image, video, or audio generation endpoints are refused.';

  return {
    name: `proxy_${method.toLowerCase()}`,
    description:
      `${summary} The request goes to the REST API of the provider the credential belongs to (its base URL plus \`path\`), ` +
      `for example the OpenAI API, GitHub REST API, or Resend API. Each provider's base URL and API reference are listed at ` +
      `${PROXY_PROVIDERS_DOCS_URL} and returned by get_key_metadata. API Locker injects the stored secret server-side, so the ` +
      `raw key is never returned, and every call is recorded in the audit log.${writeLimits}`,
    inputSchema: {
      type: 'object',
      properties,
      required: ['key_id', 'path'],
    },
    annotations: { title, ...annotations, openWorldHint: true },
  };
}

const TOOLS = [
  // ---- Read tools ----
  //
  // Every tool in this catalog has an `annotations` block per MCP spec.
  // The Claude Connectors Directory submission guide requires these
  // hints so the client can render safety signals and decide whether
  // to auto-approve the call:
  //   - title: human-readable tool name
  //   - readOnlyHint: true if the tool never modifies server state
  //   - destructiveHint: true if the tool modifies state or makes
  //     external requests (only meaningful when readOnlyHint is false)
  //   - idempotentHint: true if calling twice has the same effect as
  //     once (helpful for retry behavior)
  //   - openWorldHint: true if the tool interacts with external
  //     systems beyond the vault itself
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
    annotations: {
      title: 'List credentials',
      readOnlyHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Get credential metadata',
      readOnlyHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'reveal_key',
    description:
      'Return the decrypted value of one credential by alias. For api_key credentials this is the secret string; for oauth2 credentials it is every stored field (client_id, client_secret, refresh_token, etc.). The value is a live secret, and every reveal is recorded in the audit log.',
    inputSchema: {
      type: 'object',
      properties: {
        alias: { type: 'string', description: 'The credential alias (name).' },
      },
      required: ['alias'],
    },
    annotations: {
      title: 'Reveal credential value',
      readOnlyHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'List provider templates',
      readOnlyHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Get audit activity',
      readOnlyHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'run_doctor',
    description:
      'Run a security health check on the vault. Returns warnings about stale rotations, unused keys, expiring tokens, stale devices. The same checks the CLI `apilocker doctor` command runs.',
    inputSchema: { type: 'object', properties: {} },
    annotations: {
      title: 'Run vault health check',
      readOnlyHint: true,
      openWorldHint: false,
    },
  },

  // ---- Proxy tools ----
  proxyTool('GET', 'Proxy read request (GET)', 'Send a read-only HTTP GET request to a provider API using a credential stored in API Locker.', {
    readOnlyHint: true,
  }),
  proxyTool(
    'POST',
    'Proxy create request (POST)',
    'Send an HTTP POST request (create a resource or run an action, such as an OpenAI chat completion) to a provider API using a credential stored in API Locker.',
    { readOnlyHint: false, destructiveHint: true }
  ),
  proxyTool(
    'PUT',
    'Proxy replace request (PUT)',
    'Send an HTTP PUT request (create or replace a resource) to a provider API using a credential stored in API Locker.',
    { readOnlyHint: false, destructiveHint: true, idempotentHint: true }
  ),
  proxyTool(
    'PATCH',
    'Proxy update request (PATCH)',
    'Send an HTTP PATCH request (update part of a resource) to a provider API using a credential stored in API Locker.',
    { readOnlyHint: false, destructiveHint: true }
  ),
  proxyTool(
    'DELETE',
    'Proxy delete request (DELETE)',
    'Send an HTTP DELETE request (delete a resource) to a provider API using a credential stored in API Locker.',
    { readOnlyHint: false, destructiveHint: true, idempotentHint: true }
  ),

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
    annotations: {
      title: 'Store API key',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Store OAuth credential',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Rotate credential value',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Rename credential alias',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Pause credential',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Resume credential',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Delete credential',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'list_tokens',
    description:
      'List scoped access tokens for the user\'s account. Each token authorizes proxy/MCP access to a specific subset of credentials. Requires master token auth.',
    inputSchema: { type: 'object', properties: {} },
    annotations: {
      title: 'List scoped tokens',
      readOnlyHint: true,
      openWorldHint: false,
    },
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
    annotations: {
      title: 'Create scoped token',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Pause scoped token',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Resume scoped token',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
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
    annotations: {
      title: 'Revoke scoped token',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'list_devices',
    description: 'List all devices registered to the user\'s account. Requires master token auth.',
    inputSchema: { type: 'object', properties: {} },
    annotations: {
      title: 'List registered devices',
      readOnlyHint: true,
      openWorldHint: false,
    },
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
    annotations: {
      title: 'Revoke device',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
  },
];

// ==================== AUTH ====================

async function validateMCPAuth(request: Request, env: Env): Promise<MCPAuthContext | null> {
  // Try OAuth 2.1 access token first (new in v1.0.3). This is how
  // Claude and other remote MCP clients authenticate after going
  // through the authorization code flow + DCR. The caller gets full
  // read access to the user's vault (allowedKeys=null), and the
  // scopes list carries through so write-tool gates can check for
  // vault:write. See isMasterToken below for the per-tool logic.
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const bearerToken = authHeader.slice(7);
    const oauth = await validateOAuthAccessToken(bearerToken, env);
    if (oauth) {
      // OAuth tokens must at minimum have vault:read to use /v1/mcp.
      // A token with only vault:write would be strange and we reject
      // it rather than silently granting read access.
      if (!oauth.scopes.includes('vault:read')) {
        return null;
      }
      return {
        userId: oauth.user_id,
        tokenId: oauth.token_id,
        // vault:read implies the token can see all of the user's keys
        // via read tools; individual write tools check oauthScopes
        // for vault:write via isMasterToken() below.
        allowedKeys: null,
        oauthScopes: oauth.scopes,
      };
    }
  }

  // Fall back to scoped token (existing path; preserves backwards compat)
  const scoped = await validateScopedToken(request, env);
  if (scoped) {
    return {
      userId: scoped.userId,
      tokenId: scoped.tokenId,
      allowedKeys: scoped.allowedKeys,
    };
  }
  // Then master token via validateSession (cookie OR Bearer master token)
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
  // OAuth callers: master-token-equivalent iff vault:write scope was
  // approved. This is what gates write tools (store, rotate, rename,
  // pause/resume, delete, token management, device management) for
  // remote MCP clients that authenticated via OAuth.
  if (auth.oauthScopes !== undefined) {
    return auth.oauthScopes.includes('vault:write');
  }
  // Non-OAuth callers (dashboard session, CLI device master token,
  // legacy scoped tokens): master iff no allowedKeys restriction.
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
    // MCP clients send GET with Accept: text/event-stream to open a
    // server-to-client stream. We never push server-initiated messages,
    // and the Streamable HTTP spec says to answer that GET with 405.
    if (request.headers.get('Accept')?.includes('text/event-stream')) {
      return jsonError('This MCP server does not offer a server-to-client stream', 405);
    }
    return jsonOk({
      name: 'apilocker',
      version: '1.1.0',
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
    // MCP spec requires 401 responses to include WWW-Authenticate with
    // a pointer to the protected resource metadata. Without this header,
    // Claude.ai's MCP client can't discover the authorization server and
    // the connector flow silently fails even though our OAuth endpoints
    // work correctly. This was the root cause of the "Authorization with
    // the MCP server failed" error — Claude completed OAuth and got a
    // token, but couldn't link it back to the resource. `scope` tells the
    // client which scopes to request.
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate':
            'Bearer resource_metadata="https://api.apilocker.app/.well-known/oauth-protected-resource", scope="vault:read vault:write vault:proxy"',
        },
      }
    );
  }

  let rpc: MCPRequest;
  try {
    const body = await request.json();
    // Handle JSON-RPC batch (array) — some MCP clients send batched
    // requests. For now, process only the first message. Full batch
    // support is a future enhancement.
    rpc = (Array.isArray(body) ? body[0] : body) as MCPRequest;
  } catch {
    return jsonOk(rpcError(0, -32700, 'Parse error'));
  }

  if (!rpc || rpc.jsonrpc !== '2.0' || !rpc.method) {
    return jsonOk(rpcError(rpc?.id || 0, -32600, 'Invalid request'));
  }

  switch (rpc.method) {
    // Protocol lifecycle methods.
    //
    // We support multiple protocol versions for compatibility with a
    // range of MCP clients. We echo back the client's requested version
    // if it's in our supported set, otherwise default to the latest.
    // This is how the MCP spec describes protocol negotiation in
    // §4.1.1 of 2025-03-26 and later.
    case 'initialize': {
      const SUPPORTED_PROTOCOL_VERSIONS = [
        '2025-06-18',
        '2025-03-26',
        '2024-11-05',
      ];
      const clientVersion = rpc.params?.protocolVersion as string | undefined;
      const protocolVersion =
        clientVersion && SUPPORTED_PROTOCOL_VERSIONS.includes(clientVersion)
          ? clientVersion
          : SUPPORTED_PROTOCOL_VERSIONS[0];
      return jsonOk(
        rpcResult(rpc.id, {
          protocolVersion,
          serverInfo: {
            name: 'apilocker',
            title: 'API Locker',
            version: '1.1.0',
          },
          capabilities: {
            tools: { listChanged: false },
          },
          instructions:
            'API Locker — encrypted credential vault. Use list_keys to discover what credentials the user has stored, the proxy tools (proxy_get for reads; proxy_post, proxy_put, proxy_patch, proxy_delete for writes) to call a provider API with a stored credential without ever seeing the raw key, reveal_key to read a secret value (only when the user explicitly asks), and run_doctor to audit vault health. Treat all reveal_key responses as highly sensitive; do not log or echo them.',
        })
      );
    }
    case 'notifications/initialized':
      // Notification (no id) — per MCP Streamable HTTP spec, notifications
      // should be acknowledged with HTTP 204 No Content, not a JSON body.
      // Returning JSON here caused Claude.ai's connector flow to fail
      // because the client treated the non-standard response as a protocol
      // error, even though the OAuth token exchange completed successfully.
      return new Response(null, { status: 204 });
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

      // ---- Proxy tools (OAuth callers need vault:proxy) ----
      case 'proxy_get':
      case 'proxy_post':
      case 'proxy_put':
      case 'proxy_patch':
      case 'proxy_delete':
        if (auth.oauthScopes !== undefined && !auth.oauthScopes.includes('vault:proxy')) {
          return mcpText(
            rpc.id,
            'Error: this connection was not granted the vault:proxy scope. Reconnect API Locker and approve proxy access to use the proxy tools.',
            true
          );
        }
        return await toolProxyRequest(
          rpc,
          env,
          auth,
          args,
          originalRequest,
          toolName.slice('proxy_'.length).toUpperCase() as ProxyMethod
        );

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
    api_docs_url: getProviderTemplate(row.provider)?.api_docs_url ?? null,
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

  // Audit log (awaited: Workers drop unawaited promises once the response returns)
  await insertAuditLog(env, {
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
      api_docs_url: p.api_docs_url,
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

/** Proxied responses above this size are truncated before reaching the agent. */
const MAX_PROXY_RESPONSE_CHARS = 50_000;

async function toolProxyRequest(
  rpc: MCPRequest,
  env: Env,
  auth: MCPAuthContext,
  args: any,
  request: Request,
  method: ProxyMethod
): Promise<Response> {
  const { key_id, path, headers: extraHeaders } = args;
  // GET never carries a body, even if one is passed.
  const body = method === 'GET' ? undefined : args.body;
  if (!key_id || typeof path !== 'string') return mcpText(rpc.id, 'Error: key_id and path are required', true);
  if (!path.startsWith('/')) {
    return mcpText(rpc.id, `Error: path must start with "/" (for example "/v1/models"), got "${path}"`, true);
  }

  if (auth.allowedKeys !== null && !auth.allowedKeys.includes(key_id)) {
    return mcpText(rpc.id, 'Token does not have access to this key', true);
  }

  const metadata = await getKeyMetadata(env, key_id, auth.userId);
  if (!metadata) return mcpText(rpc.id, 'Key not found', true);
  if (metadata.paused_at)
    return mcpText(rpc.id, `Key "${metadata.name}" is paused. Resume it before proxying.`, true);
  if (!metadata.base_url)
    return mcpText(rpc.id, 'This credential has no base_url configured (vault-only).', true);

  const targetUrl = buildProxyTargetUrl(metadata.base_url, path);
  if (!targetUrl) {
    return mcpText(rpc.id, `Error: path "${path}" must stay on ${metadata.base_url} (for example "/v1/models").`, true);
  }

  const blocked = checkProxyPolicy({ method, url: new URL(targetUrl), headers: extraHeaders, body });
  if (blocked) return mcpText(rpc.id, blocked, true);

  const outgoingHeaders = new Headers();
  outgoingHeaders.set('Content-Type', 'application/json');
  if (extraHeaders && typeof extraHeaders === 'object') {
    for (const [k, v] of Object.entries(extraHeaders)) outgoingHeaders.set(k, String(v));
  }

  let finalUrl: string;

  if (metadata.credential_type === 'oauth2') {
    // Level 2 OAuth orchestration: get a cached or refreshed access_token
    // from the vault's token lifecycle manager and inject as Bearer.
    let accessToken: string;
    try {
      accessToken = await getOAuthAccessToken(env, key_id, metadata);
    } catch (e: any) {
      return mcpText(rpc.id, `OAuth proxy error: ${e.message}`, true);
    }
    outgoingHeaders.set('Authorization', `Bearer ${accessToken}`);
    finalUrl = targetUrl;
  } else {
    // api_key credential: decrypt and inject directly, the same way the
    // app-facing proxy does.
    const blob = await env.KEYS.get(key_id);
    if (!blob) return mcpText(rpc.id, 'Encrypted blob missing', true);
    const encrypted: EncryptedKeyRecord = JSON.parse(blob);
    const realKey = await decrypt(encrypted, env);

    const template = getProviderTemplate(metadata.provider);
    injectApiKey(outgoingHeaders, metadata, template?.auth_header_name ?? null, realKey);
    finalUrl =
      metadata.auth_header_type === 'query'
        ? appendQueryParam(targetUrl, template?.query_param_name ?? 'api_key', realKey)
        : targetUrl;
  }

  const startTime = Date.now();
  let providerResponse: Response | null = null;
  let fetchError: string | null = null;
  try {
    providerResponse = await fetch(finalUrl, {
      method,
      headers: outgoingHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e: any) {
    fetchError = e.message;
  }

  // Awaited: Workers drop unawaited promises once the response returns,
  // and the audit log is part of the tool's contract.
  await insertAuditLog(env, {
    id: generateId('log'),
    user_id: auth.userId,
    token_id: auth.tokenId,
    key_id,
    provider: metadata.provider,
    forward_path: path,
    source_ip: request.headers.get('CF-Connecting-IP'),
    country: request.headers.get('CF-IPCountry') || null,
    status_code: providerResponse ? providerResponse.status : 502,
    latency_ms: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  }).catch(() => {});

  if (!providerResponse) return mcpText(rpc.id, `Failed to reach provider — ${fetchError}`, true);

  const statusCode = providerResponse.status;
  let responseText = await providerResponse.text();
  if (responseText.length > MAX_PROXY_RESPONSE_CHARS) {
    responseText =
      `${responseText.slice(0, MAX_PROXY_RESPONSE_CHARS)}\n\n[Truncated: the response was ${responseText.length} characters; ` +
      `showing the first ${MAX_PROXY_RESPONSE_CHARS}. Narrow the request with filters or pagination to see the rest.]`;
  }
  return mcpText(rpc.id, `Status: ${statusCode}\n\n${responseText}`, statusCode >= 400);
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

  await insertAuditLog(env, {
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
