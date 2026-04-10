/**
 * Origins allowed to make credentialed browser requests to the API.
 *
 * The www/apex are our own marketing site and dashboard.
 *
 * localhost:5173 and :3000 cover local dev for site + dashboard.
 *
 * claude.ai and claude.com are Anthropic's first-party origins for
 * Claude web and Claude Code; they load remote MCP servers from
 * https://api.apilocker.app/v1/mcp via the Connectors Directory flow
 * and require the server to send an Access-Control-Allow-Origin
 * response matching the Claude origin.
 */
const ALLOWED_ORIGINS = new Set([
  'https://www.apilocker.app',
  'https://apilocker.app',
  'http://localhost:5173',
  'http://localhost:3000',
  'https://claude.ai',
  'https://claude.com',
]);

/**
 * Build the CORS response headers for a given request origin. If the
 * origin is allowed, echo it back as Access-Control-Allow-Origin; if
 * not (no Origin header, or not in the allowlist), fall back to the
 * canonical www origin. `Vary: Origin` is always set so caches don't
 * serve the wrong ACAO to a different origin.
 */
export function buildCorsHeaders(origin: string | null): Record<string, string> {
  // For credentialed requests, ACAO must be a specific origin (not "*")
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://www.apilocker.app';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, X-Locker-Forward-Path, X-Device-Signature, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-Id',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id, Mcp-Protocol-Version',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

// Backwards-compatible default headers (for code paths that don't have a request).
// These bake in `https://www.apilocker.app` as ACAO, which works fine for the
// dashboard's own fetch calls since the origin matches. The router wraps
// responses and rewrites these headers per-request for cross-origin callers
// (Claude, localhost dev, etc).
const corsHeaders = buildCorsHeaders(null);

export function jsonOk(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: corsHeaders });
}

export function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: corsHeaders });
}

export function corsPreflightResponse(request?: Request): Response {
  const origin = request?.headers.get('Origin') ?? null;
  return new Response(null, { status: 204, headers: buildCorsHeaders(origin) });
}

/**
 * Rewrite the CORS headers of an existing Response to match the given
 * request's origin. Called by the router after each handler returns,
 * so that jsonOk/jsonError (which bake in static headers) still produce
 * the correct ACAO for cross-origin callers without needing to thread
 * the request through every call site.
 *
 * Headers preserved: everything the handler set. Only the 6 CORS
 * headers are overwritten.
 */
export function applyCorsHeaders(response: Response, request: Request): Response {
  const origin = request.headers.get('Origin');
  if (!origin) return response; // Non-browser call, CORS doesn't matter
  const cors = buildCorsHeaders(origin);
  const newHeaders = new Headers(response.headers);
  for (const [k, v] of Object.entries(cors)) {
    newHeaders.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
