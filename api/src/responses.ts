const ALLOWED_ORIGINS = new Set([
  'https://www.apilocker.app',
  'https://apilocker.app',
  'http://localhost:5173',
  'http://localhost:3000',
]);

function buildCorsHeaders(origin: string | null): Record<string, string> {
  // For credentialed requests, ACAO must be a specific origin (not "*")
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://www.apilocker.app';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Locker-Forward-Path, X-Device-Signature',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

// Backwards-compatible default headers (for code paths that don't have a request)
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
