import { Env, EncryptedKeyRecord, KeyMetadata } from './types';
import { decrypt } from './crypto';
import { generateId } from './crypto';
import { getKeyMetadata, insertAuditLog } from './db';
import { validateScopedToken } from './auth';
import { getProviderTemplate, getAuthHeaderName } from './providers';
import { jsonError } from './responses';

export async function handleProxy(
  request: Request,
  env: Env,
  params: Record<string, string>,
  userId: string
): Promise<Response> {
  const { keyId } = params;
  const startTime = Date.now();

  // Get token info for access check and audit logging
  const tokenInfo = await validateScopedToken(request, env);
  if (!tokenInfo) {
    return jsonError('Unauthorized', 401);
  }

  // Check if token has access to this key
  if (!tokenInfo.allowedKeys.includes(keyId)) {
    return jsonError('Token does not have access to this key', 403);
  }

  // Get key metadata from D1
  const metadata = await getKeyMetadata(env, keyId, userId);
  if (!metadata) {
    return jsonError('Key not found', 404);
  }

  // v1.0.0: OAuth credentials cannot be proxied yet (the proxy would need
  // to perform the full OAuth dance, which is Level 2 roadmap work).
  if (metadata.credential_type === 'oauth2') {
    return jsonError(
      'OAuth credentials cannot be used via the proxy yet. Use apilocker run/get/env to inject them as environment variables instead.',
      400
    );
  }

  // v1.0.0: vault-only credentials (no base_url configured) cannot be
  // proxied. The user meant to use them via reveal/run/get/env.
  if (!metadata.base_url) {
    return jsonError(
      'This credential has no base URL configured. Use apilocker run/get/env to inject it directly, or add a base URL to enable proxy access.',
      400
    );
  }

  // v1.0.0: paused keys are not forwardable. Reveal still works, so
  // users can still rotate or inspect the key, but the proxy is frozen.
  if (metadata.paused_at) {
    return new Response(
      JSON.stringify({
        error: `Key "${metadata.name}" is paused. Run 'apilocker resume ${metadata.name}' to reactivate.`,
      }),
      { status: 423, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Get encrypted key from KV
  const encryptedJson = await env.KEYS.get(keyId);
  if (!encryptedJson) {
    return jsonError('Encrypted key data missing', 500);
  }

  const encrypted: EncryptedKeyRecord = JSON.parse(encryptedJson);

  // Decrypt the real API key
  const realKey = await decrypt(encrypted, env);

  // Build the target URL
  const forwardPath = request.headers.get('X-Locker-Forward-Path') || '';
  const targetUrl = `${metadata.base_url}${forwardPath}`;

  // Build outgoing headers — pass through relevant headers, strip locker-specific ones
  const outgoingHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (
      lower === 'authorization' ||
      lower === 'x-locker-forward-path' ||
      lower === 'x-device-signature' ||
      lower === 'host' ||
      lower === 'cookie'
    ) {
      continue;
    }
    outgoingHeaders.set(key, value);
  }

  // Inject the real API key based on auth_header_type, respecting any
  // custom header name declared on the provider template.
  const template = getProviderTemplate(metadata.provider);
  injectApiKey(outgoingHeaders, metadata, template?.auth_header_name ?? null, realKey);

  // Determine the final URL (may have query param appended)
  // Providers like Google AI use `?key=...` instead of the default `?api_key=...`
  const queryParamName = template?.query_param_name ?? 'api_key';
  const finalUrl =
    metadata.auth_header_type === 'query'
      ? appendQueryParam(targetUrl, queryParamName, realKey)
      : targetUrl;

  // Forward the request — stream the body directly
  let providerResponse: Response;
  let statusCode: number;

  try {
    providerResponse = await fetch(finalUrl, {
      method: request.method,
      headers: outgoingHeaders,
      body: request.body,
    });
    statusCode = providerResponse.status;
  } catch (e) {
    statusCode = 502;

    // Log the failed request
    const latencyMs = Date.now() - startTime;
    const logPromise = insertAuditLog(env, {
      id: generateId('log'),
      user_id: userId,
      token_id: tokenInfo.tokenId,
      key_id: keyId,
      provider: metadata.provider,
      forward_path: forwardPath,
      source_ip: request.headers.get('CF-Connecting-IP'),
      status_code: statusCode,
      latency_ms: latencyMs,
      timestamp: new Date().toISOString(),
      country: request.headers.get('CF-IPCountry') || null,
    });

    // Fire and forget
    if (typeof globalThis !== 'undefined' && 'waitUntil' in globalThis) {
      // In a Worker context, we'd use ctx.waitUntil, but we don't have ctx here
      // The log will still be attempted
    }
    await logPromise;

    return jsonError('Failed to reach provider', 502);
  }

  const latencyMs = Date.now() - startTime;

  // Log the request. We MUST await this — Cloudflare Workers terminate any
  // unawaited promises the moment we return a Response, which means a
  // fire-and-forget insert never actually hits D1. Awaiting adds a few ms
  // of latency but guarantees the audit log lands.
  try {
    await insertAuditLog(env, {
      id: generateId('log'),
      user_id: userId,
      token_id: tokenInfo.tokenId,
      key_id: keyId,
      provider: metadata.provider,
      forward_path: forwardPath,
      source_ip: request.headers.get('CF-Connecting-IP'),
      status_code: statusCode,
      latency_ms: latencyMs,
      timestamp: new Date().toISOString(),
      country: request.headers.get('CF-IPCountry') || null,
    });
  } catch (err) {
    console.error('[AuditLog] Failed to write:', err);
    // Don't block the response on audit-log failures
  }

  // Record traffic for anomaly detection. Awaited for the same reason as
  // above — unawaited DO calls get killed when the worker returns.
  try {
    const monitorId = env.TRAFFIC_MONITOR.idFromName(tokenInfo.tokenId);
    const monitor = env.TRAFFIC_MONITOR.get(monitorId);
    await monitor.fetch('https://monitor/record', {
      method: 'POST',
      body: JSON.stringify({ tokenId: tokenInfo.tokenId, keyId }),
    });
  } catch {
    // Don't let monitoring failures affect the proxy
  }

  // Return the provider's response as-is (streamed)
  return new Response(providerResponse.body, {
    status: providerResponse.status,
    statusText: providerResponse.statusText,
    headers: providerResponse.headers,
  });
}

function injectApiKey(
  headers: Headers,
  metadata: KeyMetadata,
  customHeaderName: string | null,
  key: string
): void {
  // Custom header name always wins — for providers like ElevenLabs
  // that use 'xi-api-key' instead of any standard header.
  if (customHeaderName) {
    headers.set(customHeaderName, key);
    return;
  }
  switch (metadata.auth_header_type) {
    case 'bearer':
      headers.set('Authorization', `Bearer ${key}`);
      break;
    case 'x-api-key':
      headers.set('X-API-Key', key);
      break;
    case 'basic':
      headers.set('Authorization', `Basic ${key}`);
      break;
    case 'custom':
      // Falls through to the auth header name lookup if no customHeaderName
      // was passed — should be rare, but handles edge cases.
      headers.set(getAuthHeaderName('custom', null), key);
      break;
    case 'query':
      // Handled via URL append, not header
      break;
  }
}

function appendQueryParam(url: string, key: string, value: string): string {
  const separator = url.includes('?') ? '&' : '?';
  return `${url}${separator}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}
