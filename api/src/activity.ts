import { Env } from './types';
import { queryAuditLogs } from './db';
import { jsonOk } from './responses';

export async function handleGetActivity(
  request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  const url = new URL(request.url);
  const keyId = url.searchParams.get('key_id') || undefined;
  const tokenId = url.searchParams.get('token_id') || undefined;
  const limit = parseInt(url.searchParams.get('limit') || '100', 10);

  const logs = await queryAuditLogs(env, userId, {
    key_id: keyId,
    token_id: tokenId,
    limit: Math.min(limit, 500),
  });

  return jsonOk({ logs });
}
