import { Env, Route, RouteHandler, UnauthenticatedRouteHandler } from './types';
import { jsonError, corsPreflightResponse } from './responses';
import { validateSession, validateScopedToken } from './auth';

const routes: Route[] = [];

export function addRoute(
  method: string,
  path: string,
  handler: RouteHandler | UnauthenticatedRouteHandler,
  auth: Route['auth'] = 'session'
) {
  routes.push({
    method,
    pattern: new URLPattern({ pathname: path }),
    handler,
    auth,
  });
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method === 'OPTIONS') {
    return corsPreflightResponse(request);
  }

  const url = new URL(request.url);

  for (const route of routes) {
    if (route.method !== request.method) continue;

    const match = route.pattern.exec({ pathname: url.pathname });
    if (!match) continue;

    const params: Record<string, string> = {};
    for (const [key, value] of Object.entries(match.pathname.groups)) {
      if (value !== undefined) params[key] = value;
    }

    if (route.auth === 'none') {
      return (route.handler as UnauthenticatedRouteHandler)(request, env, params);
    }

    if (route.auth === 'session') {
      const userId = await validateSession(request, env);
      if (!userId) return jsonError('Unauthorized', 401);
      return (route.handler as RouteHandler)(request, env, params, userId);
    }

    if (route.auth === 'scoped') {
      const tokenInfo = await validateScopedToken(request, env);
      if (!tokenInfo) return jsonError('Unauthorized', 401);
      return (route.handler as RouteHandler)(request, env, params, tokenInfo.userId);
    }
  }

  return jsonError('Not found', 404);
}
