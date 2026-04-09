/**
 * Cloudflare Pages middleware — runs before every request to the site.
 *
 * Primary job: gate the /admin and /admin.html paths so that only
 * authenticated administrators can load the admin dashboard HTML itself.
 * Non-admins get a plain 404 (the URL pretends not to exist), matching
 * the principle that admin surfaces should be invisible to anyone
 * who isn't supposed to know they exist.
 *
 * Implementation: calls the cheap /v1/admin/check endpoint on the
 * backend worker, passing through the user's session cookie. If the
 * check returns 200, we let the request through to the static
 * admin.html file. Any other status gets a 404.
 *
 * All other paths pass through unchanged (context.next()) so the rest
 * of the site continues to work normally.
 */

export const onRequest: PagesFunction = async (context) => {
  const url = new URL(context.request.url);
  const pathname = url.pathname;

  if (pathname === '/admin' || pathname === '/admin.html' || pathname === '/admin/') {
    const cookie = context.request.headers.get('Cookie') || '';
    try {
      const checkRes = await fetch('https://api.apilocker.app/v1/admin/check', {
        headers: {
          Cookie: cookie,
          'User-Agent': 'apilocker-pages-middleware',
        },
      });
      if (checkRes.status !== 200) {
        return notFound();
      }
    } catch {
      // If the backend is unreachable, fail closed.
      return notFound();
    }
    // Admin verified — fall through to serve admin.html
  }

  return context.next();
};

function notFound(): Response {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>404 — Not Found</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; background: #F8FAFC; color: #0F172A; margin: 0; display: grid; place-items: center; min-height: 100vh; text-align: center; }
  h1 { font-size: 48px; font-weight: 800; letter-spacing: -0.02em; margin: 0 0 8px; }
  p { color: #64748B; margin: 0 0 24px; }
  a { color: #3B82F6; text-decoration: none; font-weight: 600; }
</style>
</head>
<body>
  <div>
    <h1>404</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="/">← Back to API Locker</a>
  </div>
</body>
</html>`,
    {
      status: 404,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    }
  );
}
