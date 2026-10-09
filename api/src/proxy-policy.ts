/**
 * What AI agents may send through the MCP proxy tools (proxy_get,
 * proxy_post, proxy_put, proxy_patch, proxy_delete).
 *
 * Anthropic's Software Directory Policy doesn't accept connectors that
 * move money or that generate images, video, or audio with AI models.
 * These rules keep the MCP proxy inside that policy. They apply only when
 * an agent drives the proxy through /v1/mcp; apps calling /v1/proxy with
 * a scoped token are unaffected.
 *
 *   1. GET is allowed for every proxyable credential.
 *   2. Writes go only to the vetted provider hosts in WRITE_HOSTS. Payment
 *      APIs are deliberately absent, and so is any host a user typed in as
 *      a custom base URL.
 *   3. Writes to a vetted host are still refused when they buy something
 *      or call an AI image / video / audio generation endpoint or model.
 */

export type ProxyMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Public page listing each provider's base URL and API reference. */
export const PROXY_PROVIDERS_DOCS_URL = 'https://www.apilocker.app/docs/mcp#providers';

/** Vetted provider API hosts that accept writes through the MCP proxy. */
const WRITE_HOSTS = new Set([
  // LLM providers (their image / audio / video endpoints are blocked below)
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
  'api.mistral.ai',
  // Email / messaging
  'api.twilio.com',
  'api.sendgrid.com',
  'api.resend.com',
  // Infra / dev platform / auth
  'api.cloudflare.com',
  'api.vercel.com',
  'api.upstash.com',
  'api.github.com',
  'api.clerk.com',
  // Monitoring / analytics
  'sentry.io',
  'us.sentry.io',
  'de.sentry.io',
  'app.posthog.com',
  'us.posthog.com',
  'eu.posthog.com',
  // Media hosting (generative transformations are blocked below)
  'api.cloudinary.com',
  'api.mux.com',
  // APIs behind the OAuth provider templates
  'www.googleapis.com',
  'gmail.googleapis.com',
  'sheets.googleapis.com',
  'docs.googleapis.com',
  'people.googleapis.com',
  'slack.com',
  'graph.microsoft.com',
  'api.notion.com',
  'api.spotify.com',
  'api.twitter.com',
  'api.x.com',
  'api.linkedin.com',
  'discord.com',
  'api.zoom.us',
  'api.dropboxapi.com',
  'content.dropboxapi.com',
  'api.hubapi.com',
]);

/** Salesforce serves each org from its own subdomain. */
const WRITE_HOST_SUFFIXES = ['.my.salesforce.com'];

// The next two sets aren't on WRITE_HOSTS either; they're named only so
// the refusal message can say why.
const PAYMENT_HOSTS = new Set([
  'api.stripe.com',
  'files.stripe.com',
  'api.lemonsqueezy.com',
  'api-m.paypal.com',
  'api-m.sandbox.paypal.com',
  'connect.squareup.com',
  'connect.squareupsandbox.com',
  'api.paddle.com',
  'sandbox-api.paddle.com',
  'api.coinbase.com',
  'api.commerce.coinbase.com',
  'production.plaid.com',
  'sandbox.plaid.com',
  'api.wise.com',
  'api.transferwise.com',
]);

const MEDIA_HOSTS = new Set([
  'api.elevenlabs.io',
  'api.stability.ai',
  'api.replicate.com',
  'api.dev.runwayml.com',
  'api.lumalabs.ai',
  'fal.run',
  'queue.fal.run',
  'api.ideogram.ai',
  'cloud.leonardo.ai',
]);

interface WriteRule {
  host: string;
  /** Tested against the URL path + query string. */
  path?: RegExp;
  /** Tested against the JSON-encoded request body. */
  body?: RegExp;
  kind: 'purchase' | 'media';
  what: string;
}

/** Endpoints on vetted hosts that writes may not reach. */
const WRITE_RULES: WriteRule[] = [
  // Purchases and money movement
  { host: 'api.cloudflare.com', path: /\/registrar\//i, kind: 'purchase', what: 'Cloudflare Registrar domain purchases' },
  { host: 'api.vercel.com', path: /\/(domains\/buy|registrar\/)/i, kind: 'purchase', what: 'Vercel domain purchases' },
  {
    host: 'api.twilio.com',
    path: /\/IncomingPhoneNumbers(\/(Local|Mobile|TollFree))?\.json(\?|$)/i,
    kind: 'purchase',
    what: 'Twilio phone number purchases',
  },
  { host: 'api.github.com', body: /\bcreateSponsorships?\b/, kind: 'purchase', what: 'GitHub Sponsors payments' },
  { host: 'www.googleapis.com', path: /\/androidpublisher\//i, kind: 'purchase', what: 'Google Play orders and refunds' },

  // AI image / video / audio generation
  {
    host: 'api.openai.com',
    path: /^\/v1\/(images|audio\/speech|videos|realtime)\b/i,
    kind: 'media',
    what: 'OpenAI image, speech, video, and realtime audio endpoints',
  },
  {
    host: 'generativelanguage.googleapis.com',
    path: /:(predict|predictLongRunning)\b/i,
    kind: 'media',
    what: 'Imagen and Veo generation endpoints',
  },
  { host: 'api.groq.com', path: /\/audio\/speech\b/i, kind: 'media', what: 'Groq text-to-speech' },
  {
    host: 'api.cloudinary.com',
    body: /\be_gen_|\bgen_(fill|remove|replace|recolor|restore|background_replace)\b/i,
    kind: 'media',
    what: 'Cloudinary generative AI transformations',
  },
];

/** Model ids for image, video, and audio generation across providers. */
const MEDIA_MODEL =
  /(dall-e|gpt-image|chatgpt-image|sora|imagen|veo-|lyria|stable-diffusion|sdxl|flux|dreamshaper|lucid-origin|phoenix|melotts|aura-|tts|text-to-speech|native-audio|image-generation|-image\b|realtime|gpt-audio|gpt-4o-audio|eleven_)/i;

const METHOD_OVERRIDE_HEADER = /^x-(http-)?method(-override)?$/i;
const METHOD_OVERRIDE_PARAM = /[?&](_method|x-http-method-override|x-http-method|x-method-override)=/i;

export interface ProxyPolicyInput {
  method: ProxyMethod;
  /** The final target URL, already checked by buildProxyTargetUrl. */
  url: URL;
  headers?: Record<string, unknown>;
  body?: unknown;
}

/**
 * Returns a refusal message the agent can act on, or null if the request
 * may go out.
 */
export function checkProxyPolicy({ method, url, headers, body }: ProxyPolicyInput): string | null {
  // Method overrides would let a proxy_get call land as a write.
  const overrideHeader = Object.keys(headers ?? {}).find((name) => METHOD_OVERRIDE_HEADER.test(name));
  if (overrideHeader) {
    return `Blocked: the ${overrideHeader} header isn't allowed. Use the proxy tool for the method you need (proxy_get, proxy_post, proxy_put, proxy_patch, or proxy_delete).`;
  }
  if (METHOD_OVERRIDE_PARAM.test(url.search)) {
    return 'Blocked: method-override query parameters (such as _method) aren\'t allowed. Use the proxy tool for the method you need.';
  }

  if (method === 'GET') return null;

  const host = url.hostname.toLowerCase();
  const appNote = 'Your own apps can still make this call through the API Locker proxy with a scoped token.';

  if (PAYMENT_HOSTS.has(host)) {
    return `Blocked: ${host} is a payment API, and payment APIs are read-only through API Locker's MCP tools (use proxy_get). ${appNote}`;
  }
  if (MEDIA_HOSTS.has(host)) {
    return `Blocked: ${host} generates AI audio, images, or video, so it's read-only through API Locker's MCP tools (use proxy_get). ${appNote}`;
  }
  if (!WRITE_HOSTS.has(host) && !WRITE_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    return `Blocked: write requests through API Locker's MCP tools only go to vetted provider APIs, and ${host} isn't one of them. Use proxy_get to read from it. ${appNote} Vetted providers: ${PROXY_PROVIDERS_DOCS_URL}`;
  }

  const pathAndQuery = url.pathname + url.search;
  const bodyJson = body === undefined ? '' : JSON.stringify(body);
  for (const rule of WRITE_RULES) {
    if (rule.host !== host) continue;
    const hit = (rule.path && rule.path.test(pathAndQuery)) || (rule.body && rule.body.test(bodyJson));
    if (hit) return refusal(rule.kind, rule.what, appNote);
  }

  const model = modelFromPath(url.pathname);
  if (model && MEDIA_MODEL.test(model)) {
    return refusal('media', `model "${model}"`, appNote);
  }
  const mediaOutput = requestedMediaOutput(body);
  if (mediaOutput) return refusal('media', mediaOutput, appNote);

  return null;
}

function refusal(kind: WriteRule['kind'], what: string, appNote: string): string {
  return kind === 'purchase'
    ? `Blocked: this request makes a purchase or moves money (${what}), which API Locker's MCP tools don't allow. ${appNote}`
    : `Blocked: this request generates AI images, video, or audio (${what}), which API Locker's MCP tools don't allow. ${appNote}`;
}

/**
 * Model ids that appear in the URL instead of the body:
 * Gemini's /v1beta/models/{model}:generateContent and Cloudflare Workers
 * AI's /accounts/{id}/ai/run/{model}.
 */
function modelFromPath(pathname: string): string | null {
  const gemini = /\/models\/([^/:]+)/.exec(pathname);
  if (gemini) return decodeURIComponent(gemini[1]);
  const workersAi = /\/ai\/run\/(.+)$/.exec(pathname);
  if (workersAi) return decodeURIComponent(workersAi[1]);
  return null;
}

/** Describes the AI media output a JSON body asks for, if any. */
function requestedMediaOutput(body: unknown): string | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, any>;

  if (typeof b.model === 'string' && MEDIA_MODEL.test(b.model)) return `model "${b.model}"`;

  const modalities = [
    ...asArray(b.modalities),
    ...asArray(b.generationConfig?.responseModalities),
    ...asArray(b.generation_config?.response_modalities),
  ];
  const mediaModality = modalities.find((m) => /^(audio|image|video)$/i.test(String(m)));
  if (mediaModality) return `${String(mediaModality).toLowerCase()} output`;

  if (b.audio && typeof b.audio === 'object') return 'audio output';
  if (b.generationConfig?.speechConfig) return 'speech output';

  const imageTool = asArray(b.tools).find(
    (t) => t && typeof t === 'object' && /image_generation/i.test(String((t as Record<string, unknown>).type))
  );
  if (imageTool) return 'the image_generation tool';

  return null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}
