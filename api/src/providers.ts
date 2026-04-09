import { AuthHeaderType, CredentialType, ProviderCategory } from './types';

/**
 * Provider template — the pre-configured shape of a credential for a
 * specific service. Users picking "OpenAI" from the Add Key modal get
 * the correct base URL and auth header type filled in automatically.
 *
 * v1.0.0 additions:
 *   - `category` for the three-bucket dashboard grouping
 *   - `credential_type` for OAuth providers
 *   - `auth_header_name` for providers like ElevenLabs that use
 *     non-standard header names (xi-api-key, etc.)
 *   - `authorize_url` / `token_url` / `default_scopes` for OAuth
 */
export interface ProviderTemplate {
  id: string;
  name: string;
  category: ProviderCategory;
  credential_type: CredentialType;

  // api_key shape
  base_url?: string;
  auth_header_type?: AuthHeaderType;
  /**
   * Override the default header name for this provider. Only used when
   * `auth_header_type` is 'custom' (or when a provider uses a non-standard
   * name even with a standard type). Example: ElevenLabs uses 'xi-api-key'
   * rather than the standard 'X-API-Key'.
   */
  auth_header_name?: string;
  /**
   * When auth_header_type is 'query', this overrides the default query
   * parameter name ('api_key'). Google AI, for example, expects `?key=...`.
   */
  query_param_name?: string;

  // oauth2 shape
  authorize_url?: string;
  token_url?: string;
  default_scopes?: string;
  default_redirect_uri?: string;
}

const providers: Record<string, ProviderTemplate> = {
  // ================ LLM providers ================
  openai: {
    id: 'openai',
    name: 'OpenAI',
    category: 'llm',
    credential_type: 'api_key',
    base_url: 'https://api.openai.com',
    auth_header_type: 'bearer',
  },
  anthropic: {
    id: 'anthropic',
    name: 'Anthropic',
    category: 'llm',
    credential_type: 'api_key',
    base_url: 'https://api.anthropic.com',
    auth_header_type: 'x-api-key',
  },
  'google-ai': {
    id: 'google-ai',
    name: 'Google AI (Gemini)',
    category: 'llm',
    credential_type: 'api_key',
    base_url: 'https://generativelanguage.googleapis.com',
    auth_header_type: 'query',
    query_param_name: 'key',
  },
  groq: {
    id: 'groq',
    name: 'Groq',
    category: 'llm',
    credential_type: 'api_key',
    base_url: 'https://api.groq.com/openai/v1',
    auth_header_type: 'bearer',
  },
  mistral: {
    id: 'mistral',
    name: 'Mistral',
    category: 'llm',
    credential_type: 'api_key',
    base_url: 'https://api.mistral.ai',
    auth_header_type: 'bearer',
  },

  // ================ Service API providers ================
  // Payments
  stripe: {
    id: 'stripe',
    name: 'Stripe',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.stripe.com',
    auth_header_type: 'bearer',
  },
  lemonsqueezy: {
    id: 'lemonsqueezy',
    name: 'Lemon Squeezy',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.lemonsqueezy.com/v1',
    auth_header_type: 'bearer',
  },

  // Communications / email
  twilio: {
    id: 'twilio',
    name: 'Twilio',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.twilio.com',
    auth_header_type: 'basic',
  },
  sendgrid: {
    id: 'sendgrid',
    name: 'SendGrid',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.sendgrid.com',
    auth_header_type: 'bearer',
  },
  resend: {
    id: 'resend',
    name: 'Resend',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.resend.com',
    auth_header_type: 'bearer',
  },

  // Infra / hosting
  cloudflare: {
    id: 'cloudflare',
    name: 'Cloudflare',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.cloudflare.com',
    auth_header_type: 'bearer',
  },
  vercel: {
    id: 'vercel',
    name: 'Vercel',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.vercel.com',
    auth_header_type: 'bearer',
  },
  upstash: {
    id: 'upstash',
    name: 'Upstash',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.upstash.com/v2',
    auth_header_type: 'bearer',
  },

  // Dev platform
  github: {
    id: 'github',
    name: 'GitHub',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.github.com',
    auth_header_type: 'bearer',
  },

  // Auth
  clerk: {
    id: 'clerk',
    name: 'Clerk',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.clerk.com/v1',
    auth_header_type: 'bearer',
  },

  // Monitoring / analytics
  sentry: {
    id: 'sentry',
    name: 'Sentry',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://sentry.io/api/0',
    auth_header_type: 'bearer',
  },
  posthog: {
    id: 'posthog',
    name: 'PostHog',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://app.posthog.com',
    auth_header_type: 'bearer',
  },

  // Media / content
  cloudinary: {
    id: 'cloudinary',
    name: 'Cloudinary',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.cloudinary.com/v1_1',
    auth_header_type: 'basic',
  },
  mux: {
    id: 'mux',
    name: 'Mux',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.mux.com',
    auth_header_type: 'basic',
  },

  // Voice / audio — new in v1.0.0
  elevenlabs: {
    id: 'elevenlabs',
    name: 'ElevenLabs',
    category: 'service',
    credential_type: 'api_key',
    base_url: 'https://api.elevenlabs.io/v1',
    auth_header_type: 'custom',
    auth_header_name: 'xi-api-key',
  },

  // ================ OAuth providers (new in v1.0.0) ================
  'google-oauth': {
    id: 'google-oauth',
    name: 'Google OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token',
    default_scopes: 'openid email profile',
  },
  'github-oauth': {
    id: 'github-oauth',
    name: 'GitHub OAuth App',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://github.com/login/oauth/authorize',
    token_url: 'https://github.com/login/oauth/access_token',
    default_scopes: 'repo user:email',
  },
  'slack-oauth': {
    id: 'slack-oauth',
    name: 'Slack OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://slack.com/oauth/v2/authorize',
    token_url: 'https://slack.com/api/oauth.v2.access',
    default_scopes: 'chat:write channels:read users:read',
  },
  'microsoft-oauth': {
    id: 'microsoft-oauth',
    name: 'Microsoft OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    token_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    default_scopes: 'openid email profile User.Read offline_access',
  },
  'notion-oauth': {
    id: 'notion-oauth',
    name: 'Notion OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://api.notion.com/v1/oauth/authorize',
    token_url: 'https://api.notion.com/v1/oauth/token',
  },
  'spotify-oauth': {
    id: 'spotify-oauth',
    name: 'Spotify OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://accounts.spotify.com/authorize',
    token_url: 'https://accounts.spotify.com/api/token',
    default_scopes: 'user-read-email user-read-private',
  },
  'twitter-oauth': {
    id: 'twitter-oauth',
    name: 'Twitter / X OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://twitter.com/i/oauth2/authorize',
    token_url: 'https://api.twitter.com/2/oauth2/token',
    default_scopes: 'tweet.read users.read offline.access',
  },
  'linkedin-oauth': {
    id: 'linkedin-oauth',
    name: 'LinkedIn OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://www.linkedin.com/oauth/v2/authorization',
    token_url: 'https://www.linkedin.com/oauth/v2/accessToken',
    default_scopes: 'openid profile email',
  },
  'discord-oauth': {
    id: 'discord-oauth',
    name: 'Discord OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://discord.com/oauth2/authorize',
    token_url: 'https://discord.com/api/oauth2/token',
    default_scopes: 'identify email',
  },
  'zoom-oauth': {
    id: 'zoom-oauth',
    name: 'Zoom OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://zoom.us/oauth/authorize',
    token_url: 'https://zoom.us/oauth/token',
    default_scopes: 'user:read',
  },
  'dropbox-oauth': {
    id: 'dropbox-oauth',
    name: 'Dropbox OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://www.dropbox.com/oauth2/authorize',
    token_url: 'https://api.dropboxapi.com/oauth2/token',
    default_scopes: 'account_info.read files.metadata.read',
  },
  'salesforce-oauth': {
    id: 'salesforce-oauth',
    name: 'Salesforce OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://login.salesforce.com/services/oauth2/authorize',
    token_url: 'https://login.salesforce.com/services/oauth2/token',
    default_scopes: 'api refresh_token',
  },
  'hubspot-oauth': {
    id: 'hubspot-oauth',
    name: 'HubSpot OAuth',
    category: 'oauth',
    credential_type: 'oauth2',
    authorize_url: 'https://app.hubspot.com/oauth/authorize',
    token_url: 'https://api.hubapi.com/oauth/v1/token',
    default_scopes: 'crm.objects.contacts.read crm.objects.contacts.write',
  },
  'custom-oauth': {
    id: 'custom-oauth',
    name: 'Custom OAuth 2.0',
    category: 'oauth',
    credential_type: 'oauth2',
  },
};

export function getProviderTemplate(provider: string): ProviderTemplate | null {
  return providers[provider.toLowerCase()] ?? null;
}

export function listProviders(): ProviderTemplate[] {
  return Object.values(providers);
}

export function listProvidersByCategory(category: ProviderCategory): ProviderTemplate[] {
  return Object.values(providers).filter((p) => p.category === category);
}

/**
 * Return the default HTTP header name for injecting an API key, given a
 * provider's auth header type and any custom override. Used by the proxy
 * handler when building the outgoing request.
 */
export function getAuthHeaderName(
  authHeaderType: AuthHeaderType,
  customName?: string | null
): string {
  if (customName) return customName;
  switch (authHeaderType) {
    case 'bearer':
      return 'Authorization';
    case 'x-api-key':
      return 'X-API-Key';
    case 'basic':
      return 'Authorization';
    case 'custom':
      // If a provider says 'custom' but didn't give a name, fall back to
      // the most common real-world header. Better than silently dropping.
      return customName || 'X-API-Key';
    case 'query':
      // Query-param auth doesn't use a header; caller should handle this
      // separately.
      return '';
  }
}
