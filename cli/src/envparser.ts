/**
 * Minimal `.env` file parser, hand-rolled to avoid a dotenv dependency.
 *
 * Handles:
 *   - KEY=value
 *   - KEY="quoted value with spaces"
 *   - KEY='single-quoted value'
 *   - KEY=unquoted_value_with_no_spaces
 *   - export KEY=value  (the `export` prefix is stripped)
 *   - # full-line comments
 *   - blank lines
 *   - trailing whitespace
 *   - escape sequences inside double quotes: \n \r \t \\ \" \$
 *
 * Does NOT support:
 *   - Variable interpolation (${OTHER_VAR}) — we explicitly don't resolve
 *     these because the original author may have intended literal text.
 *     The value is imported verbatim; if it's a template it stays a template.
 *   - Multi-line values with literal newlines inside quoted strings.
 *     Keep values on a single line.
 *
 * This parser is deliberately permissive: malformed lines are skipped
 * with a warning rather than throwing, so a single typo doesn't abort
 * the whole import.
 */

export interface ParsedEntry {
  key: string;
  value: string;
  line_number: number;
}

export interface ParseResult {
  entries: ParsedEntry[];
  warnings: { line_number: number; message: string }[];
}

export function parseEnvFile(source: string): ParseResult {
  const lines = source.split(/\r?\n/);
  const entries: ParsedEntry[] = [];
  const warnings: ParseResult['warnings'] = [];
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    let line = lines[i];

    // Strip BOM from the first line
    if (i === 0 && line.charCodeAt(0) === 0xfeff) {
      line = line.slice(1);
    }

    // Skip blank lines and comments
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) continue;

    // Optional `export ` prefix
    let body = trimmed;
    if (body.startsWith('export ')) {
      body = body.slice('export '.length).trimStart();
    }

    // Split on the first `=`
    const eqIdx = body.indexOf('=');
    if (eqIdx === -1) {
      warnings.push({
        line_number: lineNumber,
        message: `No '=' separator, skipping: ${truncate(line, 60)}`,
      });
      continue;
    }

    const key = body.slice(0, eqIdx).trim();
    let valueRaw = body.slice(eqIdx + 1);

    // Strip a trailing inline comment (only for UNQUOTED values)
    // We detect "unquoted" by checking if the value doesn't start with " or '
    if (!valueRaw.startsWith('"') && !valueRaw.startsWith("'")) {
      const hashIdx = valueRaw.indexOf('#');
      if (hashIdx !== -1) {
        valueRaw = valueRaw.slice(0, hashIdx);
      }
    }

    valueRaw = valueRaw.trim();

    // Validate key name
    if (!key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      warnings.push({
        line_number: lineNumber,
        message: `Invalid key name, skipping: ${truncate(key, 40)}`,
      });
      continue;
    }

    // Parse quoted / unquoted value
    let value: string;
    if (valueRaw.startsWith('"') && valueRaw.endsWith('"') && valueRaw.length >= 2) {
      value = unescapeDoubleQuoted(valueRaw.slice(1, -1));
    } else if (valueRaw.startsWith("'") && valueRaw.endsWith("'") && valueRaw.length >= 2) {
      // Single-quoted strings are taken literally
      value = valueRaw.slice(1, -1);
    } else if (valueRaw.startsWith('"') || valueRaw.startsWith("'")) {
      // Unbalanced quotes — take the rest as-is minus the opening quote
      warnings.push({
        line_number: lineNumber,
        message: `Unbalanced quote on ${key}, using the literal remainder`,
      });
      value = valueRaw.slice(1);
    } else {
      value = valueRaw;
    }

    if (seen.has(key)) {
      warnings.push({
        line_number: lineNumber,
        message: `Duplicate key ${key}, later definition wins`,
      });
      // Overwrite the earlier entry
      const idx = entries.findIndex((e) => e.key === key);
      if (idx !== -1) entries.splice(idx, 1);
    }

    seen.add(key);
    entries.push({ key, value, line_number: lineNumber });
  }

  return { entries, warnings };
}

function unescapeDoubleQuoted(s: string): string {
  return s.replace(/\\([\\"ntr$])/g, (_match, ch: string) => {
    switch (ch) {
      case 'n':
        return '\n';
      case 't':
        return '\t';
      case 'r':
        return '\r';
      case '\\':
        return '\\';
      case '"':
        return '"';
      case '$':
        return '$';
      default:
        return ch;
    }
  });
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

/**
 * Pattern-match a variable name against known provider prefixes and
 * return the most likely provider id. Falls back to 'custom' for any
 * name that doesn't match. The match is case-insensitive and only
 * considers the leading component (before the first underscore).
 */
export function detectProvider(varName: string): string {
  const upper = varName.toUpperCase();

  // Prefix → provider mapping. Order matters for overlapping prefixes
  // (e.g. GOOGLE_API_KEY → google-ai, but GITHUB_TOKEN → github).
  const rules: { prefix: string; provider: string }[] = [
    { prefix: 'OPENAI_', provider: 'openai' },
    { prefix: 'ANTHROPIC_', provider: 'anthropic' },
    { prefix: 'CLAUDE_', provider: 'anthropic' },
    { prefix: 'GEMINI_', provider: 'google-ai' },
    { prefix: 'GOOGLE_AI_', provider: 'google-ai' },
    { prefix: 'GOOGLE_API_', provider: 'google-ai' },
    { prefix: 'GROQ_', provider: 'groq' },
    { prefix: 'MISTRAL_', provider: 'mistral' },
    { prefix: 'STRIPE_', provider: 'stripe' },
    { prefix: 'LEMON_', provider: 'lemonsqueezy' },
    { prefix: 'LS_', provider: 'lemonsqueezy' },
    { prefix: 'LEMONSQUEEZY_', provider: 'lemonsqueezy' },
    { prefix: 'TWILIO_', provider: 'twilio' },
    { prefix: 'SENDGRID_', provider: 'sendgrid' },
    { prefix: 'RESEND_', provider: 'resend' },
    { prefix: 'CLOUDFLARE_', provider: 'cloudflare' },
    { prefix: 'CF_', provider: 'cloudflare' },
    { prefix: 'VERCEL_', provider: 'vercel' },
    { prefix: 'UPSTASH_', provider: 'upstash' },
    { prefix: 'GITHUB_', provider: 'github' },
    { prefix: 'GH_', provider: 'github' },
    { prefix: 'CLERK_', provider: 'clerk' },
    { prefix: 'SENTRY_', provider: 'sentry' },
    { prefix: 'POSTHOG_', provider: 'posthog' },
    { prefix: 'CLOUDINARY_', provider: 'cloudinary' },
    { prefix: 'MUX_', provider: 'mux' },
    { prefix: 'ELEVENLABS_', provider: 'custom' }, // no template yet, but ELEVENLABS is real
  ];

  for (const rule of rules) {
    if (upper.startsWith(rule.prefix)) {
      return rule.provider;
    }
  }
  return 'custom';
}
