/**
 * Hidden admin analytics endpoint (v1.0.0).
 *
 * Gated by an `ADMIN_USER_IDS` worker secret — a comma-separated list of
 * user IDs that are allowed to query this endpoint. Non-listed users see
 * a 404, not a 403, so the endpoint pretends not to exist to anyone who
 * doesn't already know it's admin-only.
 *
 * Returns aggregate D1 metrics useful during the public beta. Includes
 * both vanity counts AND real launch tracking — onboarding funnel,
 * time-to-value, DAU/WAU, retention cohorts, pillar adoption, activity
 * heatmap, and geographic distribution.
 *
 * All metrics are aggregated across the whole user base. No per-user
 * data is leaked, no credential values are revealed.
 */

import { Env } from './types';
import { jsonOk, jsonError } from './responses';
import { listProvidersByCategory } from './providers';

interface AdminMetrics {
  generated_at: string;
  users: {
    total: number;
    new_last_7d: number;
    new_last_30d: number;
    logged_in_last_7d: number;
  };
  credentials: {
    total: number;
    by_credential_type: Record<string, number>;
    by_category: Record<string, number>;
    paused: number;
  };
  tokens: {
    total: number;
    active: number;
    revoked: number;
    paused: number;
  };
  devices: {
    total: number;
    active: number;
    revoked: number;
  };
  activity: {
    last_24h: number;
    last_7d: number;
    last_30d: number;
  };
  top_providers: Array<{ provider: string; count: number }>;

  // ---- Launch tracking (v1.0.0 Tier 1) ----
  launch_tracking: {
    /**
     * Onboarding funnel: signups → registered CLI → stored credential
     * → made first usage. Each stage is a count of distinct users who
     * have reached that stage. The frontend computes percentages.
     */
    funnel: {
      signups: number;
      registered_cli: number;
      stored_credential: number;
      first_usage: number;
    };
    /**
     * Average time-to-value (in seconds) between funnel stages. Uses
     * AVG rather than median because SQLite doesn't have a native
     * percentile aggregate. Null for any stage with zero rows.
     */
    time_to_value_seconds: {
      signup_to_register: number | null;
      register_to_store: number | null;
      store_to_use: number | null;
    };
    /**
     * Daily active users for the last 30 days. "Active" = made at
     * least one proxy call OR reveal call that day. Returned as
     * an array of { date, active_users } sorted ascending.
     */
    dau_series: Array<{ date: string; active_users: number }>;
    /**
     * Weekly retention cohorts. Each entry is one (cohort_week,
     * weeks_offset) pair: of N users who signed up in cohort_week,
     * how many were active weeks_offset weeks later. The frontend
     * pivots into a triangular grid.
     */
    retention_cohorts: Array<{
      cohort_week: string;
      cohort_size: number;
      weeks_offset: number;
      active: number;
    }>;
    /**
     * Three-pillar adoption: how many users have stored at least one
     * credential of each type. Validates the marketing positioning.
     */
    pillar_adoption: {
      total_users_with_any_credential: number;
      with_llm: number;
      with_service: number;
      with_oauth: number;
      with_all_three: number;
    };
    /**
     * Activity heatmap (UTC). 7×24 grid keyed by day_of_week (0=Sun)
     * and hour_of_day (0-23). Cells with no activity are omitted.
     */
    activity_heatmap: Array<{
      day_of_week: number;
      hour_of_day: number;
      calls: number;
    }>;
    /**
     * Top countries by request volume in the last 30 days. Uses the
     * `country` column on audit_logs (populated from CF-IPCountry
     * starting in v1.0.0).
     */
    geo: Array<{ country: string; calls: number }>;
  };
}

function isAuthorizedAdmin(env: Env, userId: string): boolean {
  if (!env.ADMIN_USER_IDS) return false;
  const allowed = env.ADMIN_USER_IDS.split(',').map((s) => s.trim()).filter(Boolean);
  return allowed.includes(userId);
}

/**
 * SQL fragment defining a "usage event" — a row in audit_logs that
 * counts as the user actually getting value from the product. Includes
 * proxy calls (token_id NOT NULL) and reveal calls (forward_path =
 * '/reveal'). Excludes management operations like rename/pause/rotate
 * which don't represent the user actively using a credential.
 */
const USAGE_PREDICATE = `(token_id IS NOT NULL OR forward_path = '/reveal')`;

export async function handleAdminMetrics(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  if (!isAuthorizedAdmin(env, userId)) {
    return jsonError('Not found', 404);
  }

  try {
    const metrics = await computeMetrics(env);
    return jsonOk(metrics);
  } catch (e: any) {
    console.error('Admin metrics error:', e);
    return jsonError(`Failed to compute metrics: ${e.message}`, 500);
  }
}

/**
 * Lightweight admin-check endpoint used by Pages middleware to decide
 * whether to serve /admin at all. Returns 200 if the caller is an
 * authorized admin, 404 otherwise. Does not compute any metrics —
 * this is the cheap path for edge-gating the admin page.
 */
export async function handleAdminCheck(
  _request: Request,
  env: Env,
  _params: Record<string, string>,
  userId: string
): Promise<Response> {
  if (!isAuthorizedAdmin(env, userId)) {
    return jsonError('Not found', 404);
  }
  return jsonOk({ ok: true });
}

async function computeMetrics(env: Env): Promise<AdminMetrics> {
  // ---------------- VANITY METRICS (existing) ----------------
  const usersRow = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM users) AS total,
       (SELECT COUNT(*) FROM users WHERE datetime(created_at) > datetime('now', '-7 days')) AS new_7d,
       (SELECT COUNT(*) FROM users WHERE datetime(created_at) > datetime('now', '-30 days')) AS new_30d,
       (SELECT COUNT(*) FROM users WHERE datetime(last_login_at) > datetime('now', '-7 days')) AS active_7d`
  ).first<{ total: number; new_7d: number; new_30d: number; active_7d: number }>();

  const credsTotal = await env.DB.prepare(
    'SELECT COUNT(*) AS c FROM keys_metadata'
  ).first<{ c: number }>();
  const credsByType = await env.DB.prepare(
    `SELECT COALESCE(credential_type, 'api_key') AS t, COUNT(*) AS c
       FROM keys_metadata
       GROUP BY t`
  ).all<{ t: string; c: number }>();
  const credsByProvider = await env.DB.prepare(
    `SELECT provider, COUNT(*) AS c
       FROM keys_metadata
       GROUP BY provider
       ORDER BY c DESC
       LIMIT 15`
  ).all<{ provider: string; c: number }>();
  const credsPaused = await env.DB.prepare(
    'SELECT COUNT(*) AS c FROM keys_metadata WHERE paused_at IS NOT NULL'
  ).first<{ c: number }>();

  const tokensRow = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM tokens) AS total,
       (SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL AND paused_at IS NULL) AS active,
       (SELECT COUNT(*) FROM tokens WHERE revoked_at IS NOT NULL) AS revoked,
       (SELECT COUNT(*) FROM tokens WHERE paused_at IS NOT NULL) AS paused`
  ).first<{ total: number; active: number; revoked: number; paused: number }>();

  const devicesRow = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM devices) AS total,
       (SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL) AS active,
       (SELECT COUNT(*) FROM devices WHERE revoked_at IS NOT NULL) AS revoked`
  ).first<{ total: number; active: number; revoked: number }>();

  const activityRow = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM audit_logs WHERE datetime(timestamp) > datetime('now', '-1 day')) AS last_24h,
       (SELECT COUNT(*) FROM audit_logs WHERE datetime(timestamp) > datetime('now', '-7 days')) AS last_7d,
       (SELECT COUNT(*) FROM audit_logs WHERE datetime(timestamp) > datetime('now', '-30 days')) AS last_30d`
  ).first<{ last_24h: number; last_7d: number; last_30d: number }>();

  // Provider category breakdown
  const categoryCounts: Record<string, number> = { llm: 0, service: 0, oauth: 0 };
  for (const row of credsByProvider.results || []) {
    const cat = await getCategoryForProvider(row.provider);
    categoryCounts[cat] = (categoryCounts[cat] ?? 0) + row.c;
  }

  const typeMap: Record<string, number> = {};
  for (const row of credsByType.results || []) {
    typeMap[row.t] = row.c;
  }

  // ---------------- LAUNCH TRACKING (v1.0.0 Tier 1) ----------------

  // 1. Onboarding funnel
  const funnelRow = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM users) AS signups,
       (SELECT COUNT(DISTINCT user_id) FROM devices WHERE revoked_at IS NULL) AS registered,
       (SELECT COUNT(DISTINCT user_id) FROM keys_metadata) AS stored,
       (SELECT COUNT(DISTINCT user_id) FROM audit_logs WHERE ${USAGE_PREDICATE}) AS used`
  ).first<{ signups: number; registered: number; stored: number; used: number }>();

  // 2. Average time-to-value (in seconds)
  // For each step, average across users who completed both endpoints.
  const ttvSignupToRegister = await env.DB.prepare(
    `SELECT AVG(ts) AS avg_seconds FROM (
       SELECT
         (julianday(MIN(d.registered_at)) - julianday(u.created_at)) * 86400 AS ts
       FROM users u
       INNER JOIN devices d ON d.user_id = u.id
       GROUP BY u.id
     )`
  ).first<{ avg_seconds: number | null }>();

  const ttvRegisterToStore = await env.DB.prepare(
    `SELECT AVG(ts) AS avg_seconds FROM (
       SELECT
         (julianday(MIN(k.created_at)) - julianday(MIN(d.registered_at))) * 86400 AS ts
       FROM users u
       INNER JOIN devices d ON d.user_id = u.id
       INNER JOIN keys_metadata k ON k.user_id = u.id
       GROUP BY u.id
     )`
  ).first<{ avg_seconds: number | null }>();

  const ttvStoreToUse = await env.DB.prepare(
    `SELECT AVG(ts) AS avg_seconds FROM (
       SELECT
         (julianday(MIN(a.timestamp)) - julianday(MIN(k.created_at))) * 86400 AS ts
       FROM users u
       INNER JOIN keys_metadata k ON k.user_id = u.id
       INNER JOIN audit_logs a ON a.user_id = u.id AND ${USAGE_PREDICATE}
       GROUP BY u.id
     )`
  ).first<{ avg_seconds: number | null }>();

  // 3. DAU series (last 30 days)
  const dauResult = await env.DB.prepare(
    `SELECT
       DATE(timestamp) AS day,
       COUNT(DISTINCT user_id) AS active_users
     FROM audit_logs
     WHERE datetime(timestamp) > datetime('now', '-30 days')
       AND ${USAGE_PREDICATE}
     GROUP BY day
     ORDER BY day ASC`
  ).all<{ day: string; active_users: number }>();

  // 4. Retention cohorts (week-based)
  // For each user: cohort_week = signup week, then look at every distinct
  // week they were active. Compute (cohort, weeks_offset, count).
  const cohortRows = await env.DB.prepare(
    `WITH user_cohorts AS (
       SELECT
         u.id AS user_id,
         strftime('%Y-W%W', u.created_at) AS cohort_week,
         u.created_at AS signup_at
       FROM users u
     ),
     user_active_weeks AS (
       SELECT
         a.user_id,
         strftime('%Y-W%W', a.timestamp) AS active_week,
         MIN(a.timestamp) AS first_in_week
       FROM audit_logs a
       WHERE ${USAGE_PREDICATE}
       GROUP BY a.user_id, active_week
     )
     SELECT
       uc.cohort_week,
       uaw.active_week,
       CAST((julianday(uaw.first_in_week) - julianday(uc.signup_at)) / 7 AS INTEGER) AS weeks_offset,
       COUNT(DISTINCT uc.user_id) AS active
     FROM user_cohorts uc
     INNER JOIN user_active_weeks uaw ON uaw.user_id = uc.user_id
     GROUP BY uc.cohort_week, uaw.active_week
     ORDER BY uc.cohort_week, uaw.active_week`
  ).all<{ cohort_week: string; active_week: string; weeks_offset: number; active: number }>();

  // Compute cohort sizes (total users per cohort)
  const cohortSizesResult = await env.DB.prepare(
    `SELECT
       strftime('%Y-W%W', created_at) AS cohort_week,
       COUNT(*) AS size
     FROM users
     GROUP BY cohort_week`
  ).all<{ cohort_week: string; size: number }>();
  const cohortSizes: Record<string, number> = {};
  for (const row of cohortSizesResult.results || []) {
    cohortSizes[row.cohort_week] = row.size;
  }

  const retentionCohorts = (cohortRows.results || []).map((r) => ({
    cohort_week: r.cohort_week,
    cohort_size: cohortSizes[r.cohort_week] ?? 0,
    weeks_offset: Math.max(0, r.weeks_offset),
    active: r.active,
  }));

  // 5. Pillar adoption — distinct users per category
  const llmProviders = listProvidersByCategory('llm').map((p) => p.id);
  const serviceProviders = listProvidersByCategory('service').map((p) => p.id);
  const oauthProviders = listProvidersByCategory('oauth').map((p) => p.id);

  const usersWithLLM = await countUsersWithProviders(env, llmProviders);
  const usersWithService = await countUsersWithProviders(env, serviceProviders);
  const usersWithOAuth = await countUsersWithProviders(env, oauthProviders);
  const usersWithAny = await env.DB.prepare(
    'SELECT COUNT(DISTINCT user_id) AS c FROM keys_metadata'
  ).first<{ c: number }>();
  const usersWithAllThree = await countUsersWithAllThreePillars(
    env,
    llmProviders,
    serviceProviders,
    oauthProviders
  );

  // 6. Activity heatmap (UTC, last 7 days)
  const heatmapResult = await env.DB.prepare(
    `SELECT
       CAST(strftime('%w', timestamp) AS INTEGER) AS day_of_week,
       CAST(strftime('%H', timestamp) AS INTEGER) AS hour_of_day,
       COUNT(*) AS calls
     FROM audit_logs
     WHERE datetime(timestamp) > datetime('now', '-7 days')
       AND ${USAGE_PREDICATE}
     GROUP BY day_of_week, hour_of_day
     ORDER BY day_of_week, hour_of_day`
  ).all<{ day_of_week: number; hour_of_day: number; calls: number }>();

  // 7. Geographic distribution (top 15 countries, last 30 days)
  const geoResult = await env.DB.prepare(
    `SELECT country, COUNT(*) AS calls
     FROM audit_logs
     WHERE datetime(timestamp) > datetime('now', '-30 days')
       AND country IS NOT NULL
       AND country != ''
       AND ${USAGE_PREDICATE}
     GROUP BY country
     ORDER BY calls DESC
     LIMIT 15`
  ).all<{ country: string; calls: number }>();

  return {
    generated_at: new Date().toISOString(),
    users: {
      total: usersRow?.total ?? 0,
      new_last_7d: usersRow?.new_7d ?? 0,
      new_last_30d: usersRow?.new_30d ?? 0,
      logged_in_last_7d: usersRow?.active_7d ?? 0,
    },
    credentials: {
      total: credsTotal?.c ?? 0,
      by_credential_type: typeMap,
      by_category: categoryCounts,
      paused: credsPaused?.c ?? 0,
    },
    tokens: {
      total: tokensRow?.total ?? 0,
      active: tokensRow?.active ?? 0,
      revoked: tokensRow?.revoked ?? 0,
      paused: tokensRow?.paused ?? 0,
    },
    devices: {
      total: devicesRow?.total ?? 0,
      active: devicesRow?.active ?? 0,
      revoked: devicesRow?.revoked ?? 0,
    },
    activity: {
      last_24h: activityRow?.last_24h ?? 0,
      last_7d: activityRow?.last_7d ?? 0,
      last_30d: activityRow?.last_30d ?? 0,
    },
    top_providers: (credsByProvider.results || []).map((r) => ({
      provider: r.provider,
      count: r.c,
    })),
    launch_tracking: {
      funnel: {
        signups: funnelRow?.signups ?? 0,
        registered_cli: funnelRow?.registered ?? 0,
        stored_credential: funnelRow?.stored ?? 0,
        first_usage: funnelRow?.used ?? 0,
      },
      time_to_value_seconds: {
        signup_to_register: ttvSignupToRegister?.avg_seconds ?? null,
        register_to_store: ttvRegisterToStore?.avg_seconds ?? null,
        store_to_use: ttvStoreToUse?.avg_seconds ?? null,
      },
      dau_series: (dauResult.results || []).map((r) => ({
        date: r.day,
        active_users: r.active_users,
      })),
      retention_cohorts: retentionCohorts,
      pillar_adoption: {
        total_users_with_any_credential: usersWithAny?.c ?? 0,
        with_llm: usersWithLLM,
        with_service: usersWithService,
        with_oauth: usersWithOAuth,
        with_all_three: usersWithAllThree,
      },
      activity_heatmap: heatmapResult.results || [],
      geo: geoResult.results || [],
    },
  };
}

async function getCategoryForProvider(provider: string): Promise<'llm' | 'service' | 'oauth'> {
  // Lazy import to avoid circular deps
  const { getProviderTemplate } = await import('./providers');
  const template = getProviderTemplate(provider);
  return (template?.category as 'llm' | 'service' | 'oauth') ?? 'service';
}

async function countUsersWithProviders(env: Env, providers: string[]): Promise<number> {
  if (providers.length === 0) return 0;
  const placeholders = providers.map(() => '?').join(',');
  const row = await env.DB.prepare(
    `SELECT COUNT(DISTINCT user_id) AS c
       FROM keys_metadata
      WHERE provider IN (${placeholders})`
  )
    .bind(...providers)
    .first<{ c: number }>();
  return row?.c ?? 0;
}

async function countUsersWithAllThreePillars(
  env: Env,
  llm: string[],
  service: string[],
  oauth: string[]
): Promise<number> {
  if (llm.length === 0 || service.length === 0 || oauth.length === 0) return 0;
  const llmPlace = llm.map(() => '?').join(',');
  const svcPlace = service.map(() => '?').join(',');
  const oauthPlace = oauth.map(() => '?').join(',');
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM (
       SELECT user_id
         FROM keys_metadata
        WHERE provider IN (${llmPlace})
        GROUP BY user_id
       INTERSECT
       SELECT user_id
         FROM keys_metadata
        WHERE provider IN (${svcPlace})
        GROUP BY user_id
       INTERSECT
       SELECT user_id
         FROM keys_metadata
        WHERE provider IN (${oauthPlace})
        GROUP BY user_id
     )`
  )
    .bind(...llm, ...service, ...oauth)
    .first<{ c: number }>();
  return row?.c ?? 0;
}
