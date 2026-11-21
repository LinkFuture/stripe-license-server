import { config } from "../config/config";
import { generateEd25519, publicKeyImports } from "./crypto";
import { logEvent } from "./db";
import type { AppRow, Env } from "./types";
import { appKeySecretName, likeContains, nowIso, pageParams, parseMailFrom, parsePositiveInt, str, timingSafeEqualHash } from "./util";

export async function adminAuthorized(env: Env, header: string | undefined): Promise<boolean> {
  const token = env.ADMIN_TOKEN;
  if (!token || !header?.startsWith("Bearer ")) return false;
  const presented = header.slice("Bearer ".length).trim();
  if (!presented) return false;
  return timingSafeEqualHash(presented, token);
}

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const PREFIX = /^[A-Z0-9]{2,12}$/;
const RESERVED_SLUGS = new Set(["admin", "stripe", "health", "api"]);

function mailFromInput(
  value: unknown,
  current: string | null,
): { ok: true; value: string | null } | { ok: false } {
  if (value === undefined) return { ok: true, value: current };
  if (value === null || value === "") return { ok: true, value: null };
  if (typeof value !== "string") return { ok: false };
  const formatted = parseMailFrom(value);
  if (!formatted) return { ok: false };
  return { ok: true, value: formatted };
}

function optInt(value: unknown, fallback: number, min: number, max: number): number | null {
  if (value === undefined || value === null || value === "") return fallback;
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return null;
  return n;
}

export async function createApp(env: Env, body: Record<string, unknown>, now: Date) {
  const slug = str(body.slug, 40)?.toLowerCase() ?? "";
  const name = str(body.name, 120) ?? "";
  const keyPrefix = str(body.key_prefix, 12)?.toUpperCase() ?? "";
  if (!SLUG.test(slug)) return { status: 400 as const, body: { error: "invalid_slug" } };
  if (RESERVED_SLUGS.has(slug)) return { status: 400 as const, body: { error: "reserved_slug" } };
  if (!name) return { status: 400 as const, body: { error: "invalid_name" } };
  if (!PREFIX.test(keyPrefix)) return { status: 400 as const, body: { error: "invalid_key_prefix" } };
  const defaults = config.appDefaults;
  const trialDays = optInt(body.trial_days, defaults.trialDays, 0, 3650);
  const grace = optInt(body.offline_grace_days, defaults.offlineGraceDays, 0, 3650);
  const inactive = optInt(body.inactive_release_days, defaults.inactiveReleaseDays, 0, 3650);
  const resetLimit = optInt(body.reset_limit, defaults.resetLimit, 0, 100);
  const resetWindow = optInt(body.reset_window_days, defaults.resetWindowDays, 1, 3650);
  if (
    trialDays === null ||
    grace === null ||
    inactive === null ||
    resetLimit === null ||
    resetWindow === null
  ) {
    return { status: 400 as const, body: { error: "invalid_settings" } };
  }
  const mailFrom = mailFromInput(body.mail_from, null);
  if (!mailFrom.ok) return { status: 400 as const, body: { error: "invalid_mail_from" } };

  let publicKey = str(body.public_key, 4000);
  let privateKey: string | null = null;
  if (publicKey) {
    if (!(await publicKeyImports(publicKey))) {
      return { status: 400 as const, body: { error: "invalid_public_key" } };
    }
  } else {
    const generated = await generateEd25519();
    publicKey = generated.publicKeyPem;
    privateKey = generated.privateKeyPem;
  }

  try {
    await env.DB
      .prepare(
        `INSERT INTO apps (
           slug, name, key_prefix, public_key, trial_days, offline_grace_days,
           inactive_release_days, reset_limit, reset_window_days, mail_from, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        slug,
        name,
        keyPrefix,
        publicKey,
        trialDays,
        grace,
        inactive,
        resetLimit,
        resetWindow,
        mailFrom.value,
        nowIso(now),
      )
      .run();
  } catch (error) {
    if (String(error).includes("UNIQUE")) {
      return { status: 409 as const, body: { error: "app_exists" } };
    }
    throw error;
  }
  const app = await env.DB.prepare(`SELECT * FROM apps WHERE slug = ?`).bind(slug).first<AppRow>();
  const secretName = appKeySecretName(slug);
  return {
    status: 201 as const,
    body: {
      app,
      ...(privateKey
        ? {
            private_key: privateKey,
            instructions: `Store this private key now. It is not saved. Run: wrangler secret put ${secretName}`,
          }
        : { instructions: `Ensure wrangler secret ${secretName} matches this public key.` }),
    },
  };
}

export async function listApps(env: Env) {
  const rows = await env.DB.prepare(`SELECT * FROM apps ORDER BY id ASC`).all<AppRow>();
  return rows.results ?? [];
}

export async function patchApp(env: Env, slug: string, body: Record<string, unknown>) {
  const app = await env.DB.prepare(`SELECT * FROM apps WHERE slug = ?`).bind(slug).first<AppRow>();
  if (!app) return { status: 404 as const, body: { error: "app_not_found" } };
  const name = body.name === undefined ? app.name : str(body.name, 120);
  const trialDays = optInt(body.trial_days, app.trial_days, 0, 3650);
  const grace = optInt(body.offline_grace_days, app.offline_grace_days, 0, 3650);
  const inactive = optInt(body.inactive_release_days, app.inactive_release_days, 0, 3650);
  const resetLimit = optInt(body.reset_limit, app.reset_limit, 0, 100);
  const resetWindow = optInt(body.reset_window_days, app.reset_window_days, 1, 3650);
  const status =
    body.status === undefined ? app.status : body.status === "active" || body.status === "disabled" ? body.status : null;
  const mailFrom = mailFromInput(body.mail_from, app.mail_from);
  if (!name || trialDays === null || grace === null || inactive === null || resetLimit === null || resetWindow === null || !status) {
    return { status: 400 as const, body: { error: "invalid_settings" } };
  }
  if (!mailFrom.ok) return { status: 400 as const, body: { error: "invalid_mail_from" } };
  await env.DB
    .prepare(
      `UPDATE apps SET name = ?, trial_days = ?, offline_grace_days = ?, inactive_release_days = ?,
        reset_limit = ?, reset_window_days = ?, mail_from = ?, status = ? WHERE id = ?`,
    )
    .bind(name, trialDays, grace, inactive, resetLimit, resetWindow, mailFrom.value, status, app.id)
    .run();
  const updated = await env.DB.prepare(`SELECT * FROM apps WHERE id = ?`).bind(app.id).first<AppRow>();
  return { status: 200 as const, body: { app: updated } };
}

function cutoffFor(days: number, now: Date): string {
  if (days <= 0) return "0000-01-01T00:00:00.000Z";
  return new Date(now.getTime() - days * 86_400_000).toISOString();
}

export async function listLicenses(env: Env, url: URL, now: Date) {
  const page = pageParams(url);
  if (!page) return { status: 400 as const, body: { error: "invalid_page" } };
  const app = url.searchParams.get("app");
  const status = url.searchParams.get("status");
  const q = url.searchParams.get("q")?.trim() ?? "";
  if (status && status !== "active" && status !== "revoked") {
    return { status: 400 as const, body: { error: "invalid_status" } };
  }
  const filters = [
    app ? "apps.slug = ?" : "1 = 1",
    status ? "licenses.status = ?" : "1 = 1",
    q ? "(licenses.email LIKE ? ESCAPE '\\' OR licenses.key_last4 = ?)" : "1 = 1",
  ];
  const binds: unknown[] = [];
  if (app) binds.push(app);
  if (status) binds.push(status);
  if (q) binds.push(likeContains(q.toLowerCase()), q.toUpperCase());
  const where = filters.join(" AND ");
  const totalRow = await env.DB
    .prepare(
      `SELECT COUNT(*) AS c FROM licenses JOIN apps ON apps.id = licenses.app_id WHERE ${where}`,
    )
    .bind(...binds)
    .first<{ c: number }>();
  const rows = await env.DB
    .prepare(
      `SELECT licenses.*, apps.slug AS app_slug, apps.inactive_release_days AS inactive_release_days
       FROM licenses JOIN apps ON apps.id = licenses.app_id
       WHERE ${where}
       ORDER BY licenses.id DESC
       LIMIT ? OFFSET ?`,
    )
    .bind(...binds, page.perPage, page.offset)
    .all<Record<string, unknown>>();
  const items = rows.results ?? [];
  const ids = items.map((row) => row.id as number);
  const activations = ids.length
    ? (
        await env.DB
          .prepare(
            `SELECT license_id, last_seen_at FROM activations WHERE license_id IN (${ids.map(() => "?").join(",")})`,
          )
          .bind(...ids)
          .all<{ license_id: number; last_seen_at: string }>()
      ).results ?? []
    : [];
  const shaped = items.map((row) => {
    const cutoff = cutoffFor(Number(row.inactive_release_days), now);
    const mine = activations.filter((a) => a.license_id === row.id);
    const used = mine.filter((a) => a.last_seen_at >= cutoff).length;
    return {
      id: row.id,
      app: row.app_slug,
      email: row.email,
      key_last4: row.key_last4,
      max_machines: row.max_machines,
      used_machines: used,
      total_machines: mine.length,
      status: row.status,
      stripe_session_id: row.stripe_session_id,
      stripe_payment_intent: row.stripe_payment_intent,
      revoked_at: row.revoked_at,
      revoke_reason: row.revoke_reason,
      created_at: row.created_at,
    };
  });
  return {
    status: 200 as const,
    body: { items: shaped, page: page.page, per_page: page.perPage, total: totalRow?.c ?? 0 },
  };
}

export async function listActivations(env: Env, url: URL) {
  const page = pageParams(url);
  if (!page) return { status: 400 as const, body: { error: "invalid_page" } };
  const app = url.searchParams.get("app");
  const license = url.searchParams.get("license");
  const email = url.searchParams.get("email");
  const platform = url.searchParams.get("platform");
  let licenseId: number | null = null;
  if (license) {
    licenseId = parsePositiveInt(license, 1_000_000_000);
    if (!licenseId) return { status: 400 as const, body: { error: "invalid_license" } };
  }
  const filters = [
    app ? "apps.slug = ?" : "1 = 1",
    licenseId ? "activations.license_id = ?" : "1 = 1",
    email ? "licenses.email = ?" : "1 = 1",
    platform ? "activations.platform = ?" : "1 = 1",
  ];
  const binds: unknown[] = [];
  if (app) binds.push(app);
  if (licenseId) binds.push(licenseId);
  if (email) binds.push(email.toLowerCase());
  if (platform) binds.push(platform);
  const where = filters.join(" AND ");
  const totalRow = await env.DB
    .prepare(
      `SELECT COUNT(*) AS c
       FROM activations
       JOIN licenses ON licenses.id = activations.license_id
       JOIN apps ON apps.id = licenses.app_id
       WHERE ${where}`,
    )
    .bind(...binds)
    .first<{ c: number }>();
  const rows = await env.DB
    .prepare(
      `SELECT activations.*, licenses.email AS email, licenses.key_last4 AS key_last4,
              licenses.status AS license_status, licenses.max_machines AS max_machines,
              apps.slug AS app
       FROM activations
       JOIN licenses ON licenses.id = activations.license_id
       JOIN apps ON apps.id = licenses.app_id
       WHERE ${where}
       ORDER BY activations.id DESC
       LIMIT ? OFFSET ?`,
    )
    .bind(...binds, page.perPage, page.offset)
    .all();
  return {
    status: 200 as const,
    body: {
      items: rows.results ?? [],
      page: page.page,
      per_page: page.perPage,
      total: totalRow?.c ?? 0,
    },
  };
}

export async function revokeLicense(env: Env, id: number, ip: string, now: Date, appSlug: string) {
  const license = await env.DB
    .prepare(
      `SELECT licenses.id, licenses.app_id, licenses.status
       FROM licenses JOIN apps ON apps.id = licenses.app_id
       WHERE licenses.id = ? AND apps.slug = ?`,
    )
    .bind(id, appSlug)
    .first<{ id: number; app_id: number; status: string }>();
  if (!license) return { status: 404 as const, body: { error: "not_found" } };
  if (license.status !== "revoked") {
    const revokedAt = nowIso(now);
    await env.DB
      .prepare(
        `UPDATE licenses SET status = 'revoked', revoked_at = ?, revoke_reason = 'admin'
         WHERE id = ? AND app_id = ?`,
      )
      .bind(revokedAt, id, license.app_id)
      .run();
    await logEvent(env.DB, {
      appId: license.app_id,
      licenseId: id,
      type: "license.revoked",
      ip,
      detail: { reason: "admin" },
      createdAt: revokedAt,
    });
  }
  const updated = await env.DB.prepare(`SELECT * FROM licenses WHERE id = ?`).bind(id).first();
  return { status: 200 as const, body: { license: updated } };
}

export async function deleteActivation(env: Env, id: number, ip: string, now: Date, appSlug: string) {
  const row = await env.DB
    .prepare(
      `SELECT activations.*, licenses.app_id AS app_id
       FROM activations
       JOIN licenses ON licenses.id = activations.license_id
       JOIN apps ON apps.id = licenses.app_id
       WHERE activations.id = ? AND apps.slug = ?`,
    )
    .bind(id, appSlug)
    .first<{ id: number; license_id: number; app_id: number; machine_hash: string }>();
  if (!row) return { status: 404 as const, body: { error: "not_found" } };
  await env.DB
    .prepare(
      `DELETE FROM activations
       WHERE id = ?
         AND license_id IN (SELECT id FROM licenses WHERE app_id = ?)`,
    )
    .bind(id, row.app_id)
    .run();
  await logEvent(env.DB, {
    appId: row.app_id,
    licenseId: row.license_id,
    type: "activation.removed",
    machineHash: row.machine_hash,
    ip,
    detail: { reason: "admin", activation_id: id },
    createdAt: nowIso(now),
  });
  return { status: 200 as const, body: { ok: true } };
}

interface TrendPoint {
  date: string;
  trial_started: number;
  activation_created: number;
  license_issued: number;
}

async function statsForApp(env: Env, app: AppRow, now: Date) {
  const db = env.DB;
  const day = 86_400_000;
  const iso7 = new Date(now.getTime() - 7 * day).toISOString();
  const iso30 = new Date(now.getTime() - 30 * day).toISOString();
  const nowIsoValue = now.toISOString();
  const trendStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 29)).toISOString();

  const licenseCounts = await db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked
       FROM licenses WHERE app_id = ?`,
    )
    .bind(app.id)
    .first<{ total: number; active: number | null; revoked: number | null }>();
  const byMax = await db
    .prepare(
      `SELECT max_machines, COUNT(*) AS count FROM licenses WHERE app_id = ? GROUP BY max_machines ORDER BY max_machines`,
    )
    .bind(app.id)
    .all<{ max_machines: number; count: number }>();
  const activatedLicenses = await db
    .prepare(
      `SELECT COUNT(DISTINCT licenses.id) AS c
       FROM licenses JOIN activations ON activations.license_id = licenses.id
       WHERE licenses.app_id = ?`,
    )
    .bind(app.id)
    .first<{ c: number }>();
  const activatedUsers = await db
    .prepare(
      `SELECT COUNT(DISTINCT licenses.email) AS c
       FROM licenses JOIN activations ON activations.license_id = licenses.id
       WHERE licenses.app_id = ?`,
    )
    .bind(app.id)
    .first<{ c: number }>();
  const machines = await db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN activations.last_seen_at >= ? THEN 1 ELSE 0 END) AS active_7d,
         SUM(CASE WHEN activations.last_seen_at >= ? THEN 1 ELSE 0 END) AS active_30d
       FROM activations JOIN licenses ON licenses.id = activations.license_id
       WHERE licenses.app_id = ?`,
    )
    .bind(iso7, iso30, app.id)
    .first<{ total: number; active_7d: number | null; active_30d: number | null }>();
  const byPlatform = await db
    .prepare(
      `SELECT COALESCE(activations.platform, 'unknown') AS platform, COUNT(*) AS count
       FROM activations JOIN licenses ON licenses.id = activations.license_id
       WHERE licenses.app_id = ?
       GROUP BY platform ORDER BY platform`,
    )
    .bind(app.id)
    .all<{ platform: string; count: number }>();
  const byVersion = await db
    .prepare(
      `SELECT COALESCE(activations.app_version, 'unknown') AS app_version, COUNT(*) AS count
       FROM activations JOIN licenses ON licenses.id = activations.license_id
       WHERE licenses.app_id = ?
       GROUP BY app_version ORDER BY app_version`,
    )
    .bind(app.id)
    .all<{ app_version: string; count: number }>();
  const trials = await db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS running,
         SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) AS expired
       FROM trials WHERE app_id = ?`,
    )
    .bind(nowIsoValue, nowIsoValue, app.id)
    .first<{ total: number; running: number | null; expired: number | null }>();
  const converted = await db
    .prepare(
      `SELECT COUNT(DISTINCT trials.machine_hash) AS c
       FROM trials
       WHERE trials.app_id = ?
         AND EXISTS (
           SELECT 1 FROM activations
           JOIN licenses ON licenses.id = activations.license_id
           WHERE licenses.app_id = trials.app_id AND activations.machine_hash = trials.machine_hash
         )`,
    )
    .bind(app.id)
    .first<{ c: number }>();
  const trendRows = await db
    .prepare(
      `SELECT substr(created_at, 1, 10) AS day, type, COUNT(*) AS c
       FROM events
       WHERE app_id = ?
         AND type IN ('trial.started', 'activation.created', 'license.issued')
         AND created_at >= ?
       GROUP BY day, type`,
    )
    .bind(app.id, trendStart)
    .all<{ day: string; type: string; c: number }>();
  const trendMap = new Map<string, TrendPoint>();
  for (let i = 0; i < 30; i++) {
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 29 + i))
      .toISOString()
      .slice(0, 10);
    trendMap.set(date, { date, trial_started: 0, activation_created: 0, license_issued: 0 });
  }
  for (const row of trendRows.results ?? []) {
    const point = trendMap.get(row.day);
    if (!point) continue;
    if (row.type === "trial.started") point.trial_started = row.c;
    else if (row.type === "activation.created") point.activation_created = row.c;
    else if (row.type === "license.issued") point.license_issued = row.c;
  }

  const n = (value: unknown) => {
    const parsed = Number(value ?? 0);
    return Number.isFinite(parsed) ? parsed : 0;
  };
  return {
    app: app.slug,
    licenses: {
      total: n(licenseCounts?.total),
      active: n(licenseCounts?.active),
      revoked: n(licenseCounts?.revoked),
      by_max_machines: (byMax.results ?? []).map((row) => ({
        max_machines: n(row.max_machines),
        count: n(row.count),
      })),
    },
    activated_licenses: n(activatedLicenses?.c),
    activated_users: n(activatedUsers?.c),
    machines: {
      total: n(machines?.total),
      active_7d: n(machines?.active_7d),
      active_30d: n(machines?.active_30d),
      by_platform: (byPlatform.results ?? []).map((row) => ({ platform: row.platform, count: n(row.count) })),
      by_app_version: (byVersion.results ?? []).map((row) => ({
        app_version: row.app_version,
        count: n(row.count),
      })),
    },
    trials: {
      total: n(trials?.total),
      running: n(trials?.running),
      expired: n(trials?.expired),
      converted: n(converted?.c),
    },
    trend: [...trendMap.values()],
  };
}

export async function stats(env: Env, url: URL, now: Date) {
  const slug = url.searchParams.get("app");
  const apps = slug
    ? [
        await env.DB.prepare(`SELECT * FROM apps WHERE slug = ?`).bind(slug).first<AppRow>(),
      ].filter((app): app is AppRow => !!app)
    : ((await env.DB.prepare(`SELECT * FROM apps ORDER BY slug ASC`).all<AppRow>()).results ?? []);
  if (slug && apps.length === 0) return { status: 404 as const, body: { error: "app_not_found" } };
  const result = [];
  for (const app of apps) result.push(await statsForApp(env, app, now));
  return { status: 200 as const, body: { apps: result } };
}
