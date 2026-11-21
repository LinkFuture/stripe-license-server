import {
  decryptSecret,
  hashCode,
  hashLicenseKey,
  normalizeLicenseKey,
  randomDigits,
} from "./crypto";
import { countsTowardLimit, getLicenseByHash, listActivations, logEvent, machineView } from "./db";
import { licenseEmail, resetCodeEmail } from "./email";
import { hitLimit, limits } from "./rate-limit";
import { signLicenseJwt, signTrialJwt } from "./tokens";
import type { ActivationRow, AppRow, Env, LicenseRow, SendEmail, TrialRow } from "./types";
import { addDays, emailOk, machineHashOk, normalizeMachineHash, nowIso, resolveMailFrom, resolveReplyTo, str, timingSafeEqual } from "./util";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly extra?: Record<string, unknown>,
  ) {
    super(code);
  }
}

async function requireSigningKey(env: Env, app: AppRow): Promise<string> {
  const { appPrivateKey } = await import("./util");
  const key = appPrivateKey(env, app.slug);
  if (!key) throw new HttpError(500, "signing_key_missing");
  return key;
}

export async function loadLicense(
  db: D1Database,
  app: AppRow,
  rawKey: unknown,
): Promise<{ license: LicenseRow; canonical: string }> {
  const keyText = str(rawKey, 80);
  if (!keyText) throw new HttpError(400, "invalid_key");
  const canonical = normalizeLicenseKey(keyText);
  if (!canonical) throw new HttpError(400, "invalid_key");
  const license = await getLicenseByHash(db, await hashLicenseKey(canonical));
  if (!license || license.app_id !== app.id) throw new HttpError(400, "invalid_key");
  return { license, canonical };
}

function assertActive(license: LicenseRow): void {
  if (license.status === "revoked") throw new HttpError(403, "revoked");
}

async function touchActivation(
  db: D1Database,
  row: ActivationRow,
  fields: { machineName: string | null; platform: string | null; appVersion: string | null },
  now: Date,
): Promise<void> {
  await db
    .prepare(
      `UPDATE activations
       SET last_seen_at = ?, machine_name = COALESCE(?, machine_name),
           platform = COALESCE(?, platform), app_version = COALESCE(?, app_version)
       WHERE id = ?`,
    )
    .bind(nowIso(now), fields.machineName, fields.platform, fields.appVersion, row.id)
    .run();
}

export async function activate(opts: {
  env: Env;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, app, body, ip, now } = opts;
  const machineHash = str(body.machine_hash, 80);
  if (!machineHash || !machineHashOk(machineHash)) throw new HttpError(400, "invalid_machine");
  const hash = normalizeMachineHash(machineHash);
  const { license } = await loadLicense(env.DB, app, body.key);
  const lim = limits();
  if (await hitLimit(env.DB, `activate-key:${license.key_hash}`, lim.activateKeyPerMin, 60, now)) {
    throw new HttpError(429, "rate_limited");
  }
  assertActive(license);
  const machineName = str(body.machine_name, 128);
  const platform = str(body.platform, 64);
  const appVersion = str(body.app_version, 64);
  const rows = await listActivations(env.DB, license.id);
  const existing = rows.find((row) => row.machine_hash === hash);
  const privateKey = await requireSigningKey(env, app);
  if (existing) {
    await touchActivation(env.DB, existing, { machineName, platform, appVersion }, now);
    const signed = await signLicenseJwt(env, app, privateKey, license.id, hash, license.max_machines, now);
    return {
      token: signed.token,
      license_id: license.id,
      max_machines: license.max_machines,
      expires_at: signed.expiresAt,
      machine_hash: hash,
    };
  }
  const counting = rows.filter((row) => countsTowardLimit(row, app.inactive_release_days, now));
  if (counting.length >= license.max_machines) {
    throw new HttpError(409, "machine_limit_reached", {
      message: "All device slots are in use.",
      max_machines: license.max_machines,
      machines: rows.map((row) => machineView(row, countsTowardLimit(row, app.inactive_release_days, now))),
    });
  }
  await env.DB
    .prepare(
      `INSERT INTO activations (license_id, machine_hash, machine_name, platform, app_version, activated_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(license.id, hash, machineName, platform, appVersion, nowIso(now), nowIso(now))
    .run();
  await logEvent(env.DB, {
    appId: app.id,
    licenseId: license.id,
    type: "activation.created",
    machineHash: hash,
    ip,
    detail: { machine_name: machineName, platform, app_version: appVersion },
    createdAt: nowIso(now),
  });
  const signed = await signLicenseJwt(env, app, privateKey, license.id, hash, license.max_machines, now);
  return {
    token: signed.token,
    license_id: license.id,
    max_machines: license.max_machines,
    expires_at: signed.expiresAt,
    machine_hash: hash,
  };
}

export async function validate(opts: {
  env: Env;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, app, body, ip, now } = opts;
  const machineHash = str(body.machine_hash, 80);
  if (!machineHash || !machineHashOk(machineHash)) throw new HttpError(400, "invalid_machine");
  const hash = normalizeMachineHash(machineHash);
  const { license } = await loadLicense(env.DB, app, body.key);
  const lim = limits();
  if (await hitLimit(env.DB, `validate-key:${license.key_hash}`, lim.validateKeyPerMin, 60, now)) {
    throw new HttpError(429, "rate_limited");
  }
  assertActive(license);
  const row = await env.DB
    .prepare(`SELECT * FROM activations WHERE license_id = ? AND machine_hash = ?`)
    .bind(license.id, hash)
    .first<ActivationRow>();
  if (!row) throw new HttpError(403, "not_activated");
  await touchActivation(
    env.DB,
    row,
    { machineName: null, platform: null, appVersion: null },
    now,
  );
  await logEvent(env.DB, {
    appId: app.id,
    licenseId: license.id,
    type: "activation.validated",
    machineHash: hash,
    ip,
    createdAt: nowIso(now),
  });
  const privateKey = await requireSigningKey(env, app);
  const signed = await signLicenseJwt(env, app, privateKey, license.id, hash, license.max_machines, now);
  return {
    token: signed.token,
    license_id: license.id,
    max_machines: license.max_machines,
    expires_at: signed.expiresAt,
    machine_hash: hash,
  };
}

export async function deactivate(opts: {
  env: Env;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, app, body, ip, now } = opts;
  const machineHash = str(body.machine_hash, 80);
  if (!machineHash || !machineHashOk(machineHash)) throw new HttpError(400, "invalid_machine");
  const hash = normalizeMachineHash(machineHash);
  const { license } = await loadLicense(env.DB, app, body.key);
  const existing = await env.DB
    .prepare(`SELECT id FROM activations WHERE license_id = ? AND machine_hash = ?`)
    .bind(license.id, hash)
    .first<{ id: number }>();
  if (existing) {
    await env.DB.prepare(`DELETE FROM activations WHERE id = ?`).bind(existing.id).run();
    await logEvent(env.DB, {
      appId: app.id,
      licenseId: license.id,
      type: "activation.removed",
      machineHash: hash,
      ip,
      detail: { reason: "deactivate", activation_id: existing.id },
      createdAt: nowIso(now),
    });
  }
  return { ok: true };
}

export async function startTrial(opts: {
  env: Env;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, app, body, ip, now } = opts;
  const machineHash = str(body.machine_hash, 80);
  if (!machineHash || !machineHashOk(machineHash)) throw new HttpError(400, "invalid_machine");
  const hash = normalizeMachineHash(machineHash);
  const platform = str(body.platform, 64);
  const appVersion = str(body.app_version, 64);
  let local: Date | null = null;
  if (body.local_started_at !== undefined && body.local_started_at !== null) {
    const text = str(body.local_started_at, 40);
    const parsed = text ? Date.parse(text) : NaN;
    if (!text || Number.isNaN(parsed)) throw new HttpError(400, "invalid_local_started_at");
    const skew = 5 * 60 * 1000;
    local = new Date(Math.min(parsed, now.getTime() + skew));
    if (local.getTime() > now.getTime()) local = now;
  }

  const existing = await env.DB
    .prepare(`SELECT * FROM trials WHERE app_id = ? AND machine_hash = ?`)
    .bind(app.id, hash)
    .first<TrialRow>();

  let trial: TrialRow;
  if (!existing) {
    const start = local && local.getTime() < now.getTime() ? local : now;
    const expires = addDays(start, app.trial_days);
    const inserted = await env.DB
      .prepare(
        `INSERT INTO trials (app_id, machine_hash, started_at, expires_at, platform, app_version, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         RETURNING *`,
      )
      .bind(app.id, hash, start.toISOString(), expires, platform, appVersion, nowIso(now))
      .all<TrialRow>();
    trial = inserted.results?.[0] as TrialRow;
    await logEvent(env.DB, {
      appId: app.id,
      type: "trial.started",
      machineHash: hash,
      ip,
      detail: { started_at: trial.started_at, expires_at: trial.expires_at, platform, app_version: appVersion },
      createdAt: nowIso(now),
    });
  } else {
    trial = existing;
    if (local && local.getTime() < Date.parse(existing.started_at)) {
      const expires = addDays(local, app.trial_days);
      await env.DB
        .prepare(
          `UPDATE trials SET started_at = ?, expires_at = ?, platform = COALESCE(?, platform), app_version = COALESCE(?, app_version) WHERE id = ?`,
        )
        .bind(local.toISOString(), expires, platform, appVersion, existing.id)
        .run();
      trial = {
        ...existing,
        started_at: local.toISOString(),
        expires_at: expires,
      };
      await logEvent(env.DB, {
        appId: app.id,
        type: "trial.adjusted",
        machineHash: hash,
        ip,
        detail: { started_at: trial.started_at, expires_at: trial.expires_at },
        createdAt: nowIso(now),
      });
    }
  }

  const privateKey = await requireSigningKey(env, app);
  const token = await signTrialJwt(env, app, privateKey, trial.id, hash, trial.expires_at, now);
  return {
    token,
    started_at: trial.started_at,
    expires_at: trial.expires_at,
    machine_hash: hash,
    trial_days: app.trial_days,
  };
}

export async function recover(opts: {
  env: Env;
  send: SendEmail;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, send, app, body, ip, now } = opts;
  const response = {
    ok: true,
    message: "If a license exists for this email, it has been sent.",
  };
  const email = str(body.email, 320)?.toLowerCase() ?? "";
  const lim = limits();
  if (
    email &&
    (await hitLimit(env.DB, `recover-email:${app.id}:${email}`, lim.recoverEmailPerHour, 3600, now))
  ) {
    throw new HttpError(429, "rate_limited");
  }
  if (!email || !emailOk(email)) return response;
  await logEvent(env.DB, {
    appId: app.id,
    type: "license.recovered",
    ip,
    detail: { email },
    createdAt: nowIso(now),
  });
  if (!env.LICENSE_ENCRYPTION_KEY) return response;
  const rows = await env.DB
    .prepare(
      `SELECT * FROM licenses WHERE app_id = ? AND email = ? AND status = 'active' ORDER BY id ASC`,
    )
    .bind(app.id, email)
    .all<LicenseRow>();
  const licenses = rows.results ?? [];
  if (licenses.length === 0) return response;
  const from = resolveMailFrom(env, app.mail_from);
  if (!from) {
    console.log(JSON.stringify({ event: "email_failed", reason: "mail_from_unset", app: app.slug }));
    await logEvent(env.DB, {
      appId: app.id,
      type: "email.failed",
      ip,
      detail: { reason: "mail_from_unset", purpose: "recover" },
      createdAt: nowIso(now),
    });
    return response;
  }
  const keys: string[] = [];
  for (const license of licenses) {
    keys.push(await decryptSecret(license.key_enc, env.LICENSE_ENCRYPTION_KEY));
  }
  try {
    await send(env, {
      from,
      replyTo: resolveReplyTo(env),
      to: email,
      subject: `Your ${app.name} license key${keys.length > 1 ? "s" : ""}`,
      text: licenseEmail(app.name, keys),
    });
  } catch (error) {
    console.log(JSON.stringify({ event: "email_failed", error: String(error) }));
  }
  return response;
}

async function assertResetAllowed(db: D1Database, app: AppRow, licenseId: number, now: Date): Promise<void> {
  if (app.reset_limit === 0) return;
  const since = addDays(now, -app.reset_window_days);
  if ((await resetCount(db, licenseId, since)) >= app.reset_limit) {
    throw new HttpError(429, "reset_limit_reached");
  }
}

async function resetCount(db: D1Database, licenseId: number, sinceIso: string): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS c FROM events
       WHERE license_id = ? AND type = 'activation.removed'
         AND machine_hash IS NULL
         AND created_at >= ?
         AND detail LIKE '%"reason":"reset"%'`,
    )
    .bind(licenseId, sinceIso)
    .first<{ c: number }>();
  return row?.c ?? 0;
}

export async function requestReset(opts: {
  env: Env;
  send: SendEmail;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, send, app, body, ip, now } = opts;
  const { license } = await loadLicense(env.DB, app, body.key);
  assertActive(license);
  if (!env.LICENSE_ENCRYPTION_KEY) throw new HttpError(500, "encryption_key_missing");
  const from = resolveMailFrom(env, app.mail_from);
  if (!from) throw new HttpError(500, "mail_from_unset");
  await assertResetAllowed(env.DB, app, license.id, now);
  const lim = limits();
  const code = randomDigits(6);
  const codeHash = await hashCode(code, license.id, env.LICENSE_ENCRYPTION_KEY);
  const expires = new Date(now.getTime() + lim.codeTtlSeconds * 1000).toISOString();
  await env.DB
    .prepare(
      `INSERT INTO email_codes (app_id, email, license_id, code_hash, purpose, expires_at, created_at)
       VALUES (?, ?, ?, ?, 'reset_machines', ?, ?)`,
    )
    .bind(app.id, license.email, license.id, codeHash, expires, nowIso(now))
    .run();
  await logEvent(env.DB, {
    appId: app.id,
    licenseId: license.id,
    type: "reset.requested",
    ip,
    createdAt: nowIso(now),
  });
  await send(env, {
    from,
    replyTo: resolveReplyTo(env),
    to: license.email,
    subject: `${app.name} device reset code`,
    text: resetCodeEmail(app.name, code),
  });
  return { ok: true };
}

export async function confirmReset(opts: {
  env: Env;
  app: AppRow;
  body: Record<string, unknown>;
  ip: string;
  now: Date;
}): Promise<Record<string, unknown>> {
  const { env, app, body, ip, now } = opts;
  const machineHash = str(body.machine_hash, 80);
  if (!machineHash || !machineHashOk(machineHash)) throw new HttpError(400, "invalid_machine");
  const hash = normalizeMachineHash(machineHash);
  const { license } = await loadLicense(env.DB, app, body.key);
  assertActive(license);
  if (!env.LICENSE_ENCRYPTION_KEY) throw new HttpError(500, "encryption_key_missing");
  await assertResetAllowed(env.DB, app, license.id, now);
  const code = str(body.code, 12);
  if (!code || !/^\d{6}$/.test(code)) throw new HttpError(400, "invalid_code");
  const row = await env.DB
    .prepare(
      `SELECT * FROM email_codes
       WHERE license_id = ? AND purpose = 'reset_machines' AND used_at IS NULL
       ORDER BY id DESC LIMIT 1`,
    )
    .bind(license.id)
    .first<{
      id: number;
      code_hash: string;
      attempts: number;
      expires_at: string;
    }>();
  if (!row) throw new HttpError(400, "invalid_code");
  const lim = limits();
  if (row.attempts >= lim.codeMaxAttempts) throw new HttpError(400, "invalid_code");
  if (Date.parse(row.expires_at) < now.getTime()) throw new HttpError(400, "invalid_code");
  const expected = await hashCode(code, license.id, env.LICENSE_ENCRYPTION_KEY);
  if (!timingSafeEqual(expected, row.code_hash)) {
    await env.DB
      .prepare(`UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?`)
      .bind(row.id)
      .run();
    throw new HttpError(400, "invalid_code");
  }
  await env.DB
    .prepare(`UPDATE email_codes SET used_at = ?, attempts = attempts + 1 WHERE id = ?`)
    .bind(nowIso(now), row.id)
    .run();

  const existing = await listActivations(env.DB, license.id);
  await env.DB.prepare(`DELETE FROM activations WHERE license_id = ?`).bind(license.id).run();
  const batch = crypto.randomUUID();
  for (const activation of existing) {
    await logEvent(env.DB, {
      appId: app.id,
      licenseId: license.id,
      type: "activation.removed",
      machineHash: activation.machine_hash,
      ip,
      detail: { reason: "reset", batch, activation_id: activation.id },
      createdAt: nowIso(now),
    });
  }
  await logEvent(env.DB, {
    appId: app.id,
    licenseId: license.id,
    type: "activation.removed",
    machineHash: null,
    ip,
    detail: { reason: "reset", batch, count: existing.length },
    createdAt: nowIso(now),
  });

  const machineName = str(body.machine_name, 128);
  const platform = str(body.platform, 64);
  const appVersion = str(body.app_version, 64);
  await env.DB
    .prepare(
      `INSERT INTO activations (license_id, machine_hash, machine_name, platform, app_version, activated_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(license.id, hash, machineName, platform, appVersion, nowIso(now), nowIso(now))
    .run();
  await logEvent(env.DB, {
    appId: app.id,
    licenseId: license.id,
    type: "activation.created",
    machineHash: hash,
    ip,
    detail: { via: "reset", machine_name: machineName, platform, app_version: appVersion },
    createdAt: nowIso(now),
  });
  const privateKey = await requireSigningKey(env, app);
  const signed = await signLicenseJwt(env, app, privateKey, license.id, hash, license.max_machines, now);
  return {
    token: signed.token,
    license_id: license.id,
    max_machines: license.max_machines,
    expires_at: signed.expiresAt,
    machine_hash: hash,
  };
}
