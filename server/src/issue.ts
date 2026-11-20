import { decryptSecret, encryptSecret, generateLicenseKey, hashLicenseKey, keyLast4 } from "./crypto";
import { getAppBySlug, logEvent } from "./db";
import type { LicenseRow, SendEmail } from "./types";
import type { Env } from "./types";
import { licenseEmail } from "./email";
import { isFullRefund, parseCheckout, stripeId } from "./stripe";
import { emailOk, nowIso, parsePositiveInt } from "./util";

async function findBySession(db: D1Database, sessionId: string): Promise<LicenseRow | null> {
  return db
    .prepare(`SELECT * FROM licenses WHERE stripe_session_id = ?`)
    .bind(sessionId)
    .first<LicenseRow>();
}

async function deliverKey(
  env: Env,
  send: SendEmail,
  db: D1Database,
  license: LicenseRow,
  appName: string,
  plaintext: string | null,
  now: Date,
): Promise<void> {
  if (license.email_sent_at) return;
  if (!env.LICENSE_ENCRYPTION_KEY) {
    throw new Error("encryption_key_missing");
  }
  const key = plaintext ?? (await decryptSecret(license.key_enc, env.LICENSE_ENCRYPTION_KEY));
  if (!env.RESEND_API_KEY) {
    console.log(
      JSON.stringify({
        event: "email_skipped",
        license_id: license.id,
        reason: "RESEND_API_KEY unset",
      }),
    );
    return;
  }
  await send(env, {
    to: license.email,
    subject: `Your ${appName} license key`,
    text: licenseEmail(appName, [key]),
  });
  await db
    .prepare(`UPDATE licenses SET email_sent_at = ? WHERE id = ?`)
    .bind(nowIso(now), license.id)
    .run();
}

export async function handleCheckoutCompleted(
  env: Env,
  send: SendEmail,
  object: Record<string, unknown>,
  ip: string,
  now: Date,
): Promise<{ status: number }> {
  const db = env.DB;
  const parsed = parseCheckout(object);
  const fail = async (reason: string, appId?: number | null) => {
    await logEvent(db, {
      appId: appId ?? null,
      type: "webhook.error",
      ip,
      detail: { reason, session_id: parsed.sessionId || null },
      createdAt: nowIso(now),
    });
    return { status: 200 };
  };

  if (!parsed.sessionId) return fail("missing_session_id");
  if (!env.LICENSE_ENCRYPTION_KEY) {
    await logEvent(db, {
      type: "webhook.error",
      ip,
      detail: { reason: "encryption_key_missing", session_id: parsed.sessionId },
      createdAt: nowIso(now),
    });
    return { status: 500 };
  }

  const existing = await findBySession(db, parsed.sessionId);
  if (existing) {
    const app = await db
      .prepare(`SELECT name FROM apps WHERE id = ?`)
      .bind(existing.app_id)
      .first<{ name: string }>();
    try {
      await deliverKey(env, send, db, existing, app?.name ?? "app", null, now);
    } catch (error) {
      console.log(JSON.stringify({ event: "email_failed", session_id: parsed.sessionId, error: String(error) }));
      return { status: 500 };
    }
    return { status: 200 };
  }

  if (!parsed.app) return fail("missing_metadata_app");
  const maxMachines = parsePositiveInt(parsed.maxMachinesRaw);
  if (!maxMachines) return fail("invalid_metadata_max_machines");
  if (!parsed.email || !emailOk(parsed.email)) return fail("missing_email");

  const app = await getAppBySlug(db, parsed.app);
  if (!app) return fail("unknown_app");
  if (app.status !== "active") return fail("app_disabled", app.id);

  const plaintext = generateLicenseKey(app.key_prefix);
  const keyHash = await hashLicenseKey(plaintext);
  const enc = await encryptSecret(plaintext, env.LICENSE_ENCRYPTION_KEY);
  let license: LicenseRow | null = null;
  try {
    const inserted = await db
      .prepare(
        `INSERT INTO licenses (
           app_id, key_hash, key_last4, key_enc, email, max_machines,
           stripe_session_id, stripe_payment_intent, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING *`,
      )
      .bind(
        app.id,
        keyHash,
        keyLast4(plaintext),
        enc,
        parsed.email,
        maxMachines,
        parsed.sessionId,
        parsed.paymentIntent,
        nowIso(now),
      )
      .all<LicenseRow>();
    license = inserted.results?.[0] ?? null;
  } catch (error) {
    const message = String(error);
    if (message.includes("UNIQUE")) {
      const raced = await findBySession(db, parsed.sessionId);
      if (raced) {
        try {
          await deliverKey(env, send, db, raced, app.name, null, now);
        } catch (sendError) {
          console.log(JSON.stringify({ event: "email_failed", error: String(sendError) }));
          return { status: 500 };
        }
        return { status: 200 };
      }
    }
    throw error;
  }
  if (!license) return fail("insert_failed", app.id);

  await logEvent(db, {
    appId: app.id,
    licenseId: license.id,
    type: "license.issued",
    ip,
    detail: {
      stripe_session_id: parsed.sessionId,
      stripe_payment_intent: parsed.paymentIntent,
      max_machines: maxMachines,
    },
    createdAt: nowIso(now),
  });

  try {
    await deliverKey(env, send, db, license, app.name, plaintext, now);
  } catch (error) {
    console.log(JSON.stringify({ event: "email_failed", license_id: license.id, error: String(error) }));
    return { status: 500 };
  }
  return { status: 200 };
}

export async function revokeByPaymentIntent(
  env: Env,
  paymentIntent: string | null,
  reason: "refund" | "dispute",
  ip: string,
  now: Date,
  detail: Record<string, unknown>,
): Promise<void> {
  const db = env.DB;
  if (!paymentIntent) {
    await logEvent(db, {
      type: "webhook.error",
      ip,
      detail: { reason: "missing_payment_intent", ...detail },
      createdAt: nowIso(now),
    });
    return;
  }
  const license = await db
    .prepare(`SELECT * FROM licenses WHERE stripe_payment_intent = ?`)
    .bind(paymentIntent)
    .first<LicenseRow>();
  if (!license) {
    await logEvent(db, {
      type: "webhook.error",
      ip,
      detail: { reason: "license_not_found", payment_intent: paymentIntent, ...detail },
      createdAt: nowIso(now),
    });
    return;
  }
  if (license.status === "revoked") return;
  const revokedAt = nowIso(now);
  await db
    .prepare(
      `UPDATE licenses SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE id = ? AND status = 'active'`,
    )
    .bind(revokedAt, reason, license.id)
    .run();
  await logEvent(db, {
    appId: license.app_id,
    licenseId: license.id,
    type: "license.revoked",
    ip,
    detail: { reason, payment_intent: paymentIntent, ...detail },
    createdAt: revokedAt,
  });
}

export async function handleChargeRefunded(
  env: Env,
  object: Record<string, unknown>,
  ip: string,
  now: Date,
): Promise<void> {
  if (!isFullRefund(object)) {
    await logEvent(env.DB, {
      type: "webhook.ignored",
      ip,
      detail: { reason: "partial_refund", charge: stripeId(object.id) ?? object.id ?? null },
      createdAt: nowIso(now),
    });
    return;
  }
  await revokeByPaymentIntent(env, stripeId(object.payment_intent), "refund", ip, now, {
    charge: stripeId(object.id),
  });
}

export async function handleDisputeCreated(
  env: Env,
  object: Record<string, unknown>,
  ip: string,
  now: Date,
): Promise<void> {
  await revokeByPaymentIntent(env, stripeId(object.payment_intent), "dispute", ip, now, {
    dispute: stripeId(object.id),
  });
}
