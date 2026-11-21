import { env } from "cloudflare:test";
import { importSPKI, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { normalizeLicenseKey } from "../src/lib/crypto";
import { verifyStripeSignature } from "../src/lib/stripe";
import {
  emails,
  handler,
  issueKey,
  keyFromEmail,
  machine,
  num,
  postJson,
  postWebhook,
  resetDb,
  seedApp,
  stripeSignature,
  checkoutPayload,
} from "./helpers";

async function completeReset(
  app: ReturnType<typeof handler>,
  runtime: Awaited<ReturnType<typeof seedApp>>["env"],
  key: string,
  hash: string,
): Promise<void> {
  emails.length = 0;
  const requested = await postJson(app, runtime, "/api/myapp/licenses/reset/request", { key });
  expect(requested.status).toBe(200);
  const code = emails[0]?.text.match(/(\d{6})/)?.[1];
  expect(code).toBeTruthy();
  const confirmed = await postJson(app, runtime, "/api/myapp/licenses/reset/confirm", {
    key,
    code,
    machine_hash: hash,
    machine_name: "Current",
  });
  expect(confirmed.status).toBe(200);
  expect(typeof confirmed.body.token).toBe("string");
}

async function expectVerifyFails(pending: Promise<unknown>): Promise<void> {
  try {
    await pending;
  } catch {
    return;
  }
  throw new Error("expected JWT verification to fail");
}

const M1 = machine("a");
const M2 = machine("b");
const M3 = machine("c");
const M4 = machine("d");

beforeEach(async () => {
  await resetDb();
});

describe("stripe webhook", () => {
  it("emails a key after checkout and activates it", async () => {
    const seeded = await seedApp();
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_pay", maxMachines: "2" });
    expect(key.startsWith("MYAPP-")).toBe(true);
    expect(emails[0]?.to).toBe("buyer@example.com");
    expect(emails[0]?.from).toBe("My App <noreply@example.com>");
    expect(emails[0]?.replyTo).toBe("support@example.com");
    expect(emails[0]?.subject).toContain("My App");
    const activated = await postJson(app, seeded.env, "/api/myapp/licenses/activate", {
      key,
      machine_hash: M1,
      machine_name: "Desk",
      platform: "darwin",
      app_version: "1.2.3",
    });
    expect(activated.status).toBe(200);
    expect(typeof activated.body.token).toBe("string");
    const issued = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'license.issued'`).first<{ c: number }>();
    const created = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'activation.created'`).first<{ c: number }>();
    expect(num(issued?.c)).toBe(1);
    expect(num(created?.c)).toBe(1);
  });

  it("issues once when the same webhook is delivered twice, including a zero-amount session", async () => {
    const seeded = await seedApp();
    const app = handler();
    const payload = checkoutPayload({ sessionId: "cs_once", paymentIntent: "pi_once", metadata: { app: "myapp", max_machines: "1" } });
    expect((await postWebhook(app, seeded.env, payload)).status).toBe(200);
    expect((await postWebhook(app, seeded.env, payload)).status).toBe(200);
    const count = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses`).first<{ c: number }>();
    expect(num(count?.c)).toBe(1);
    expect(emails).toHaveLength(1);

    emails.length = 0;
    const zero = checkoutPayload({
      sessionId: "cs_zero",
      paymentIntent: null,
      amount: 0,
      metadata: { app: "myapp", max_machines: "1" },
    });
    expect((await postWebhook(app, seeded.env, zero)).status).toBe(200);
    const row = await env.DB.prepare(`SELECT stripe_payment_intent AS pi FROM licenses WHERE stripe_session_id = 'cs_zero'`).first<{ pi: string | null }>();
    expect(row?.pi).toBeNull();
    expect(emails).toHaveLength(1);
    const key = keyFromEmail(emails[0].text);
    const activated = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M1 });
    expect(activated.status).toBe(200);
  });

  it("uses a per-app sender and still issues a key when no sender is configured", async () => {
    const seeded = await seedApp(env, { mailFrom: "Desk <desk@example.com>" });
    const app = handler();
    await issueKey(app, seeded, { sessionId: "cs_from", maxMachines: "1" });
    expect(emails.at(-1)?.from).toBe("Desk <desk@example.com>");

    emails.length = 0;
    const unset = await seedApp(env, { slug: "plain", prefix: "PLAIN", name: "Plain", extra: { MAIL_FROM: "" } });
    const payload = checkoutPayload({
      sessionId: "cs_nofrom",
      metadata: { app: "plain", max_machines: "1" },
    });
    expect((await postWebhook(app, unset.env, payload)).status).toBe(200);
    const count = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses WHERE stripe_session_id = 'cs_nofrom'`).first<{ c: number }>();
    expect(num(count?.c)).toBe(1);
    expect(emails).toHaveLength(0);
    const failed = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'email.failed'`).first<{ c: number }>();
    expect(num(failed?.c)).toBe(1);
  });

  it("does not issue a key when metadata or email is missing, and rejects bad signatures", async () => {
    const seeded = await seedApp();
    const app = handler();
    const missing = checkoutPayload({ sessionId: "cs_missing", metadata: null });
    expect((await postWebhook(app, seeded.env, missing)).status).toBe(200);
    const badMax = checkoutPayload({
      sessionId: "cs_bad_max",
      metadata: { app: "myapp", max_machines: "0" },
    });
    expect((await postWebhook(app, seeded.env, badMax)).status).toBe(200);
    const noEmail = checkoutPayload({ sessionId: "cs_no_email", email: null });
    expect((await postWebhook(app, seeded.env, noEmail)).status).toBe(200);
    const licenses = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses`).first<{ c: number }>();
    expect(num(licenses?.c)).toBe(0);
    const errors = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'webhook.error'`).first<{ c: number }>();
    expect(num(errors?.c)).toBeGreaterThanOrEqual(3);

    const payload = checkoutPayload({ sessionId: "cs_bad_sig" });
    const res = await app.request(
      "/api/stripe/webhook",
      {
        method: "POST",
        headers: { "Stripe-Signature": "t=1,v1=deadbeef" },
        body: payload,
      },
      seeded.env,
    );
    expect(res.status).toBe(400);
    const stale = await stripeSignature(payload, "whsec_test_secret", Math.floor(Date.now() / 1000) - 1000);
    const staleRes = await app.request(
      "/api/stripe/webhook",
      { method: "POST", headers: { "Stripe-Signature": stale }, body: payload },
      seeded.env,
    );
    expect(staleRes.status).toBe(400);
  });

  it("revokes on a full refund or dispute and refuses to renew", async () => {
    const seeded = await seedApp();
    const app = handler();
    const refundKey = await issueKey(app, seeded, { sessionId: "cs_refund", paymentIntent: "pi_refund" });
    const disputeKey = await issueKey(app, seeded, { sessionId: "cs_dispute", paymentIntent: "pi_dispute", email: "other@example.com" });
    const partialKey = await issueKey(app, seeded, { sessionId: "cs_partial", paymentIntent: "pi_partial", email: "partial@example.com" });

    const refund = JSON.stringify({
      type: "charge.refunded",
      data: { object: { id: "ch_refund", object: "charge", amount: 2000, amount_refunded: 2000, refunded: true, payment_intent: "pi_refund" } },
    });
    expect((await postWebhook(app, seeded.env, refund)).status).toBe(200);
    const partial = JSON.stringify({
      type: "charge.refunded",
      data: { object: { id: "ch_partial", object: "charge", amount: 2000, amount_refunded: 500, refunded: false, payment_intent: "pi_partial" } },
    });
    expect((await postWebhook(app, seeded.env, partial)).status).toBe(200);
    const dispute = JSON.stringify({
      type: "charge.dispute.created",
      data: { object: { id: "dp_1", object: "dispute", charge: "ch_dispute", payment_intent: "pi_dispute" } },
    });
    expect((await postWebhook(app, seeded.env, dispute)).status).toBe(200);

    const refunded = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key: refundKey, machine_hash: M1 });
    expect(refunded.status).toBe(403);
    expect(refunded.body.error).toBe("revoked");
    expect(refunded.body.token).toBeUndefined();
    const disputed = await postJson(app, seeded.env, "/api/myapp/licenses/validate", { key: disputeKey, machine_hash: M1 });
    expect(disputed.body.error).toBe("revoked");
    expect(disputed.body.token).toBeUndefined();
    const stillActive = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key: partialKey, machine_hash: M2 });
    expect(stillActive.status).toBe(200);

    const reasons = await env.DB.prepare(`SELECT revoke_reason AS reason FROM licenses WHERE status = 'revoked' ORDER BY revoke_reason`).all<{ reason: string }>();
    expect((reasons.results ?? []).map((row) => row.reason).sort()).toEqual(["dispute", "refund"]);
    const revokedEvents = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'license.revoked'`).first<{ c: number }>();
    expect(num(revokedEvents?.c)).toBe(2);
  });
});

describe("activation limits", () => {
  it("rejects a full license, frees a slot on deactivate, and treats the same machine as idempotent", async () => {
    const seeded = await seedApp();
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_limit", maxMachines: "2" });
    const first = await postJson(app, seeded.env, "/api/myapp/licenses/activate", {
      key,
      machine_hash: M1,
      machine_name: "One",
      platform: "darwin",
    });
    const second = await postJson(app, seeded.env, "/api/myapp/licenses/activate", {
      key,
      machine_hash: M2,
      machine_name: "Two",
      platform: "win32",
    });
    const again = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M1, machine_name: "One" });
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(again.status).toBe(200);
    const rows = await env.DB.prepare(`SELECT COUNT(*) AS c FROM activations`).first<{ c: number }>();
    expect(num(rows?.c)).toBe(2);

    const blocked = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M3, machine_name: "Three" });
    expect(blocked.status).toBe(409);
    expect(blocked.body.error).toBe("machine_limit_reached");
    const machines = blocked.body.machines as { machine_name: string }[];
    expect(machines.map((item) => item.machine_name).sort()).toEqual(["One", "Two"]);

    const removed = await postJson(app, seeded.env, "/api/myapp/licenses/deactivate", { key, machine_hash: M2 });
    expect(removed.body.ok).toBe(true);
    const freed = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M3, machine_name: "Three" });
    expect(freed.status).toBe(200);
    const removedEvents = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'activation.removed'`).first<{ c: number }>();
    expect(num(removedEvents?.c)).toBe(1);
  });

  it("does not count a machine that has been offline longer than inactive_release_days, and keeps the row", async () => {
    const seeded = await seedApp(env, { inactiveReleaseDays: 90 });
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_stale", maxMachines: "1" });
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M1, machine_name: "Old" })).status).toBe(200);
    const stale = new Date(Date.now() - 91 * 86_400_000).toISOString();
    await env.DB.prepare(`UPDATE activations SET last_seen_at = ? WHERE machine_hash = ?`).bind(stale, M1).run();
    const fresh = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M2, machine_name: "New" });
    expect(fresh.status).toBe(200);
    const rows = await env.DB.prepare(`SELECT machine_hash FROM activations ORDER BY machine_hash`).all<{ machine_hash: string }>();
    expect((rows.results ?? []).map((row) => row.machine_hash)).toEqual([M1, M2].sort());
  });

  it("rejects a key from another app", async () => {
    const first = await seedApp(env, { slug: "myapp", prefix: "MYAPP" });
    const second = await seedApp(first.env, { slug: "other", prefix: "APP", name: "Other" });
    const runtime = second.env;
    const app = handler();
    const key = await issueKey(app, { ...first, env: runtime }, { sessionId: "cs_cross", maxMachines: "1" });
    const wrong = await postJson(app, runtime, "/api/other/licenses/activate", { key, machine_hash: M1 });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toBe("invalid_key");
    const right = await postJson(app, runtime, "/api/myapp/licenses/activate", { key, machine_hash: M1 });
    expect(right.status).toBe(200);
  });

  it("rate limits activate by IP and by key", async () => {
    const seeded = await seedApp(env, {
      extra: { RATE_LIMIT_ACTIVATE_IP_PER_MIN: "2", RATE_LIMIT_ACTIVATE_KEY_PER_MIN: "100" },
    });
    const app = handler();
    const body = { key: "MYAPP-00000-00000-00000-00000", machine_hash: M1 };
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/activate", body, "198.51.100.8")).status).toBe(400);
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/activate", body, "198.51.100.8")).status).toBe(400);
    const blocked = await postJson(app, seeded.env, "/api/myapp/licenses/activate", body, "198.51.100.8");
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe("rate_limited");

    const byKey = await seedApp(env, {
      slug: "other",
      prefix: "APP",
      extra: { RATE_LIMIT_ACTIVATE_IP_PER_MIN: "100", RATE_LIMIT_ACTIVATE_KEY_PER_MIN: "2" },
    });
    const attempt = { key: "APP-00000-00000-00000-00000", machine_hash: M1 };
    expect((await postJson(app, byKey.env, "/api/other/licenses/activate", attempt, "198.51.100.9")).status).toBe(400);
    expect((await postJson(app, byKey.env, "/api/other/licenses/activate", attempt, "198.51.100.9")).status).toBe(400);
    expect((await postJson(app, byKey.env, "/api/other/licenses/activate", attempt, "198.51.100.9")).status).toBe(429);
  });
});

describe("offline token", () => {
  it("signs an EdDSA token that fails when tampered, retargeted, or expired", async () => {
    const seeded = await seedApp(env, { offlineGraceDays: 30 });
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_jwt", maxMachines: "2" });
    const activated = await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M1 });
    const token = String(activated.body.token);
    const publicKey = await importSPKI(seeded.publicKey, "EdDSA");
    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      audience: "myapp",
      issuer: "https://license.example.com",
      algorithms: ["EdDSA"],
    });
    expect(protectedHeader.alg).toBe("EdDSA");
    expect(payload.sub).toBe(String(activated.body.license_id));
    expect(payload.mid).toBe(M1);
    expect(payload.mid).not.toBe(M2);
    expect(payload.max).toBe(2);
    expect(payload).not.toHaveProperty("email");
    expect(Number(payload.exp) - Number(payload.iat)).toBe(30 * 86_400);

    const tampered = `${token.slice(0, -4)}aaaa`;
    await expectVerifyFails(jwtVerify(tampered, publicKey, { algorithms: ["EdDSA"] }));
    await expectVerifyFails(jwtVerify(token, publicKey, { audience: "other", algorithms: ["EdDSA"] }));
    await expectVerifyFails(
      jwtVerify(token, publicKey, {
        algorithms: ["EdDSA"],
        currentDate: new Date(Date.now() + 31 * 86_400_000),
      }),
    );

    const validated = await postJson(app, seeded.env, "/api/myapp/licenses/validate", { key, machine_hash: M1 });
    expect(validated.status).toBe(200);
    expect(typeof validated.body.token).toBe("string");
    const missing = await postJson(app, seeded.env, "/api/myapp/licenses/validate", { key, machine_hash: M2 });
    expect(missing.body.error).toBe("not_activated");
  });
});

describe("trials", () => {
  it("does not reset on reinstall or a later local clock, and keeps apps independent", async () => {
    const myapp = await seedApp(env, { slug: "myapp", prefix: "MYAPP", trialDays: 30 });
    const other = await seedApp(myapp.env, { slug: "other", prefix: "APP", name: "Other", trialDays: 14 });
    const app = handler();
    const first = await postJson(app, other.env, "/api/myapp/licenses/trial", {
      machine_hash: M1,
      local_started_at: new Date().toISOString(),
      platform: "linux",
      app_version: "1.0.0",
    });
    expect(first.status).toBe(200);
    const later = await postJson(app, other.env, "/api/myapp/licenses/trial", {
      machine_hash: M1,
      local_started_at: new Date(Date.now() + 3 * 86_400_000).toISOString(),
    });
    expect(later.body.started_at).toBe(first.body.started_at);
    expect(later.body.expires_at).toBe(first.body.expires_at);

    const earlierIso = new Date(Date.parse(String(first.body.started_at)) - 5 * 86_400_000).toISOString();
    const earlier = await postJson(app, other.env, "/api/myapp/licenses/trial", {
      machine_hash: M1,
      local_started_at: earlierIso,
    });
    expect(earlier.body.started_at).toBe(earlierIso);
    expect(Date.parse(String(earlier.body.expires_at)) - Date.parse(earlierIso)).toBe(30 * 86_400_000);

    const future = await postJson(app, other.env, "/api/myapp/licenses/trial", {
      machine_hash: M2,
      local_started_at: new Date(Date.now() + 10 * 86_400_000).toISOString(),
    });
    expect(Date.parse(String(future.body.started_at))).toBeLessThanOrEqual(Date.now() + 5_000);

    const otherApp = await postJson(app, other.env, "/api/other/licenses/trial", { machine_hash: M1 });
    expect(otherApp.status).toBe(200);
    expect(otherApp.body.trial_days).toBe(14);
    const rows = await env.DB.prepare(`SELECT COUNT(*) AS c FROM trials`).first<{ c: number }>();
    expect(num(rows?.c)).toBe(3);
    const events = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'trial.started'`).first<{ c: number }>();
    expect(num(events?.c)).toBe(3);

    const publicKey = await importSPKI(myapp.publicKey, "EdDSA");
    const { payload } = await jwtVerify(String(earlier.body.token), publicKey, {
      audience: "myapp",
      algorithms: ["EdDSA"],
    });
    expect(payload.kind).toBe("trial");
    expect(payload.mid).toBe(M1);
    expect(payload.sub).toMatch(/^trial:/);
    expect(Number(payload.exp)).toBe(Math.floor(Date.parse(String(earlier.body.expires_at)) / 1000));
  });
});

describe("recovery and reset", () => {
  it("sends every active key for an email and the same response when none exist", async () => {
    const seeded = await seedApp();
    const app = handler();
    const first = await issueKey(app, seeded, { sessionId: "cs_r1", email: "owner@example.com", maxMachines: "1" });
    const second = await issueKey(app, seeded, { sessionId: "cs_r2", email: "owner@example.com", maxMachines: "1" });
    emails.length = 0;
    const found = await postJson(app, seeded.env, "/api/myapp/licenses/recover", { email: "owner@example.com" });
    const missing = await postJson(app, seeded.env, "/api/myapp/licenses/recover", { email: "nobody@example.com" });
    expect(found.status).toBe(200);
    expect(missing.status).toBe(200);
    expect(missing.body).toEqual(found.body);
    expect(emails).toHaveLength(1);
    expect(emails[0].to).toBe("owner@example.com");
    expect(emails[0].text).toContain(first);
    expect(emails[0].text).toContain(second);
    const logged = await env.DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE type = 'license.recovered'`).first<{ c: number }>();
    expect(num(logged?.c)).toBe(2);
  });

  it("resets every device with an emailed code, activates the current one, and stops at a custom per-app limit", async () => {
    const seeded = await seedApp(env, { resetLimit: 3, resetWindowDays: 30 });
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_reset", email: "owner@example.com", maxMachines: "1" });
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M1, machine_name: "Old" })).status).toBe(200);
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/activate", { key, machine_hash: M2 })).status).toBe(409);

    for (let i = 0; i < 3; i++) {
      emails.length = 0;
      const requested = await postJson(app, seeded.env, "/api/myapp/licenses/reset/request", { key });
      expect(requested.status).toBe(200);
      const code = emails[0]?.text.match(/(\d{6})/)?.[1];
      expect(code).toBeTruthy();
      const hash = i % 2 === 0 ? M3 : M4;
      const confirmed = await postJson(app, seeded.env, "/api/myapp/licenses/reset/confirm", {
        key,
        code,
        machine_hash: hash,
        machine_name: "Current",
        platform: "linux",
        app_version: "3.0.0",
      });
      expect(confirmed.status).toBe(200);
      expect(typeof confirmed.body.token).toBe("string");
      const left = await env.DB.prepare(`SELECT machine_hash FROM activations`).all<{ machine_hash: string }>();
      expect(left.results).toEqual([{ machine_hash: hash }]);
    }

    const blocked = await postJson(app, seeded.env, "/api/myapp/licenses/reset/request", { key });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe("reset_limit_reached");
    const resets = await env.DB
      .prepare(
        `SELECT COUNT(*) AS c FROM events WHERE type = 'activation.removed' AND machine_hash IS NULL AND detail LIKE '%"reason":"reset"%'`,
      )
      .first<{ c: number }>();
    expect(num(resets?.c)).toBe(3);
  });

  it("allows the default of 5 resets in 30 days and rejects the sixth", async () => {
    const seeded = await seedApp(env, { extra: { RATE_LIMIT_RESET_IP_PER_MIN: "100" } });
    const stored = await env.DB.prepare(`SELECT reset_limit, reset_window_days FROM apps WHERE slug = 'myapp'`).first<{
      reset_limit: number;
      reset_window_days: number;
    }>();
    expect(stored).toEqual({ reset_limit: 5, reset_window_days: 30 });
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_reset5", email: "owner@example.com", maxMachines: "1" });
    for (let i = 0; i < 5; i++) {
      await completeReset(app, seeded.env, key, i % 2 === 0 ? M1 : M2);
    }
    const blocked = await postJson(app, seeded.env, "/api/myapp/licenses/reset/request", { key });
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe("reset_limit_reached");
  });

  it("treats reset_limit 0 as unlimited", async () => {
    const seeded = await seedApp(env, { resetLimit: 0, extra: { RATE_LIMIT_RESET_IP_PER_MIN: "100" } });
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_reset0", email: "owner@example.com", maxMachines: "1" });
    for (let i = 0; i < 6; i++) {
      await completeReset(app, seeded.env, key, i % 2 === 0 ? M1 : M2);
    }
    const resets = await env.DB
      .prepare(
        `SELECT COUNT(*) AS c FROM events WHERE type = 'activation.removed' AND machine_hash IS NULL AND detail LIKE '%"reason":"reset"%'`,
      )
      .first<{ c: number }>();
    expect(num(resets?.c)).toBe(6);
  });

  it("burns a reset code after 5 wrong attempts", async () => {
    const seeded = await seedApp();
    const app = handler();
    const key = await issueKey(app, seeded, { sessionId: "cs_code", email: "owner@example.com" });
    emails.length = 0;
    expect((await postJson(app, seeded.env, "/api/myapp/licenses/reset/request", { key })).status).toBe(200);
    const code = emails[0]?.text.match(/(\d{6})/)?.[1] ?? "";
    for (let i = 0; i < 5; i++) {
      const wrong = await postJson(app, seeded.env, "/api/myapp/licenses/reset/confirm", {
        key,
        code: "000000",
        machine_hash: M1,
      });
      expect(wrong.body.error).toBe("invalid_code");
    }
    const burned = await postJson(app, seeded.env, "/api/myapp/licenses/reset/confirm", {
      key,
      code,
      machine_hash: M1,
    });
    expect(burned.body.error).toBe("invalid_code");
  });
});

describe("admin", () => {
  it("requires the admin token and can register an app without storing the private key", async () => {
    const app = handler();
    const denied = await app.request("/api/admin/apps", { headers: { Authorization: "Bearer wrong" } }, env);
    expect(denied.status).toBe(401);
    const created = await app.request(
      "/api/admin/apps",
      {
        method: "POST",
        headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
        body: JSON.stringify({ slug: "myapp", name: "My App", key_prefix: "MYAPP", trial_days: 14 }),
      },
      env,
    );
    expect(created.status).toBe(201);
    const body = (await created.json()) as {
      private_key: string;
      instructions: string;
      app: { public_key: string; reset_limit: number; reset_window_days: number; mail_from: string | null };
    };
    expect(body.private_key).toContain("BEGIN PRIVATE KEY");
    expect(body.instructions).toContain("APP_KEY_MYAPP");
    const stored = await env.DB.prepare(`SELECT public_key, trial_days FROM apps WHERE slug = 'myapp'`).first<{
      public_key: string;
      trial_days: number;
    }>();
    expect(stored?.public_key).toBe(body.app.public_key);
    expect(stored?.public_key).not.toContain("PRIVATE KEY");
    expect(stored?.trial_days).toBe(14);
    expect(body.app.reset_limit).toBe(5);
    expect(body.app.reset_window_days).toBe(30);
    expect(body.app.mail_from).toBeNull();
    await env.DB.prepare(
      `INSERT INTO apps (slug, name, key_prefix, public_key) VALUES ('plain', 'Plain', 'PLAIN', 'pk')`,
    ).run();
    const sqlDefault = await env.DB.prepare(
      `SELECT reset_limit, reset_window_days FROM apps WHERE slug = 'plain'`,
    ).first<{ reset_limit: number; reset_window_days: number }>();
    expect(sqlDefault).toEqual({ reset_limit: 5, reset_window_days: 30 });

    const patched = await app.request(
      "/api/admin/apps/myapp",
      {
        method: "PATCH",
        headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
        body: JSON.stringify({ reset_limit: 0, reset_window_days: 14 }),
      },
      env,
    );
    expect(patched.status).toBe(200);
    const patchedBody = (await patched.json()) as { app: { reset_limit: number; reset_window_days: number } };
    expect(patchedBody.app.reset_limit).toBe(0);
    expect(patchedBody.app.reset_window_days).toBe(14);

    const invalid = await app.request(
      "/api/admin/apps/myapp",
      {
        method: "PATCH",
        headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
        body: JSON.stringify({ reset_limit: -1 }),
      },
      env,
    );
    expect(invalid.status).toBe(400);
    const sender = await app.request(
      "/api/admin/apps/myapp",
      {
        method: "PATCH",
        headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
        body: JSON.stringify({ mail_from: "Desk <desk@example.com>" }),
      },
      env,
    );
    expect(sender.status).toBe(200);
    const senderBody = (await sender.json()) as { app: { mail_from: string | null } };
    expect(senderBody.app.mail_from).toBe("Desk <desk@example.com>");
    const badSender = await app.request(
      "/api/admin/apps/myapp",
      {
        method: "PATCH",
        headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
        body: JSON.stringify({ mail_from: "not-an-email" }),
      },
      env,
    );
    expect(badSender.status).toBe(400);
  });

  it("returns stats and license usage that match the database", async () => {
    await env.DB.prepare(
      `INSERT INTO apps (slug, name, key_prefix, public_key, inactive_release_days) VALUES
       ('myapp', 'My App', 'MYAPP', 'pk-myapp', 90),
       ('other', 'Other', 'APP', 'pk-other', 90)`,
    ).run();
    const myapp = await env.DB.prepare(`SELECT id FROM apps WHERE slug = 'myapp'`).first<{ id: number }>();
    const other = await env.DB.prepare(`SELECT id FROM apps WHERE slug = 'other'`).first<{ id: number }>();
    const now = new Date();
    const daysAgo = (days: number) => new Date(now.getTime() - days * 86_400_000).toISOString();
    const insertLicense = async (
      appId: number,
      hash: string,
      email: string,
      max: number,
      session: string,
      status: "active" | "revoked",
    ) => {
      const inserted = await env.DB.prepare(
        `INSERT INTO licenses (app_id, key_hash, key_last4, key_enc, email, max_machines, stripe_session_id, status, revoked_at, revoke_reason, created_at)
         VALUES (?, ?, ?, 'enc', ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
      )
        .bind(
          appId,
          hash,
          hash.slice(-4).toUpperCase(),
          email,
          max,
          session,
          status,
          status === "revoked" ? daysAgo(1) : null,
          status === "revoked" ? "admin" : null,
          daysAgo(2),
        )
        .all<{ id: number }>();
      const row = inserted.results?.[0];
      if (!row) throw new Error("license insert failed");
      return row.id;
    };
    const l1 = await insertLicense(myapp!.id, "h1", "a@example.com", 2, "cs1", "active");
    const l2 = await insertLicense(myapp!.id, "h2", "b@example.com", 2, "cs2", "active");
    const l3 = await insertLicense(myapp!.id, "h3", "c@example.com", 5, "cs3", "revoked");
    await insertLicense(other!.id, "h4", "d@example.com", 1, "cs4", "active");
    await env.DB.prepare(
      `INSERT INTO activations (license_id, machine_hash, platform, app_version, last_seen_at) VALUES
       (?, ?, 'darwin', '1.0.0', ?),
       (?, ?, 'win32', '1.0.0', ?),
       (?, ?, 'linux', '2.0.0', ?)`,
    )
      .bind(l1, M1, now.toISOString(), l1, M2, daysAgo(100), l3, M3, daysAgo(10))
      .run();
    await env.DB.prepare(
      `INSERT INTO trials (app_id, machine_hash, started_at, expires_at) VALUES (?, ?, ?, ?), (?, ?, ?, ?)`,
    )
      .bind(myapp!.id, M1, daysAgo(40), daysAgo(10), myapp!.id, M4, now.toISOString(), daysAgo(-30))
      .run();
    await env.DB.prepare(
      `INSERT INTO events (app_id, type, created_at) VALUES
       (?, 'trial.started', ?),
       (?, 'trial.started', ?),
       (?, 'activation.created', ?),
       (?, 'activation.created', ?),
       (?, 'activation.created', ?),
       (?, 'license.issued', ?),
       (?, 'license.issued', ?)`,
    )
      .bind(
        myapp!.id,
        daysAgo(40),
        myapp!.id,
        now.toISOString(),
        myapp!.id,
        now.toISOString(),
        myapp!.id,
        now.toISOString(),
        myapp!.id,
        now.toISOString(),
        myapp!.id,
        now.toISOString(),
        myapp!.id,
        now.toISOString(),
      )
      .run();

    const app = handler();
    const res = await app.request("/api/myapp/admin/stats", { headers: { Authorization: "Bearer test-admin-token" } }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      apps: {
        licenses: { total: number; active: number; revoked: number; by_max_machines: { max_machines: number; count: number }[] };
        activated_licenses: number;
        activated_users: number;
        machines: {
          total: number;
          active_7d: number;
          active_30d: number;
          by_platform: { platform: string; count: number }[];
          by_app_version: { app_version: string; count: number }[];
        };
        trials: { total: number; running: number; expired: number; converted: number };
        trend: { trial_started: number; activation_created: number; license_issued: number }[];
      }[];
    };
    const stats = body.apps[0];
    const licenseCount = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses WHERE app_id = ?`).bind(myapp!.id).first<{ c: number }>();
    const activeCount = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses WHERE app_id = ? AND status = 'active'`).bind(myapp!.id).first<{ c: number }>();
    const machineCount = await env.DB
      .prepare(`SELECT COUNT(*) AS c FROM activations JOIN licenses ON licenses.id = activations.license_id WHERE licenses.app_id = ?`)
      .bind(myapp!.id)
      .first<{ c: number }>();
    const trialCount = await env.DB.prepare(`SELECT COUNT(*) AS c FROM trials WHERE app_id = ?`).bind(myapp!.id).first<{ c: number }>();
    expect(stats.licenses.total).toBe(num(licenseCount?.c));
    expect(stats.licenses.active).toBe(num(activeCount?.c));
    expect(stats.machines.total).toBe(num(machineCount?.c));
    expect(stats.trials.total).toBe(num(trialCount?.c));
    expect(stats.licenses).toMatchObject({ total: 3, active: 2, revoked: 1 });
    expect(stats.licenses.by_max_machines).toEqual([
      { max_machines: 2, count: 2 },
      { max_machines: 5, count: 1 },
    ]);
    expect(stats.activated_licenses).toBe(2);
    expect(stats.activated_users).toBe(2);
    expect(stats.machines.total).toBe(3);
    expect(stats.machines.active_7d).toBe(1);
    expect(stats.machines.active_30d).toBe(2);
    expect(stats.machines.by_platform).toEqual([
      { platform: "darwin", count: 1 },
      { platform: "linux", count: 1 },
      { platform: "win32", count: 1 },
    ]);
    expect(stats.machines.by_app_version).toEqual([
      { app_version: "1.0.0", count: 2 },
      { app_version: "2.0.0", count: 1 },
    ]);
    expect(stats.trials).toMatchObject({ total: 2, running: 1, expired: 1, converted: 1 });
    expect(stats.trend.reduce((sum, point) => sum + point.trial_started, 0)).toBe(1);
    expect(stats.trend.reduce((sum, point) => sum + point.activation_created, 0)).toBe(3);
    expect(stats.trend.reduce((sum, point) => sum + point.license_issued, 0)).toBe(2);
    expect(l2).toBeGreaterThan(0);

    const otherStats = await app.request("/api/other/admin/stats", { headers: { Authorization: "Bearer test-admin-token" } }, env);
    const otherBody = (await otherStats.json()) as { apps: { app: string }[] };
    expect(otherBody.apps.map((item) => item.app)).toEqual(["other"]);

    const list = await app.request("/api/myapp/admin/licenses?q=a@example.com", {
      headers: { Authorization: "Bearer test-admin-token" },
    }, env);
    const listed = (await list.json()) as { total: number; items: { email: string; used_machines: number; total_machines: number; max_machines: number }[] };
    expect(listed.total).toBe(1);
    expect(listed.items[0]).toMatchObject({ email: "a@example.com", used_machines: 1, total_machines: 2, max_machines: 2 });
  });
});

describe("route prefixes", () => {
  it("returns 404 for the retired paths", async () => {
    const app = handler();
    expect((await app.request("/admin/apps", { headers: { Authorization: "Bearer test-admin-token" } }, env)).status).toBe(404);
    expect((await app.request("/health", {}, env)).status).toBe(404);
    expect((await app.request("/api/health", {}, env)).status).toBe(200);
  });
});

describe("admin auth", () => {
  it("returns 401 for every admin route without a token and with a wrong token", async () => {
    const app = handler();
    const routes: { method: string; path: string }[] = [
      { method: "POST", path: "/api/admin/apps" },
      { method: "GET", path: "/api/admin/apps" },
      { method: "PATCH", path: "/api/admin/apps/myapp" },
      { method: "GET", path: "/api/myapp/admin/stats" },
      { method: "GET", path: "/api/myapp/admin/licenses" },
      { method: "POST", path: "/api/myapp/admin/licenses/1/revoke" },
      { method: "GET", path: "/api/myapp/admin/activations" },
      { method: "DELETE", path: "/api/myapp/admin/activations/1" },
    ];
    for (const route of routes) {
      const missing = await app.request(route.path, { method: route.method }, env);
      const wrong = await app.request(
        route.path,
        { method: route.method, headers: { Authorization: "Bearer wrong" } },
        env,
      );
      expect(missing.status, route.path).toBe(401);
      expect(wrong.status, route.path).toBe(401);
    }
  });
});

describe("key normalization and stripe signatures", () => {
  it("normalizes case, spaces, and Crockford ambiguous characters", () => {
    expect(normalizeLicenseKey(" myapp-00oi1-lllll-ooooo-11111 ")).toBe("MYAPP-00011-11111-00000-11111");
    expect(normalizeLicenseKey("MYAPP-0000U-00000-00000-00000")).toBeNull();
  });

  it("accepts a current stripe signature and rejects a wrong secret", async () => {
    const payload = "{\"ok\":true}";
    const header = await stripeSignature(payload, "whsec_test_secret");
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret")).toBe(true);
    expect(await verifyStripeSignature(payload, header, "whsec_other")).toBe(false);
  });
});
