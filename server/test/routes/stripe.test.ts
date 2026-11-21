import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  checkoutPayload,
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
} from "../helpers/fixtures";

const M1 = machine("a");
const M2 = machine("b");

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
