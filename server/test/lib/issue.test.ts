import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handleChargeRefunded, handleCheckoutCompleted, handleDisputeCreated } from "../../src/lib/issue";
import type { Env } from "../../src/lib/types";
import { extendEnv } from "../../src/lib/util";
import { resetDb, seedApp } from "../helpers/fixtures";

const NOW = new Date("2026-06-01T00:00:00.000Z");

beforeEach(async () => {
  await resetDb();
});

describe("issuance and revocation", () => {
  it("covers webhook edge cases", async () => {
    const seeded = await seedApp();
    const sent: string[] = [];
    const send = async (_env: Env, message: { text: string }) => {
      sent.push(message.text);
    };
    expect((await handleCheckoutCompleted(seeded.env, send, {}, "1.1.1.1", NOW)).status).toBe(200);
    expect((await handleCheckoutCompleted({ ...seeded.env, LICENSE_ENCRYPTION_KEY: "" }, send, { id: "cs_x" }, "1.1.1.1", NOW)).status).toBe(500);
    const disabled = await seedApp(env, { slug: "off", prefix: "OFF", name: "Off" });
    await env.DB.prepare(`UPDATE apps SET status = 'disabled' WHERE slug = 'off'`).run();
    expect((await handleCheckoutCompleted(disabled.env, send, {
      id: "cs_off",
      customer_details: { email: "a@b.co" },
      metadata: { app: "off", max_machines: "1" },
      payment_intent: { id: "pi_off" },
    }, "1.1.1.1", NOW)).status).toBe(200);
    const first = await handleCheckoutCompleted(seeded.env, send, {
      id: "cs_ok",
      customer_details: { email: "Buyer@Example.com" },
      metadata: { app: "myapp", max_machines: "1" },
      payment_intent: "pi_ok",
    }, "1.1.1.1", NOW);
    expect(first.status).toBe(200);
    expect(sent).toHaveLength(1);
    expect((await handleCheckoutCompleted(seeded.env, send, { id: "cs_ok" }, "1.1.1.1", NOW)).status).toBe(200);
    expect(sent).toHaveLength(1);
    const noResend = extendEnv(seeded.env, { RESEND_API_KEY: "" });
    expect((await handleCheckoutCompleted(noResend, send, {
      id: "cs_skip",
      customer_email: "c@d.co",
      metadata: { app: "myapp", max_machines: "1" },
    }, "1.1.1.1", NOW)).status).toBe(200);
    const badReply = extendEnv(seeded.env, { MAIL_REPLY_TO: "not-an-email" });
    expect((await handleCheckoutCompleted(badReply, send, {
      id: "cs_reply",
      customer_details: { email: "e@f.co" },
      metadata: { app: "myapp", max_machines: "1" },
    }, "1.1.1.1", NOW)).status).toBe(200);
    const failing = async () => {
      throw new Error("smtp down");
    };
    expect((await handleCheckoutCompleted(seeded.env, failing, {
      id: "cs_fail",
      customer_details: { email: "g@h.co" },
      metadata: { app: "myapp", max_machines: "1" },
      payment_intent: "pi_fail",
    }, "1.1.1.1", NOW)).status).toBe(500);
    expect((await handleCheckoutCompleted(seeded.env, failing, { id: "cs_fail" }, "1.1.1.1", NOW)).status).toBe(500);
    await handleChargeRefunded(seeded.env, { id: "ch_part", amount: 10, amount_refunded: 1, payment_intent: "pi_ok" }, "1.1.1.1", NOW);
    await handleChargeRefunded(seeded.env, { id: { id: "ch_full" }, refunded: true, payment_intent: "pi_missing" }, "1.1.1.1", NOW);
    await handleChargeRefunded(seeded.env, { refunded: true }, "1.1.1.1", NOW);
    await handleChargeRefunded(seeded.env, { id: "ch_ok", refunded: true, payment_intent: "pi_ok" }, "1.1.1.1", NOW);
    await handleChargeRefunded(seeded.env, { id: "ch_ok", refunded: true, payment_intent: "pi_ok" }, "1.1.1.1", NOW);
    await handleDisputeCreated(seeded.env, { id: "dp_1", payment_intent: "pi_fail" }, "1.1.1.1", NOW);
    const status = await env.DB.prepare(`SELECT status FROM licenses WHERE stripe_payment_intent = 'pi_ok'`).first<{ status: string }>();
    expect(status?.status).toBe("revoked");
    await env.DB.prepare(`UPDATE licenses SET email_sent_at = NULL WHERE stripe_session_id = 'cs_ok'`).run();
    let sessionReads = 0;
    const real = seeded.env.DB;
    const racing = {
      prepare(sql: string) {
        const statement = real.prepare(sql);
        return {
          bind(...args: unknown[]) {
            const bound = statement.bind(...args);
            return {
              async first<T>() {
                if (sql.includes("stripe_session_id")) {
                  sessionReads += 1;
                  if (sessionReads % 2 === 1) return null;
                }
                return bound.first<T>();
              },
              all: () => bound.all(),
              async run() {
                if (sql.includes("INSERT INTO licenses")) throw new Error("UNIQUE constraint failed: licenses.stripe_session_id");
                return bound.run();
              },
            };
          },
        };
      },
    } as unknown as Env["DB"];
    const raced = await handleCheckoutCompleted(
      { ...seeded.env, DB: racing },
      async () => { throw new Error("resend down"); },
      { id: "cs_ok", customer_details: { email: "a@b.co" }, metadata: { app: "myapp", max_machines: "1" } },
      "1.1.1.1",
      NOW,
    );
    expect(raced.status).toBe(500);
    const racedOk = await handleCheckoutCompleted(
      { ...seeded.env, DB: racing },
      async () => undefined,
      { id: "cs_ok", customer_details: { email: "a@b.co" }, metadata: { app: "myapp", max_machines: "1" } },
      "1.1.1.1",
      NOW,
    );
    expect(racedOk.status).toBe(200);
    const missingRace = {
      prepare(sql: string) {
        const statement = real.prepare(sql);
        return {
          bind(...args: unknown[]) {
            const bound = statement.bind(...args);
            return {
              async first() {
                if (sql.includes("stripe_session_id")) return null;
                return bound.first();
              },
              async all() {
                if (sql.includes("INSERT INTO licenses")) throw new Error("UNIQUE constraint failed");
                return bound.all();
              },
              async run() {
                return bound.run();
              },
            };
          },
        };
      },
    } as unknown as Env["DB"];
    const emptyInsert = {
      prepare(sql: string) {
        const statement = real.prepare(sql);
        return {
          bind(...args: unknown[]) {
            const bound = statement.bind(...args);
            return {
              first: () => bound.first(),
              async all() {
                if (sql.includes("INSERT INTO licenses")) return { results: [] };
                return bound.all();
              },
              run: () => bound.run(),
            };
          },
        };
      },
    } as unknown as Env["DB"];
    expect((await handleCheckoutCompleted(
      { ...seeded.env, DB: emptyInsert },
      async () => undefined,
      { id: "cs_empty", customer_details: { email: "a@b.co" }, metadata: { app: "myapp", max_machines: "1" } },
      "1.1.1.1",
      NOW,
    )).status).toBe(200);
    await expect(handleCheckoutCompleted(
      { ...seeded.env, DB: missingRace },
      async () => undefined,
      { id: "cs_missing_race", customer_details: { email: "a@b.co" }, metadata: { app: "myapp", max_machines: "1" } },
      "1.1.1.1",
      NOW,
    )).rejects.toThrow("UNIQUE");
  });
});
