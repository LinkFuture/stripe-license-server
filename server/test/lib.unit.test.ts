import { env } from "cloudflare:test";
import { importSPKI, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import {
  adminAuthorized,
  createApp,
  deleteActivation,
  listActivations,
  listApps,
  listLicenses,
  patchApp,
  revokeLicense,
  stats,
} from "../src/lib/admin";
import {
  decryptSecret,
  encryptSecret,
  generateEd25519,
  generateLicenseKey,
  hashCode,
  hashLicenseKey,
  keyLast4,
  normalizeLicenseKey,
  publicKeyImports,
  randomDigits,
  signToken,
} from "../src/lib/crypto";
import { countsTowardLimit, getAppBySlug, getLicenseByHash, getLicenseById, listActivations as dbActivations, logEvent, machineView } from "../src/lib/db";
import { licenseEmail, resetCodeEmail, sendEmail } from "../src/lib/email";
import { handleChargeRefunded, handleCheckoutCompleted, handleDisputeCreated } from "../src/lib/issue";
import { HttpError, activate, confirmReset, deactivate, loadLicense, recover, requestReset, startTrial, validate } from "../src/lib/licensing";
import { hitLimit, limits } from "../src/lib/rate-limit";
import { isFullRefund, parseCheckout, stripeId, verifyStripeSignature } from "../src/lib/stripe";
import { signLicenseJwt, signTrialJwt } from "../src/lib/tokens";
import type { ActivationRow, AppRow, Env } from "../src/lib/types";
import {
  addDays,
  appPrivateKey,
  b64ToBytes,
  bytesToB64,
  clamp,
  clientIp,
  emailOk,
  extendEnv,
  intEnv,
  jsonError,
  licenseIssuer,
  likeContains,
  machineHashOk,
  normalizeMachineHash,
  nowIso,
  pageParams,
  parseMailFrom,
  parsePositiveInt,
  pemFromBuffer,
  readJson,
  resolveMailFrom,
  resolveReplyTo,
  sha256Hex,
  str,
  timingSafeEqual,
  timingSafeEqualHash,
} from "../src/lib/util";
import { handler, resetDb, seedApp, stripeSignature } from "./helpers";

const HASH = "a".repeat(64);
const NOW = new Date("2026-06-01T00:00:00.000Z");

beforeEach(async () => {
  await resetDb();
});

function headerContext(headers: Record<string, string | undefined>) {
  return {
    req: {
      header(name: string) {
        return headers[name.toLowerCase()];
      },
    },
  } as Parameters<typeof clientIp>[0];
}

async function row(slug = "myapp"): Promise<AppRow> {
  const app = await getAppBySlug(env.DB, slug);
  if (!app) throw new Error(`missing ${slug}`);
  return app;
}

async function expectHttp(run: () => Promise<unknown>, code: string) {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

describe("util", () => {
  it("covers parsing, mail, paging, and comparisons", async () => {
    expect(nowIso()).toContain("T");
    expect(nowIso(NOW)).toBe("2026-06-01T00:00:00.000Z");
    expect(str("hello")).toBe("hello");
    expect(addDays(NOW, 1)).toBe("2026-06-02T00:00:00.000Z");
    expect(addDays("2026-06-01T00:00:00.000Z", 2)).toContain("2026-06-03");
    expect(intEnv(undefined, 3)).toBe(3);
    expect(intEnv("", 3)).toBe(3);
    expect(intEnv("nope", 3)).toBe(3);
    expect(intEnv("4.9", 3)).toBe(4);
    expect(clientIp(headerContext({ "cf-connecting-ip": " 1.1.1.1 " }))).toBe("1.1.1.1");
    expect(clientIp(headerContext({ "x-forwarded-for": "2.2.2.2, 3.3.3.3" }))).toBe("2.2.2.2");
    expect(clientIp(headerContext({ "x-forwarded-for": "," }))).toBe("unknown");
    expect(clientIp(headerContext({}))).toBe("unknown");
    const response = jsonError(
      { json: (body: unknown, status?: number) => new Response(JSON.stringify(body), { status }) } as never,
      400,
      "bad",
      { extra: 1 },
    );
    expect(await response.json()).toMatchObject({ error: "bad", extra: 1 });
    const good = await readJson({ req: { json: async () => ({ a: 1 }) } } as never);
    const arrayBody = await readJson({ req: { json: async () => [] } } as never);
    const broken = await readJson({ req: { json: async () => { throw new Error("x"); } } } as never);
    expect(good.ok && good.body.a).toBe(1);
    expect(arrayBody.ok).toBe(false);
    expect(broken.ok).toBe(false);
    expect(str(1, 4)).toBeNull();
    expect(str("  ", 4)).toBeNull();
    expect(str("abcdef", 3)).toBe("abc");
    expect(clamp(null, 2)).toBeNull();
    expect(clamp("abcd", 2)).toBe("ab");
    expect(parseMailFrom("")).toBeNull();
    expect(parseMailFrom("a@b.com\ncc")).toBeNull();
    expect(parseMailFrom("x".repeat(201))).toBeNull();
    expect(parseMailFrom('"Desk" <desk@example.com>')).toBe("Desk <desk@example.com>");
    expect(parseMailFrom("<> <a@b.com>")).toBeNull();
    expect(parseMailFrom(`${"n".repeat(81)} <a@b.com>`)).toBeNull();
    expect(parseMailFrom('bad"name <a@b.com>')).toBeNull();
    expect(parseMailFrom("Name <not-an-email>")).toBeNull();
    expect(parseMailFrom("not-an-email")).toBeNull();
    expect(parseMailFrom("bare@example.com")).toBe("bare@example.com");
    expect(licenseIssuer({} as Env)).toBeNull();
    expect(licenseIssuer({ LICENSE_ISSUER: "  iss  " } as Env)).toBe("iss");
    expect(resolveMailFrom({ MAIL_FROM: "bad" } as Env, "  ")).toBeNull();
    expect(resolveMailFrom({ MAIL_FROM: "ok@example.com" } as Env, "Nope")).toBeNull();
    expect(resolveMailFrom({ MAIL_FROM: "ok@example.com" } as Env, null)).toBe("ok@example.com");
    expect(resolveReplyTo({} as Env)).toBeNull();
    expect(resolveReplyTo({ MAIL_REPLY_TO: "nope" } as Env)).toBeNull();
    expect(appPrivateKey(env, "missing")).toBeUndefined();
    expect(appPrivateKey(extendEnv(env, { APP_KEY_MYAPP: "   " }), "myapp")).toBeUndefined();
    expect(appPrivateKey(extendEnv(env, { APP_KEY_MYAPP: "pem" }), "myapp")).toBe("pem");
    const proxied = extendEnv(env, { MAIL_FROM: undefined, EXTRA: "x" });
    expect(proxied.MAIL_FROM).toBe(env.MAIL_FROM);
    expect((proxied as Env & { EXTRA: string }).EXTRA).toBe("x");
    expect(await sha256Hex("abc")).toHaveLength(64);
    expect(timingSafeEqual("ab", "a")).toBe(false);
    expect(timingSafeEqual("ab", "ab")).toBe(true);
    expect(await timingSafeEqualHash("a", "b")).toBe(false);
    expect(await timingSafeEqualHash("a", "a")).toBe(true);
    expect(pemFromBuffer("TEST", new ArrayBuffer(0))).toContain("BEGIN TEST");
    expect(pemFromBuffer("TEST", new Uint8Array(80).buffer)).toContain("\n");
    expect(b64ToBytes(bytesToB64(new Uint8Array([1, 2, 3])))).toEqual(new Uint8Array([1, 2, 3]));
    expect(machineHashOk("AB".repeat(32))).toBe(true);
    expect(machineHashOk("zz")).toBe(false);
    expect(normalizeMachineHash("AB")).toBe("ab");
    expect(parsePositiveInt(true)).toBeNull();
    expect(parsePositiveInt("")).toBeNull();
    expect(parsePositiveInt("1.5")).toBeNull();
    expect(parsePositiveInt(0)).toBeNull();
    expect(parsePositiveInt("2")).toBe(2);
    expect(emailOk(`${"a".repeat(320)}@b.co`)).toBe(false);
    expect(emailOk("a@b.co")).toBe(true);
    expect(likeContains("100%_\\x")).toBe("%100\\%\\_\\\\x%");
    expect(pageParams(new URL("https://x.test/?page=0"))).toBeNull();
    expect(pageParams(new URL("https://x.test/?page=2"))).toEqual({ page: 2, perPage: 50, offset: 50 });
    expect(pageParams(new URL("https://x.test/"))).toEqual({ page: 1, perPage: 50, offset: 0 });
  });
});

describe("crypto and tokens", () => {
  it("generates, normalizes, encrypts, and signs", async () => {
    const key = generateLicenseKey("MYAPP");
    expect(normalizeLicenseKey(key)).toBe(key);
    expect(normalizeLicenseKey("NO")).toBeNull();
    expect(normalizeLicenseKey("A-11111-11111-11111-11111")).toBeNull();
    expect(normalizeLicenseKey("MY-1111-11111-11111-11111")).toBeNull();
    expect(keyLast4(key)).toHaveLength(4);
    expect(await hashLicenseKey(key)).toBe(await sha256Hex(key));
    expect(randomDigits(0)).toBe("");
    expect(randomDigits(4000)).toMatch(/^\d{4000}$/);
    const secret = await encryptSecret("license-key", "pepper");
    expect(await decryptSecret(secret, "pepper")).toBe("license-key");
    expect(await hashCode("123456", 7, "pepper")).toHaveLength(64);
    const pair = await generateEd25519();
    expect(await publicKeyImports(pair.publicKeyPem)).toBe(true);
    expect(await publicKeyImports("nope")).toBe(false);
    const token = await signToken({
      privateKeyPem: pair.privateKeyPem,
      iss: "https://license.example.com",
      aud: "myapp",
      sub: "1",
      mid: HASH,
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const checked = await jwtVerify(token, await importSPKI(pair.publicKeyPem, "EdDSA"), {
      issuer: "https://license.example.com",
      audience: "myapp",
    });
    expect(checked.payload.mid).toBe(HASH);
    const seeded = await seedApp();
    const app = await row();
    await expect(signLicenseJwt({} as Env, app, seeded.privateKey, 1, HASH, 2, NOW)).rejects.toThrow("issuer_not_configured");
    await expect(signTrialJwt({} as Env, app, seeded.privateKey, 1, HASH, NOW.toISOString(), NOW)).rejects.toThrow("issuer_not_configured");
    const signed = await signLicenseJwt(seeded.env, app, seeded.privateKey, 9, HASH, 2, NOW);
    expect(signed.expiresAt).toContain("2026-07-01");
    const trial = await signTrialJwt(seeded.env, app, seeded.privateKey, 3, HASH, "2026-06-15T00:00:00.000Z", NOW);
    const trialPayload = await jwtVerify(trial, await importSPKI(seeded.publicKey, "EdDSA"), {
      currentDate: NOW,
    });
    expect(trialPayload.payload.sub).toBe("trial:3");
  });
});

describe("stripe helpers", () => {
  it("rejects bad signatures and parses checkout objects", async () => {
    const payload = "{\"id\":\"cs_1\"}";
    const now = 1_700_000_000;
    const header = await stripeSignature(payload, "whsec_test_secret", now);
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret", now)).toBe(true);
    expect(await verifyStripeSignature(payload, undefined, "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, header, undefined, now)).toBe(false);
    expect(await verifyStripeSignature(payload, "noequals", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, "t=abc,v1=aa", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, "t=1", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret", now + 10_000)).toBe(false);
    expect(await verifyStripeSignature(payload, `t=${"9".repeat(400)},v1=ab`, "whsec_test_secret", now)).toBe(false);
    const extras = Array.from({ length: 6 }, () => "v1=abcd").join(",");
    expect(await verifyStripeSignature(payload, `t=${now},${extras}`, "whsec_test_secret", now)).toBe(false);
    const wrong = header.replace(/v1=([0-9a-f]+)/, (_m, hex: string) => `v1=${"0".repeat(hex.length)}`);
    expect(await verifyStripeSignature(payload, `${wrong},v1=abcd`, "whsec_test_secret", now)).toBe(false);
    expect(stripeId("  pi_1  ")).toBe("pi_1");
    expect(stripeId("")).toBeNull();
    expect(stripeId({ id: " pi_2 " })).toBe("pi_2");
    expect(stripeId({ id: "  " })).toBeNull();
    expect(stripeId({ nope: 1 })).toBeNull();
    expect(stripeId(null)).toBeNull();
    const parsed = parseCheckout({
      id: "cs_9",
      customer_details: { email: " Buyer@Example.com " },
      payment_intent: { id: "pi_9" },
      metadata: { app: " MyApp ", max_machines: "2" },
    });
    expect(parsed).toMatchObject({ sessionId: "cs_9", email: "buyer@example.com", app: "myapp", paymentIntent: "pi_9" });
    expect(parseCheckout({ customer_email: "a@b.co", metadata: "nope" }).email).toBe("a@b.co");
    expect(parseCheckout({ customer_details: { email: 1 } }).email).toBeNull();
    expect(parseCheckout({}).sessionId).toBe("");
    expect(isFullRefund({ refunded: true })).toBe(true);
    expect(isFullRefund({ amount: "2", amount_refunded: 2 })).toBe(false);
    expect(isFullRefund({ amount: 0, amount_refunded: 0 })).toBe(false);
    expect(isFullRefund({ amount: 5, amount_refunded: 5 })).toBe(true);
    expect(isFullRefund({ amount: 5 })).toBe(false);
  });
});

describe("email", () => {
  it("skips, sends, and reports Resend failures", async () => {
    expect(licenseEmail("App", ["A", "B"])).toContain("keys");
    expect(licenseEmail("App", ["A"])).toContain("Your license key for App");
    expect(resetCodeEmail("App", "123456")).toContain("123456");
    await expect(sendEmail(env, { from: "", to: "a@b.co", subject: "s", text: "t" })).rejects.toThrow("mail_from_unset");
    const original = globalThis.fetch;
    try {
      await sendEmail({ ...env, RESEND_API_KEY: "" }, { from: "App <a@b.co>", to: "a@b.co", subject: "s", text: "t" });
      let body: Record<string, unknown> = {};
      globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;
      await sendEmail(env, { from: "App <a@b.co>", replyTo: "r@b.co", to: "a@b.co", subject: "s", text: "t" });
      expect(body.reply_to).toBe("r@b.co");
      globalThis.fetch = (async () => new Response("nope-body", { status: 500 })) as typeof fetch;
      await expect(sendEmail(env, { from: "App <a@b.co>", to: "a@b.co", subject: "s", text: "t" })).rejects.toThrow(/resend_500/);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("database and rate limit", () => {
  it("logs events and applies the inactive-machine rule", async () => {
    await logEvent(env.DB, { type: "note" });
    await logEvent(env.DB, { type: "note", detail: { a: 1 }, appId: null, licenseId: null, machineHash: null, ip: null });
    expect(await getAppBySlug(env.DB, "missing")).toBeNull();
    expect(await getLicenseByHash(env.DB, "missing")).toBeNull();
    expect(await getLicenseById(env.DB, 999)).toBeNull();
    expect(await dbActivations(env.DB, 1)).toEqual([]);
    const emptyDb = { prepare: () => ({ bind: () => ({ all: async () => ({}) }) }) } as unknown as D1Database;
    expect(await dbActivations(emptyDb, 1)).toEqual([]);
    const nullCount = {
      prepare: () => ({ bind: () => ({ run: async () => undefined, first: async () => null }) }),
    } as unknown as D1Database;
    expect(await hitLimit(nullCount, "missing-row", 5, 60, NOW)).toBe(false);
    const activation = { id: 1, license_id: 1, machine_hash: HASH, machine_name: null, platform: null, app_version: null, activated_at: NOW.toISOString(), last_seen_at: "2020-01-01T00:00:00.000Z" } satisfies ActivationRow;
    expect(countsTowardLimit(activation, 0, NOW)).toBe(true);
    expect(countsTowardLimit(activation, 90, NOW)).toBe(false);
    expect(machineView(activation, false).counts_toward_limit).toBe(false);
    expect(await hitLimit(env.DB, "plain", 1, 60)).toBe(false);
    expect(await hitLimit(env.DB, "bucket", 0, 60, NOW)).toBe(false);
    expect(await hitLimit(env.DB, "bucket", 1, 60, NOW)).toBe(false);
    expect(await hitLimit(env.DB, "bucket", 1, 60, new Date(NOW.getTime() + 120_000))).toBe(false);
    expect(limits({} as Env).ipPerMin).toBe(120);
    expect(limits({ RATE_LIMIT_IP_PER_MIN: "nope" } as Env).ipPerMin).toBe(120);
  });
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

describe("licensing edges", () => {
  it("covers limits, trials, recovery, and reset codes", async () => {
    const seeded = await seedApp(env, { inactiveReleaseDays: 90, resetLimit: 1, resetWindowDays: 30 });
    const app = await row();
    const bare = { env: seeded.env, app, ip: "1.1.1.1", now: NOW };
    await expectHttp(() => activate({ ...bare, body: { key: "MYAPP-11111-11111-11111-11111", machine_hash: "zz" } }), "invalid_machine");
    await expectHttp(() => activate({ ...bare, body: { key: "bad", machine_hash: HASH } }), "invalid_key");
    const issued = await handleCheckoutCompleted(seeded.env, async () => undefined, {
      id: "cs_lic",
      customer_details: { email: "owner@example.com" },
      metadata: { app: "myapp", max_machines: "1" },
      payment_intent: "pi_lic",
    }, "1.1.1.1", NOW);
    expect(issued.status).toBe(200);
    const license = await env.DB.prepare(`SELECT key_last4 FROM licenses WHERE stripe_session_id = 'cs_lic'`).first<{ key_last4: string }>();
    const keyRow = await env.DB.prepare(`SELECT key_enc FROM licenses WHERE stripe_session_id = 'cs_lic'`).first<{ key_enc: string }>();
    const plain = await decryptSecret(keyRow!.key_enc, "test-encryption-key");
    expect(plain.endsWith(license!.key_last4)).toBe(true);
    const noKey = await seedApp(env, { slug: "nokey", prefix: "NK", name: "No Key", includeKey: false });
    const noKeyApp = await row("nokey");
    await expectHttp(() => loadLicense(env.DB, noKeyApp, plain), "invalid_key");
    await expect(activate({ ...bare, body: { key: plain, machine_hash: HASH } })).resolves.toMatchObject({ machine_hash: HASH });
    await env.DB.prepare(`UPDATE licenses SET status = 'revoked', revoke_reason = 'admin' WHERE stripe_session_id = 'cs_lic'`).run();
    await expectHttp(() => validate({ ...bare, body: { key: plain, machine_hash: HASH } }), "revoked");
    await env.DB.prepare(`UPDATE licenses SET status = 'active', revoke_reason = NULL WHERE stripe_session_id = 'cs_lic'`).run();
    await expectHttp(() => validate({ ...bare, body: { key: plain, machine_hash: "b".repeat(64) } }), "not_activated");
    expect(await deactivate({ ...bare, body: { key: plain, machine_hash: "b".repeat(64) } })).toEqual({ ok: true });
    await expectHttp(() => startTrial({ ...bare, body: { machine_hash: "nope" } }), "invalid_machine");
    await expectHttp(() => startTrial({ ...bare, body: { machine_hash: HASH, local_started_at: "yesterday" } }), "invalid_local_started_at");
    const trial = await startTrial({ ...bare, body: { machine_hash: "c".repeat(64) } });
    expect(trial.token).toBeTruthy();
    await env.DB.prepare(`UPDATE apps SET status = 'disabled' WHERE slug = 'myapp'`).run();
    const disabled = await row();
    await expect(signLicenseJwt(seeded.env, disabled, seeded.privateKey, 1, HASH, 1, NOW)).resolves.toBeTruthy();
    await env.DB.prepare(`UPDATE apps SET status = 'active' WHERE slug = 'myapp'`).run();
    const current = await row();
    await env.DB.prepare(`DELETE FROM rate_limits`).run();
    const tightActivate = extendEnv(seeded.env, { RATE_LIMIT_ACTIVATE_KEY_PER_MIN: "1" });
    await activate({ env: tightActivate, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } });
    await expectHttp(() => activate({ env: tightActivate, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } }), "rate_limited");
    await env.DB.prepare(`DELETE FROM rate_limits`).run();
    const tight = extendEnv(seeded.env, { RATE_LIMIT_VALIDATE_KEY_PER_MIN: "1" });
    await validate({ env: tight, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } });
    await expectHttp(() => validate({ env: tight, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } }), "rate_limited");
    const recovered = await recover({
      env: extendEnv(seeded.env, { LICENSE_ENCRYPTION_KEY: "" }),
      send: async () => undefined,
      app: await row(),
      body: { email: "not-email" },
      ip: "1.1.1.1",
      now: NOW,
    });
    expect(recovered.ok).toBe(true);
    await expectHttp(() => requestReset({
      env: extendEnv(seeded.env, { MAIL_FROM: "" }),
      send: async () => undefined,
      app: current,
      body: { key: plain },
      ip: "1.1.1.1",
      now: NOW,
    }), "mail_from_unset");
    const limited = extendEnv(seeded.env, { RATE_LIMIT_RECOVER_EMAIL_PER_HOUR: "1" });
    const again = await row();
    await recover({ env: limited, send: async () => undefined, app: again, body: { email: "owner@example.com" }, ip: "1.1.1.1", now: NOW });
    await expectHttp(() => recover({ env: limited, send: async () => undefined, app: again, body: { email: "owner@example.com" }, ip: "1.1.1.1", now: NOW }), "rate_limited");
    await expect(recover({
      env: extendEnv(seeded.env, { MAIL_FROM: "" }),
      send: async () => undefined,
      app: current,
      body: { email: "owner@example.com" },
      ip: "1.1.1.1",
      now: NOW,
    })).resolves.toMatchObject({ ok: true });
    await expect(recover({
      env: seeded.env,
      send: async () => { throw new Error("down"); },
      app: current,
      body: { email: "owner@example.com" },
      ip: "1.1.1.1",
      now: NOW,
    })).resolves.toMatchObject({ ok: true });
    const requested = await requestReset({ env: seeded.env, send: async () => undefined, app: again, body: { key: plain }, ip: "1.1.1.1", now: NOW });
    expect(requested.ok).toBe(true);
    await expectHttp(() => confirmReset({ ...bare, body: { key: plain, machine_hash: "no" } }), "invalid_machine");
    await expectHttp(() => confirmReset({ ...bare, body: { key: plain, machine_hash: HASH, code: "12" } }), "invalid_code");
    await env.DB.prepare(`UPDATE email_codes SET expires_at = ?`).bind("2000-01-01T00:00:00.000Z").run();
    await expectHttp(() => confirmReset({ ...bare, body: { key: plain, machine_hash: HASH, code: "000000" } }), "invalid_code");
    await env.DB.prepare(`UPDATE email_codes SET expires_at = ?, attempts = 5`).bind("2099-01-01T00:00:00.000Z").run();
    await expectHttp(() => confirmReset({ ...bare, body: { key: plain, machine_hash: HASH, code: "000000" } }), "invalid_code");
    await env.DB.prepare(`DELETE FROM email_codes`).run();
    await expectHttp(() => confirmReset({ ...bare, body: { key: plain, machine_hash: HASH, code: "000000" } }), "invalid_code");
    const missingKey = await seedApp(env, { slug: "nokey2", prefix: "N2", name: "No", includeKey: false });
    const missingApp = await row("nokey2");
    await expectHttp(() => activate({
      env: missingKey.env,
      app: missingApp,
      ip: "1.1.1.1",
      now: NOW,
      body: { key: "N2-11111-11111-11111-11111", machine_hash: HASH },
    }), "invalid_key");
    expect(noKey.slug).toBe("nokey");
  });
});

describe("admin library", () => {
  it("rejects reserved slugs and covers list, revoke, and stats branches", async () => {
    expect(await adminAuthorized(env, undefined)).toBe(false);
    expect(await adminAuthorized({ ...env, ADMIN_TOKEN: "" }, "Bearer x")).toBe(false);
    expect(await adminAuthorized(env, "Basic x")).toBe(false);
    expect(await adminAuthorized(env, "Bearer   ")).toBe(false);
    expect(await adminAuthorized(env, "Bearer test-admin-token")).toBe(true);
    expect(await adminAuthorized(env, "Bearer wrong")).toBe(false);
    for (const slug of ["admin", "stripe", "health", "api", "ADMIN"]) {
      const created = await createApp(env, { slug, name: "N", key_prefix: "ZZ" }, NOW);
      expect(created.status).toBe(400);
      expect(created.body).toMatchObject({ error: slug.toLowerCase() === "admin" || RESERVED(slug) ? "reserved_slug" : "reserved_slug" });
    }
    expect((await createApp(env, { slug: "-bad", name: "N", key_prefix: "ZZ" }, NOW)).body).toMatchObject({ error: "invalid_slug" });
    expect((await createApp(env, { slug: "okapp", name: " ", key_prefix: "ZZ" }, NOW)).body).toMatchObject({ error: "invalid_name" });
    expect((await createApp(env, { slug: "okapp", name: "Ok", key_prefix: "z" }, NOW)).body).toMatchObject({ error: "invalid_key_prefix" });
    expect((await createApp(env, { slug: "okapp", name: "Ok", key_prefix: "OK", trial_days: -1 }, NOW)).body).toMatchObject({ error: "invalid_settings" });
    expect((await createApp(env, { slug: "okapp", name: "Ok", key_prefix: "OK", mail_from: 1 }, NOW)).body).toMatchObject({ error: "invalid_mail_from" });
    expect((await createApp(env, { slug: "okapp", name: "Ok", key_prefix: "OK", public_key: "nope" }, NOW)).body).toMatchObject({ error: "invalid_public_key" });
    const pair = await generateEd25519();
    const created = await createApp(env, {
      slug: "okapp",
      name: "Ok",
      key_prefix: "OK",
      public_key: pair.publicKeyPem,
      mail_from: "Desk <desk@example.com>",
      reset_limit: 0,
    }, NOW);
    expect(created.status).toBe(201);
    expect((await createApp(env, { slug: "okapp", name: "Ok", key_prefix: "OK2", public_key: pair.publicKeyPem }, NOW)).status).toBe(409);
    expect((await patchApp(env, "missing", {})).status).toBe(404);
    expect((await patchApp(env, "okapp", { name: "" })).body).toMatchObject({ error: "invalid_settings" });
    expect((await patchApp(env, "okapp", { status: "nope" })).body).toMatchObject({ error: "invalid_settings" });
    expect((await patchApp(env, "okapp", { mail_from: "bad" })).body).toMatchObject({ error: "invalid_mail_from" });
    const patched = await patchApp(env, "okapp", { mail_from: "", status: "disabled", trial_days: "10" });
    expect(patched.status).toBe(200);
    const apps = await listApps(env);
    expect(apps.some((item) => item.slug === "okapp" && item.mail_from === null && item.status === "disabled")).toBe(true);
    await env.DB.prepare(`UPDATE apps SET status = 'active' WHERE slug = 'okapp'`).run();
    expect((await listLicenses(env, new URL("https://x.test/?page=0"), NOW)).status).toBe(400);
    expect((await listLicenses(env, new URL("https://x.test/?status=nope"), NOW)).status).toBe(400);
    await handleCheckoutCompleted(env, async () => undefined, {
      id: "cs_admin",
      customer_details: { email: "a%_b@example.com" },
      metadata: { app: "okapp", max_machines: "1" },
      payment_intent: "pi_admin",
    }, "1.1.1.1", NOW);
    const listed = await listLicenses(env, new URL("https://x.test/?app=okapp&status=active&q=%5F"), NOW);
    expect(listed.status).toBe(200);
    const empty = await listLicenses(env, new URL("https://x.test/?app=okapp&q=nomatch"), NOW);
    expect(empty.status).toBe(200);
    expect((await listActivations(env, new URL("https://x.test/?page=no"))).status).toBe(400);
    expect((await listActivations(env, new URL("https://x.test/?license=0"))).status).toBe(400);
    const acts = await listActivations(env, new URL("https://x.test/?app=okapp&email=a%25_b@example.com&platform=none&license=1"));
    expect(acts.status).toBe(200);
    const license = await env.DB.prepare(`SELECT id FROM licenses WHERE stripe_session_id = 'cs_admin'`).first<{ id: number }>();
    expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "missing")).status).toBe(404);
    expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "okapp")).status).toBe(200);
    expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "okapp")).status).toBe(200);
    const inserted = await env.DB.prepare(
      `INSERT INTO activations (license_id, machine_hash, activated_at, last_seen_at) VALUES (?, ?, ?, ?) RETURNING id`,
    ).bind(license!.id, HASH, NOW.toISOString(), NOW.toISOString()).all<{ id: number }>();
    expect((await deleteActivation(env, inserted.results[0].id, "1.1.1.1", NOW, "okapp")).status).toBe(200);
    expect((await deleteActivation(env, 999, "1.1.1.1", NOW, "okapp")).status).toBe(404);
    const boom = {
      prepare(sql: string) {
        const statement = env.DB.prepare(sql);
        return {
          bind(...args: unknown[]) {
            const bound = statement.bind(...args);
            return {
              run: async () => {
                if (sql.includes("INSERT INTO apps")) throw new Error("disk full");
                return bound.run();
              },
              first: () => bound.first(),
              all: () => bound.all(),
            };
          },
        };
      },
    } as unknown as Env["DB"];
    await expect(createApp({ ...env, DB: boom }, { slug: "boom", name: "Boom", key_prefix: "BM", public_key: pair.publicKeyPem }, NOW)).rejects.toThrow("disk full");
    const all = await stats(env, new URL("https://x.test/"), NOW);
    expect(all.status).toBe(200);
    expect((await stats(env, new URL("https://x.test/?app=missing"), NOW)).status).toBe(404);
    const appHandler = handler();
    const reserved = await appHandler.request("/api/admin/apps", {
      method: "POST",
      headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "stripe", name: "Stripe", key_prefix: "ST" }),
    }, env);
    expect(reserved.status).toBe(400);
    expect(await reserved.json()).toMatchObject({ error: "reserved_slug" });
  });
});

function RESERVED(slug: string): boolean {
  return ["admin", "stripe", "health", "api"].includes(slug.toLowerCase());
}
