import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { decryptSecret } from "../../src/lib/crypto";
import { getAppBySlug } from "../../src/lib/db";
import { handleCheckoutCompleted } from "../../src/lib/issue";
import {
  HttpError,
  activate,
  confirmReset,
  deactivate,
  loadLicense,
  recover,
  requestReset,
  startTrial,
  validate,
} from "../../src/lib/licensing";
import { signLicenseJwt } from "../../src/lib/tokens";
import type { AppRow } from "../../src/lib/types";
import { extendEnv } from "../../src/lib/util";
import { resetDb, seedApp, withRateLimits } from "../helpers/fixtures";

const HASH = "a".repeat(64);
const NOW = new Date("2026-06-01T00:00:00.000Z");

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

beforeEach(async () => {
  await resetDb();
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
    await withRateLimits({ activateKeyPerMin: 1 }, async () => {
      await activate({ env: seeded.env, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } });
      await expectHttp(() => activate({ env: seeded.env, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } }), "rate_limited");
    });
    await env.DB.prepare(`DELETE FROM rate_limits`).run();
    await withRateLimits({ validateKeyPerMin: 1 }, async () => {
      await validate({ env: seeded.env, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } });
      await expectHttp(() => validate({ env: seeded.env, app: current, ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: HASH } }), "rate_limited");
    });
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
    const again = await row();
    await withRateLimits({ recoverEmailPerHour: 1 }, async () => {
      await recover({ env: seeded.env, send: async () => undefined, app: again, body: { email: "owner@example.com" }, ip: "1.1.1.1", now: NOW });
      await expectHttp(() => recover({ env: seeded.env, send: async () => undefined, app: again, body: { email: "owner@example.com" }, ip: "1.1.1.1", now: NOW }), "rate_limited");
    });
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

  it("refuses to sign when the app key is missing, blank, or from another app and does not write a new activation or trial", async () => {
    const missing = await seedApp(env, { slug: "bare", prefix: "BARE", name: "Bare", includeKey: false });
    const bare = await row("bare");
    await handleCheckoutCompleted(missing.env, async () => undefined, {
      id: "cs_bare",
      customer_details: { email: "owner@example.com" },
      metadata: { app: "bare", max_machines: "2" },
      payment_intent: "pi_bare",
    }, "1.1.1.1", NOW);
    const enc = await env.DB.prepare(`SELECT key_enc FROM licenses WHERE stripe_session_id = 'cs_bare'`).first<{ key_enc: string }>();
    const plain = await decryptSecret(enc!.key_enc, "test-encryption-key");
    const fresh = "d".repeat(64);
    const call = { ip: "1.1.1.1", now: NOW, body: { key: plain, machine_hash: fresh } };
    await expectHttp(() => activate({ env: missing.env, app: bare, ...call }), "signing_key_missing");
    await expectHttp(() => startTrial({ env: missing.env, app: bare, ip: "1.1.1.1", now: NOW, body: { machine_hash: fresh } }), "signing_key_missing");
    const blank = extendEnv(missing.env, { APP_KEY_BARE: "" });
    await expectHttp(() => activate({ env: blank, app: bare, ...call }), "signing_key_missing");
    const other = await seedApp(env, { slug: "other", prefix: "OTHR", name: "Other" });
    const mismatch = extendEnv(missing.env, { APP_KEY_BARE: other.privateKey });
    await expectHttp(() => activate({ env: mismatch, app: bare, ...call }), "signing_key_mismatch");
    const activations = await env.DB.prepare(`SELECT COUNT(*) AS c FROM activations`).first<{ c: number }>();
    const trials = await env.DB.prepare(`SELECT COUNT(*) AS c FROM trials WHERE app_id = ?`).bind(bare.id).first<{ c: number }>();
    expect(Number(activations?.c ?? 0)).toBe(0);
    expect(Number(trials?.c ?? 0)).toBe(0);
  });
});
