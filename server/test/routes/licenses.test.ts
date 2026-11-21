import { env } from "cloudflare:test";
import { importSPKI, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import {
  emails,
  handler,
  issueKey,
  machine,
  num,
  postJson,
  resetDb,
  seedApp,
} from "../helpers/fixtures";

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
