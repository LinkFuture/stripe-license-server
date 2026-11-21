import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handler, machine, num, resetDb } from "../helpers/fixtures";

const M1 = machine("a");
const M2 = machine("b");
const M3 = machine("c");
const M4 = machine("d");

beforeEach(async () => {
  await resetDb();
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

describe("cross-app admin isolation", () => {
  it("does not revoke, unbind, list, or count another app's rows", async () => {
    const now = new Date().toISOString();
    await env.DB
      .prepare(
        `INSERT INTO apps (slug, name, key_prefix, public_key) VALUES
         ('appa', 'App A', 'APPA', 'pk-a'),
         ('appb', 'App B', 'APPB', 'pk-b')`,
      )
      .run();
    const appA = await env.DB.prepare(`SELECT id FROM apps WHERE slug = 'appa'`).first<{ id: number }>();
    const appB = await env.DB.prepare(`SELECT id FROM apps WHERE slug = 'appb'`).first<{ id: number }>();
    const insertLicense = async (appId: number, session: string) => {
      const inserted = await env.DB
        .prepare(
          `INSERT INTO licenses (app_id, key_hash, key_last4, key_enc, email, max_machines, stripe_session_id, status, created_at)
           VALUES (?, ?, 'AAAA', 'enc', ?, 1, ?, 'active', ?) RETURNING id`,
        )
        .bind(appId, `hash-${session}`, `${session}@example.com`, session, now)
        .all<{ id: number }>();
      const row = inserted.results?.[0];
      if (!row) throw new Error("license insert failed");
      return row.id;
    };
    const licenseA = await insertLicense(appA!.id, "cs-a");
    const licenseB = await insertLicense(appB!.id, "cs-b");
    const activationA = await env.DB
      .prepare(
        `INSERT INTO activations (license_id, machine_hash, platform, app_version, activated_at, last_seen_at)
         VALUES (?, ?, 'darwin', '1.0.0', ?, ?) RETURNING id`,
      )
      .bind(licenseA, M1, now, now)
      .all<{ id: number }>();
    const activationB = await env.DB
      .prepare(
        `INSERT INTO activations (license_id, machine_hash, platform, app_version, activated_at, last_seen_at)
         VALUES (?, ?, 'linux', '2.0.0', ?, ?) RETURNING id`,
      )
      .bind(licenseB, M2, now, now)
      .all<{ id: number }>();
    const idB = activationB.results?.[0]?.id;
    if (!idB) throw new Error("activation insert failed");

    const app = handler();
    const auth = { Authorization: "Bearer test-admin-token" };
    const revoked = await app.request(`/api/appa/admin/licenses/${licenseB}/revoke`, { method: "POST", headers: auth }, env);
    expect(revoked.status).toBe(404);
    const stillLicensed = await env.DB
      .prepare(`SELECT status, revoke_reason FROM licenses WHERE id = ?`)
      .bind(licenseB)
      .first<{ status: string; revoke_reason: string | null }>();
    expect(stillLicensed).toEqual({ status: "active", revoke_reason: null });

    const removed = await app.request(`/api/appa/admin/activations/${idB}`, { method: "DELETE", headers: auth }, env);
    expect(removed.status).toBe(404);
    const stillBound = await env.DB.prepare(`SELECT id FROM activations WHERE id = ?`).bind(idB).first<{ id: number }>();
    expect(stillBound?.id).toBe(idB);

    const licenses = await app.request("/api/appa/admin/licenses", { headers: auth }, env);
    const licenseBody = (await licenses.json()) as { total: number; items: { id: number; email: string }[] };
    expect(licenses.status).toBe(200);
    expect(licenseBody.total).toBe(1);
    expect(licenseBody.items.map((item) => item.id)).toEqual([licenseA]);
    expect(licenseBody.items.map((item) => item.email)).toEqual(["cs-a@example.com"]);

    const activations = await app.request("/api/appa/admin/activations", { headers: auth }, env);
    const activationBody = (await activations.json()) as { total: number; items: { id: number; app: string }[] };
    expect(activations.status).toBe(200);
    expect(activationBody.total).toBe(1);
    expect(activationBody.items.map((item) => item.id)).toEqual([activationA.results?.[0]?.id]);
    expect(activationBody.items.map((item) => item.app)).toEqual(["appa"]);

    const statsRes = await app.request("/api/appa/admin/stats", { headers: auth }, env);
    const statsBody = (await statsRes.json()) as {
      apps: { app: string; licenses: { total: number; active: number }; machines: { total: number } }[];
    };
    expect(statsRes.status).toBe(200);
    expect(statsBody.apps.map((item) => item.app)).toEqual(["appa"]);
    expect(statsBody.apps[0]?.licenses).toMatchObject({ total: 1, active: 1 });
    expect(statsBody.apps[0]?.machines.total).toBe(1);
  });
});

describe("reserved slug", () => {
  it("rejects a reserved slug on the admin route", async () => {
    const app = handler();
    const reserved = await app.request("/api/admin/apps", {
      method: "POST",
      headers: { Authorization: "Bearer test-admin-token", "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "stripe", name: "Stripe", key_prefix: "ST" }),
    }, env);
    expect(reserved.status).toBe(400);
    expect(await reserved.json()).toMatchObject({ error: "reserved_slug" });
  });
});
