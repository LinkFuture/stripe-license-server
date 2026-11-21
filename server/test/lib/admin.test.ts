import { env } from "cloudflare:test";
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
} from "../../src/lib/admin";
import { generateEd25519 } from "../../src/lib/crypto";
import { handleCheckoutCompleted } from "../../src/lib/issue";
import type { Env } from "../../src/lib/types";
import { resetDb } from "../helpers/fixtures";

const HASH = "a".repeat(64);
const NOW = new Date("2026-06-01T00:00:00.000Z");

beforeEach(async () => {
  await resetDb();
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
    };
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
const otherApp = await createApp(env, { slug: "otherapp", name: "Other", key_prefix: "OT", public_key: pair.publicKeyPem }, NOW);
expect(otherApp.status).toBe(201);
const beforeCross = await env.DB.prepare(`SELECT status, revoke_reason FROM licenses WHERE id = ?`).bind(license!.id).first<{ status: string; revoke_reason: string | null }>();
expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "otherapp")).status).toBe(404);
const afterCross = await env.DB.prepare(`SELECT status, revoke_reason FROM licenses WHERE id = ?`).bind(license!.id).first<{ status: string; revoke_reason: string | null }>();
expect(afterCross).toEqual(beforeCross);
expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "okapp")).status).toBe(200);
expect((await revokeLicense(env, license!.id, "1.1.1.1", NOW, "okapp")).status).toBe(200);
const inserted = await env.DB.prepare(
      `INSERT INTO activations (license_id, machine_hash, activated_at, last_seen_at) VALUES (?, ?, ?, ?) RETURNING id`,
    ).bind(license!.id, HASH, NOW.toISOString(), NOW.toISOString()).all<{ id: number }>();
expect((await deleteActivation(env, inserted.results[0].id, "1.1.1.1", NOW, "otherapp")).status).toBe(404);
expect((await env.DB.prepare(`SELECT id FROM activations WHERE id = ?`).bind(inserted.results[0].id).first<{ id: number }>())?.id).toBe(inserted.results[0].id);
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
  });
});

function RESERVED(slug: string): boolean {
  return ["admin", "stripe", "health", "api"].includes(slug.toLowerCase());
}
