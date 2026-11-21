import { env } from "cloudflare:test";
import { importSPKI, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { getAppBySlug } from "../../src/lib/db";
import { signLicenseJwt, signTrialJwt } from "../../src/lib/tokens";
import type { AppRow, Env } from "../../src/lib/types";
import { resetDb, seedApp } from "../helpers/fixtures";

const HASH = "a".repeat(64);
const NOW = new Date("2026-06-01T00:00:00.000Z");

async function row(slug = "myapp"): Promise<AppRow> {
  const app = await getAppBySlug(env.DB, slug);
  if (!app) throw new Error(`missing ${slug}`);
  return app;
}

beforeEach(async () => {
  await resetDb();
});

describe("tokens", () => {
  it("requires an issuer and signs license and trial JWTs", async () => {
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
