import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  countsTowardLimit,
  getAppBySlug,
  getLicenseByHash,
  getLicenseById,
  listActivations as dbActivations,
  logEvent,
  machineView,
} from "../../src/lib/db";
import type { ActivationRow } from "../../src/lib/types";
import { resetDb } from "../helpers/fixtures";

const HASH = "a".repeat(64);
const NOW = new Date("2026-06-01T00:00:00.000Z");

beforeEach(async () => {
  await resetDb();
});

describe("database", () => {
  it("logs events and applies the inactive-machine rule", async () => {
await logEvent(env.DB, { type: "note" });
await logEvent(env.DB, { type: "note", detail: { a: 1 }, appId: null, licenseId: null, machineHash: null, ip: null });
expect(await getAppBySlug(env.DB, "missing")).toBeNull();
expect(await getLicenseByHash(env.DB, "missing")).toBeNull();
expect(await getLicenseById(env.DB, 999)).toBeNull();
expect(await dbActivations(env.DB, 1)).toEqual([]);
const emptyDb = { prepare: () => ({ bind: () => ({ all: async () => ({}) }) }) } as unknown as D1Database;
expect(await dbActivations(emptyDb, 1)).toEqual([]);
const activation = { id: 1, license_id: 1, machine_hash: HASH, machine_name: null, platform: null, app_version: null, activated_at: NOW.toISOString(), last_seen_at: "2020-01-01T00:00:00.000Z" } satisfies ActivationRow;
expect(countsTowardLimit(activation, 0, NOW)).toBe(true);
expect(countsTowardLimit(activation, 90, NOW)).toBe(false);
expect(machineView(activation, false).counts_toward_limit).toBe(false);
  });
});
