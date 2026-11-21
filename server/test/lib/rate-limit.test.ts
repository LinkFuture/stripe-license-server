import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { config } from "../../src/config/config";
import { hitLimit, limits } from "../../src/lib/rate-limit";
import { resetDb } from "../helpers/fixtures";

const NOW = new Date("2026-06-01T00:00:00.000Z");

beforeEach(async () => {
  await resetDb();
});

describe("rate limit", () => {
  it("applies windows and falls back when the counter row is missing", async () => {
const nullCount = {
      prepare: () => ({ bind: () => ({ run: async () => undefined, first: async () => null }) }),
    } as unknown as D1Database;
expect(await hitLimit(nullCount, "missing-row", 5, 60, NOW)).toBe(false);
expect(await hitLimit(env.DB, "plain", 1, 60)).toBe(false);
expect(await hitLimit(env.DB, "bucket", 0, 60, NOW)).toBe(false);
expect(await hitLimit(env.DB, "bucket", 1, 60, NOW)).toBe(false);
expect(await hitLimit(env.DB, "bucket", 1, 60, new Date(NOW.getTime() + 120_000))).toBe(false);
expect(limits()).toBe(config.rateLimits);
expect(limits().ipPerMin).toBe(240);
  });
});
