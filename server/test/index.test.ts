import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handler, resetDb } from "./helpers/fixtures";

beforeEach(async () => {
  await resetDb();
});

describe("route prefixes", () => {
  it("returns 404 for the retired paths", async () => {
    const app = handler();
    expect((await app.request("/admin/apps", { headers: { Authorization: "Bearer test-admin-token" } }, env)).status).toBe(404);
    expect((await app.request("/health", {}, env)).status).toBe(404);
    expect((await app.request("/api/health", {}, env)).status).toBe(200);
  });
});
