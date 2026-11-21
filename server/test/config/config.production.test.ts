import { describe, expect, it } from "vitest";
import { devConfig, productionConfig } from "../../src/config/config";
import { productionOverrides } from "../../src/config/config.production";

const wranglerSources = import.meta.glob("../../wrangler.toml", {
  query: "?raw",
  import: "default",
  eager: true,
});

const DEV_DATABASE_NAME = "stripe-license-dev";
const DEV_WORKER_NAME = "stripe-license-server-dev";
const DEV_DATABASE_ID = "00000000-0000-4000-8000-000000000001";

function stringsIn(value: unknown, found: string[] = []): string[] {
  if (typeof value === "string") found.push(value);
  else if (value && typeof value === "object") {
    for (const child of Object.values(value)) stringsIn(child, found);
  }
  return found;
}

function productionBlock(toml: string): string {
  const marker = "\n[env.production]\n";
  const start = toml.indexOf(marker);
  if (start < 0) throw new Error("missing [env.production]");
  return toml.slice(start);
}

describe("production config", () => {
  it("keeps the shared ceilings and does not point at dev resources", () => {
    expect(productionOverrides.rateLimits.ipPerMin).toBe(120);
    expect(productionConfig.rateLimits.ipPerMin).toBe(120);
    expect(productionConfig.rateLimits.activateKeyPerMin).toBe(devConfig.rateLimits.activateKeyPerMin);
    expect(productionConfig.rateLimits.ipPerMin).not.toBe(devConfig.rateLimits.ipPerMin);

    const encoded = JSON.stringify(productionConfig);
    expect(encoded).not.toContain(DEV_DATABASE_NAME);
    expect(encoded).not.toContain(DEV_WORKER_NAME);
    expect(encoded).not.toContain(DEV_DATABASE_ID);
    expect(encoded).not.toMatch(/webhook/i);
    for (const value of stringsIn(productionConfig)) {
      expect(value.toLowerCase()).not.toContain("dev");
    }

    const toml = Object.values(wranglerSources)[0] ?? "";
    expect(toml).toContain("[env.production]");
    const block = productionBlock(toml);
    expect(block).toContain('name = "stripe-license-server"');
    expect(block).toContain('database_name = "stripe-license"');
    expect(block).toContain("00000000-0000-4000-8000-000000000002");
    expect(block).not.toContain(DEV_DATABASE_NAME);
    expect(block).not.toContain(DEV_WORKER_NAME);
    expect(block).not.toContain(DEV_DATABASE_ID);
    expect(block).not.toMatch(/workers\.dev/);
  });
});
