import { describe, expect, it } from "vitest";
import { devConfig, productionConfig } from "../../src/config/config";
import { devOverrides } from "../../src/config/config.dev";

describe("dev config", () => {
  it("raises only the per-IP cap and does not name a deployment", () => {
    expect(devOverrides.rateLimits.ipPerMin).toBe(240);
    expect(devConfig.rateLimits.ipPerMin).toBe(240);
    expect(devConfig.appDefaults).toEqual(productionConfig.appDefaults);
    expect(devConfig.rateLimits.ipPerMin).not.toBe(productionConfig.rateLimits.ipPerMin);
    expect(JSON.stringify(devOverrides)).not.toMatch(/dev|http|@|stripe-license/i);
  });
});
