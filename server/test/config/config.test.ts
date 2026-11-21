import { describe, expect, it } from "vitest";
import {
  applyOverrides,
  config,
  defaultAppDefaults,
  defaultRateLimits,
  devConfig,
  resolveConfig,
} from "../../src/config/config";

const configSources = import.meta.glob("../../src/config/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

const SECRET_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: "stripe secret key", pattern: /sk_(live|test)_/ },
  { name: "restricted key", pattern: /\brk_[A-Za-z0-9]/ },
  { name: "live publishable key", pattern: /pk_live_/ },
  { name: "webhook secret", pattern: /whsec_/ },
  { name: "resend key", pattern: /\bre_[A-Za-z0-9]/ },
  { name: "pem header", pattern: /-----BEGIN/ },
  { name: "private key label", pattern: /BEGIN PRIVATE KEY/ },
  { name: "long base64", pattern: /[A-Za-z0-9+/]{80,}={0,2}/ },
];

describe("shared config", () => {
  it("uses the dev numbers unless the build asks for production", () => {
    expect(defaultAppDefaults).toEqual({
      trialDays: 30,
      offlineGraceDays: 30,
      inactiveReleaseDays: 90,
      resetLimit: 5,
      resetWindowDays: 30,
    });
    expect(defaultRateLimits.ipPerMin).toBe(120);
    expect(defaultRateLimits.codeTtlSeconds).toBe(900);
    expect(defaultRateLimits.codeMaxAttempts).toBe(5);
    expect(applyOverrides()).toEqual({
      appDefaults: defaultAppDefaults,
      rateLimits: defaultRateLimits,
    });
    expect(applyOverrides({ appDefaults: { trialDays: 7 }, rateLimits: { ipPerMin: 3 } })).toMatchObject({
      appDefaults: { trialDays: 7, resetLimit: 5 },
      rateLimits: { ipPerMin: 3, activateIpPerMin: 20 },
    });
    expect(resolveConfig("production").rateLimits.ipPerMin).toBe(120);
    expect(resolveConfig("dev")).toEqual(devConfig);
    expect(resolveConfig(undefined)).toEqual(devConfig);
    expect(resolveConfig("staging")).toEqual(devConfig);
    expect(resolveConfig("")).toEqual(devConfig);
    expect(config).toEqual(devConfig);
  });

  it("rejects secret-looking strings and mailbox or URL literals in config sources", () => {
    const names = Object.keys(configSources).map((path) => path.split("/").pop());
    expect(names.sort()).toEqual(["config.dev.ts", "config.production.ts", "config.ts"]);
    for (const [path, text] of Object.entries(configSources)) {
      expect(text, path).not.toMatch(/@/);
      expect(text, path).not.toMatch(/https?:\/\//);
      for (const rule of SECRET_PATTERNS) {
        expect(text, `${path} ${rule.name}`).not.toMatch(rule.pattern);
      }
    }
  });
});
