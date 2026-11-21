import { devOverrides } from "./config.dev";
import { productionOverrides } from "./config.production";

/** Injected by wrangler `define` (`"dev"` or `"production"`). Tests and local dev use `"dev"`. */
declare const __APP_ENV__: string;

export interface AppDefaults {
  trialDays: number;
  offlineGraceDays: number;
  inactiveReleaseDays: number;
  resetLimit: number;
  resetWindowDays: number;
}

export interface RateLimits {
  ipPerMin: number;
  activateIpPerMin: number;
  activateKeyPerMin: number;
  validateKeyPerMin: number;
  recoverIpPerMin: number;
  recoverEmailPerHour: number;
  resetIpPerMin: number;
  codeTtlSeconds: number;
  codeMaxAttempts: number;
}

export interface Config {
  appDefaults: AppDefaults;
  rateLimits: RateLimits;
}

export interface ConfigOverrides {
  appDefaults?: Partial<AppDefaults>;
  rateLimits?: Partial<RateLimits>;
}

/**
 * Shared defaults. `appDefaults` match the column defaults in migrations/0001_init.sql.
 * Mail sender, reply-to, and JWT issuer are Worker secrets, not fields on this object.
 */
export const defaultAppDefaults: AppDefaults = {
  trialDays: 30,
  offlineGraceDays: 30,
  inactiveReleaseDays: 90,
  resetLimit: 5,
  resetWindowDays: 30,
};

export const defaultRateLimits: RateLimits = {
  ipPerMin: 120,
  activateIpPerMin: 20,
  activateKeyPerMin: 10,
  validateKeyPerMin: 60,
  recoverIpPerMin: 5,
  recoverEmailPerHour: 5,
  resetIpPerMin: 10,
  codeTtlSeconds: 900,
  codeMaxAttempts: 5,
};

export function applyOverrides(overrides: ConfigOverrides = {}): Config {
  return {
    appDefaults: { ...defaultAppDefaults, ...overrides.appDefaults },
    rateLimits: { ...defaultRateLimits, ...overrides.rateLimits },
  };
}

/** `"production"` selects the production file. Every other name, including unset, selects dev. */
export function resolveConfig(envName: string | undefined): Config {
  if (envName === "production") return applyOverrides(productionOverrides);
  return applyOverrides(devOverrides);
}

export const devConfig: Config = applyOverrides(devOverrides);
export const productionConfig: Config = applyOverrides(productionOverrides);

export const config: Config = resolveConfig(__APP_ENV__);
