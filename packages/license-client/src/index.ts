import {
  errors,
  importJWK,
  importSPKI,
  jwtVerify,
  type CryptoKey,
  type JWTPayload,
} from "jose";

const DAY_MS = 86_400_000;

export interface StorageAdapter {
  get(key: string): Promise<string | null> | string | null;
  set(key: string, value: string): Promise<void> | void;
  delete?(key: string): Promise<void> | void;
}

export interface LicenseClientOptions {
  appSlug: string;
  /** SPKI PEM or JWK JSON. Verification allows EdDSA only. */
  publicKey: string;
  apiBase: string;
  storage: StorageAdapter;
  machineId: () => Promise<string> | string;
  /** Used only before the server has registered the trial. Defaults to 30. */
  trialDays?: number;
  platform?: string;
  appVersion?: string;
  machineName?: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export type LicenseState = "licensed" | "trial" | "trial_expired" | "unlicensed" | "revoked";

export interface LicenseStatus {
  state: LicenseState;
  /** Whole days remaining in the offline credential or trial. */
  daysLeft: number | null;
  maxMachines: number | null;
  expiresAt: string | null;
  machineHash: string;
  /** True when this result did not come from a successful network call. */
  offline: boolean;
  /**
   * Set when a refresh was refused. A still-valid offline token stays licensed
   * until `expiresAt`; after that, `revoked` locks the app.
   */
  warning: "revoked" | "not_activated" | null;
}

export class LicenseError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    readonly details?: unknown,
  ) {
    super(code);
  }
}

type VerifyResult =
  | { ok: true; kind: "license" | "trial"; exp: number; max: number | null }
  | { ok: false; reason: "expired"; kind: "license" | "trial"; exp: number | null }
  | { ok: false; reason: "mid" | "aud" | "alg" | "invalid" };

async function loadPublicKey(publicKey: string): Promise<CryptoKey> {
  const trimmed = publicKey.trim();
  if (trimmed.startsWith("{")) {
    const jwk = JSON.parse(trimmed) as Parameters<typeof importJWK>[0];
    const key = await importJWK(jwk, "EdDSA");
    if (key instanceof Uint8Array) throw new Error("unexpected_symmetric_key");
    return key;
  }
  return importSPKI(trimmed, "EdDSA");
}

function kindOf(payload: JWTPayload | undefined): "license" | "trial" {
  return payload?.kind === "trial" ? "trial" : "license";
}

function audienceMatches(payload: JWTPayload | undefined, audience: string): boolean {
  const aud = payload?.aud;
  if (typeof aud === "string") return aud === audience;
  if (Array.isArray(aud)) return aud.includes(audience);
  return false;
}

export async function machineHash(appSlug: string, machineId: string): Promise<string> {
  const bytes = new TextEncoder().encode(`${appSlug}\0${machineId}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyOfflineToken(
  token: string,
  opts: { publicKey: string; audience: string; machineHash: string; now: number },
): Promise<VerifyResult> {
  const key = await loadPublicKey(opts.publicKey);
  try {
    const { payload, protectedHeader } = await jwtVerify(token, key, {
      audience: opts.audience,
      algorithms: ["EdDSA"],
      currentDate: new Date(opts.now),
    });
    if (protectedHeader.alg !== "EdDSA") return { ok: false, reason: "alg" };
    if (payload.mid !== opts.machineHash) return { ok: false, reason: "mid" };
    if (typeof payload.exp !== "number") return { ok: false, reason: "invalid" };
    return {
      ok: true,
      kind: kindOf(payload),
      exp: payload.exp,
      max: typeof payload.max === "number" ? payload.max : null,
    };
  } catch (error) {
    const payload = (error as { payload?: JWTPayload }).payload;
    if (payload && payload.mid !== undefined && payload.mid !== opts.machineHash) {
      return { ok: false, reason: "mid" };
    }
    if (payload && payload.aud !== undefined && !audienceMatches(payload, opts.audience)) {
      return { ok: false, reason: "aud" };
    }
    if (error instanceof errors.JWTExpired) {
      return {
        ok: false,
        reason: "expired",
        kind: kindOf(payload),
        exp: typeof payload?.exp === "number" ? payload.exp : null,
      };
    }
    if (error instanceof errors.JWTClaimValidationFailed && error.claim === "aud") {
      return { ok: false, reason: "aud" };
    }
    return { ok: false, reason: "invalid" };
  }
}

function daysLeft(expMs: number, now: number): number {
  if (expMs <= now) return 0;
  return Math.ceil((expMs - now) / DAY_MS);
}

function status(partial: Omit<LicenseStatus, "warning"> & { warning?: LicenseStatus["warning"] }): LicenseStatus {
  return { warning: null, ...partial };
}

export class LicenseClient {
  private readonly fetchImpl: typeof fetch;
  private readonly trialDays: number;
  private readonly base: string;

  constructor(private readonly options: LicenseClientOptions) {
    this.fetchImpl = options.fetch ?? fetch;
    this.trialDays = options.trialDays ?? 30;
    this.base = options.apiBase.replace(/\/$/, "");
  }

  async getMachineHash(): Promise<string> {
    return machineHash(this.options.appSlug, await this.options.machineId());
  }

  async getStatus(): Promise<LicenseStatus> {
    return this.readStatus(true);
  }

  async activate(key: string): Promise<LicenseStatus> {
    const hash = await this.getMachineHash();
    const body = await this.requestOk("/activate", {
      key,
      machine_hash: hash,
      machine_name: this.options.machineName ?? null,
      platform: this.options.platform ?? null,
      app_version: this.options.appVersion ?? null,
    });
    const token = stringField(body, "token");
    if (!token) throw new LicenseError("invalid_response", 502);
    await this.set("license_key", key.trim());
    await this.set("license_token", token);
    await this.set("refresh_error", "");
    const current = await this.readStatus(false);
    return { ...current, offline: false };
  }

  async deactivate(): Promise<void> {
    const key = await this.get("license_key");
    const hash = await this.getMachineHash();
    if (key) {
      await this.requestOk("/deactivate", { key, machine_hash: hash });
    }
    await this.set("license_key", "");
    await this.set("license_token", "");
    await this.set("refresh_error", "");
  }

  async refreshInBackground(): Promise<LicenseStatus> {
    const key = await this.get("license_key");
    const hash = await this.getMachineHash();
    if (key) {
      try {
        const result = await this.request("/validate", { key, machine_hash: hash });
        if (result.ok) {
          const token = stringField(result.body, "token");
          if (token) await this.set("license_token", token);
          await this.set("refresh_error", "");
          const current = await this.readStatus(false);
          return { ...current, offline: false };
        }
        if (result.error === "revoked" || result.error === "not_activated") {
          await this.set("refresh_error", result.error);
        }
      } catch (error) {
        if (!(error instanceof LicenseError) || error.code !== "network") throw error;
      }
      return this.readStatus(true);
    }
    try {
      return await this.startTrial();
    } catch (error) {
      if (error instanceof LicenseError && error.code === "network") return this.readStatus(true);
      throw error;
    }
  }

  async startTrial(): Promise<LicenseStatus> {
    const now = await this.effectiveNow();
    let install = await this.get("install_at");
    if (!install) {
      install = new Date(now).toISOString();
      await this.set("install_at", install);
    }
    const hash = await this.getMachineHash();
    try {
      const result = await this.request("/trial", {
        machine_hash: hash,
        local_started_at: install,
        platform: this.options.platform ?? null,
        app_version: this.options.appVersion ?? null,
      });
      if (!result.ok) throw new LicenseError(result.error ?? "request_failed", result.status, result.body);
      const token = stringField(result.body, "token");
      const started = stringField(result.body, "started_at");
      const expires = stringField(result.body, "expires_at");
      if (token) await this.set("trial_token", token);
      if (started) {
        await this.set("trial_started_at", started);
        const install = await this.get("install_at");
        if (!install || Date.parse(started) < Date.parse(install)) await this.set("install_at", started);
      }
      if (expires) await this.set("trial_expires_at", expires);
      const current = await this.readStatus(false);
      return { ...current, offline: false };
    } catch (error) {
      if (error instanceof LicenseError && error.code === "network") return this.readStatus(true);
      throw error;
    }
  }

  async recover(email: string): Promise<void> {
    const result = await this.request("/recover", { email });
    if (!result.ok) throw new LicenseError(result.error ?? "request_failed", result.status, result.body);
  }

  private async readStatus(offline: boolean): Promise<LicenseStatus> {
    const now = await this.effectiveNow();
    const hash = await this.getMachineHash();
    const licenseToken = await this.get("license_token");
    const licenseKey = await this.get("license_key");
    const refreshError = await this.get("refresh_error");
    const warning =
      refreshError === "revoked" || refreshError === "not_activated" ? refreshError : null;

    if (licenseToken) {
      const verified = await verifyOfflineToken(licenseToken, {
        publicKey: this.options.publicKey,
        audience: this.options.appSlug,
        machineHash: hash,
        now,
      });
      if (verified.ok && verified.kind === "license") {
        return status({
          state: "licensed",
          daysLeft: daysLeft(verified.exp * 1000, now),
          maxMachines: verified.max,
          expiresAt: new Date(verified.exp * 1000).toISOString(),
          machineHash: hash,
          offline,
          warning,
        });
      }
      if (!verified.ok && verified.reason === "expired" && verified.kind === "license") {
        return status({
          state: warning === "revoked" ? "revoked" : "unlicensed",
          daysLeft: 0,
          maxMachines: null,
          expiresAt: verified.exp ? new Date(verified.exp * 1000).toISOString() : null,
          machineHash: hash,
          offline,
          warning,
        });
      }
      if (licenseKey || warning === "revoked") {
        return status({
          state: warning === "revoked" ? "revoked" : "unlicensed",
          daysLeft: null,
          maxMachines: null,
          expiresAt: null,
          machineHash: hash,
          offline,
          warning,
        });
      }
    } else if (warning === "revoked") {
      return status({
        state: "revoked",
        daysLeft: null,
        maxMachines: null,
        expiresAt: null,
        machineHash: hash,
        offline,
        warning,
      });
    }

    const trialToken = await this.get("trial_token");
    if (trialToken) {
      const verified = await verifyOfflineToken(trialToken, {
        publicKey: this.options.publicKey,
        audience: this.options.appSlug,
        machineHash: hash,
        now,
      });
      if (verified.ok && verified.kind === "trial") {
        return status({
          state: "trial",
          daysLeft: daysLeft(verified.exp * 1000, now),
          maxMachines: null,
          expiresAt: new Date(verified.exp * 1000).toISOString(),
          machineHash: hash,
          offline,
        });
      }
      if (!verified.ok && verified.reason === "expired") {
        return status({
          state: "trial_expired",
          daysLeft: 0,
          maxMachines: null,
          expiresAt: verified.exp ? new Date(verified.exp * 1000).toISOString() : null,
          machineHash: hash,
          offline,
        });
      }
    }

    let install = await this.get("install_at");
    if (!install) {
      install = new Date(now).toISOString();
      await this.set("install_at", install);
    }
    const expMs = Date.parse(install) + this.trialDays * DAY_MS;
    return status({
      state: expMs > now ? "trial" : "trial_expired",
      daysLeft: daysLeft(expMs, now),
      maxMachines: null,
      expiresAt: new Date(expMs).toISOString(),
      machineHash: hash,
      offline,
    });
  }

  private async effectiveNow(): Promise<number> {
    const now = this.options.now?.() ?? Date.now();
    const prev = Number((await this.get("last_observed_at")) || "0");
    const safePrev = Number.isFinite(prev) ? prev : 0;
    const effective = Math.max(now, safePrev);
    if (effective !== safePrev) await this.set("last_observed_at", String(effective));
    return effective;
  }

  private async request(
    path: string,
    body: unknown,
  ): Promise<{ ok: true; status: number; body: Record<string, unknown> } | { ok: false; status: number; error: string; body: unknown }> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.base}/v1/${encodeURIComponent(this.options.appSlug)}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new LicenseError("network", 0);
    }
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    if (!response.ok) {
      const error =
        parsed && typeof parsed === "object" && "error" in parsed && typeof parsed.error === "string"
          ? parsed.error
          : "request_failed";
      return { ok: false, status: response.status, error, body: parsed };
    }
    const record = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
    return { ok: true, status: response.status, body: record };
  }

  private async requestOk(path: string, body: unknown): Promise<Record<string, unknown>> {
    const result = await this.request(path, body);
    if (!result.ok) throw new LicenseError(result.error, result.status, result.body);
    return result.body;
  }

  private key(name: string): string {
    return `${this.options.appSlug}:${name}`;
  }

  private async get(name: string): Promise<string | null> {
    const value = await this.options.storage.get(this.key(name));
    return value ? value : null;
  }

  private async set(name: string, value: string): Promise<void> {
    if (!value && this.options.storage.delete) {
      await this.options.storage.delete(this.key(name));
      return;
    }
    await this.options.storage.set(this.key(name), value);
  }
}

function stringField(body: Record<string, unknown>, key: string): string | null {
  const value = body[key];
  return typeof value === "string" && value ? value : null;
}
