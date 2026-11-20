import { exportSPKI, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { describe, expect, it } from "vitest";
import {
  LicenseClient,
  machineHash,
  verifyOfflineToken,
  type StorageAdapter,
} from "../src/index";

const DAY = 86_400_000;

function memory(): StorageAdapter {
  const data = new Map<string, string>();
  return {
    get: (key) => data.get(key) ?? null,
    set: (key, value) => {
      data.set(key, value);
    },
    delete: (key) => {
      data.delete(key);
    },
  };
}

async function keyPair(): Promise<{ publicPem: string; privateKey: CryptoKey }> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  return { publicPem: await exportSPKI(publicKey), privateKey };
}

function token(privateKey: CryptoKey, opts: {
  aud?: string;
  mid: string;
  exp: number;
  iat?: number;
  max?: number;
  kind?: string;
  alg?: "EdDSA" | "HS256";
}): Promise<string> {
  const alg = opts.alg ?? "EdDSA";
  const key = alg === "HS256" ? new TextEncoder().encode("test-hmac-secret-test-hmac-secret") : privateKey;
  return new SignJWT({
    mid: opts.mid,
    kind: opts.kind ?? "license",
    ...(opts.max !== undefined ? { max: opts.max } : {}),
  })
    .setProtectedHeader({ alg })
    .setIssuer("license.linkfuture.net")
    .setAudience(opts.aud ?? "myapp")
    .setSubject(opts.kind === "trial" ? "trial:1" : "1")
    .setIssuedAt(opts.iat ?? opts.exp - 30 * 86_400)
    .setExpirationTime(opts.exp)
    .sign(key);
}

describe("machine hash", () => {
  it("changes when the app slug changes and hides the raw id", async () => {
    const left = await machineHash("myapp", "raw-machine");
    const right = await machineHash("other", "raw-machine");
    expect(left).not.toBe(right);
    expect(left).toMatch(/^[a-f0-9]{64}$/);
    expect(left).not.toContain("raw-machine");
  });
});

describe("offline verification", () => {
  it("accepts a valid token and rejects tampering, the wrong machine, the wrong app, expiry, and HS256", async () => {
    const { publicPem, privateKey } = await keyPair();
    const now = Date.parse("2026-06-01T00:00:00.000Z");
    const hash = await machineHash("myapp", "device-a");
    const otherHash = await machineHash("myapp", "device-b");
    const valid = await token(privateKey, { mid: hash, exp: Math.floor(now / 1000) + 30 * 86_400, max: 2 });
    const storage = memory();
    storage.set("myapp:license_token", valid);
    storage.set("myapp:license_key", "MYAPP-00000-00000-00000-00000");
    const client = new LicenseClient({
      appSlug: "myapp",
      publicKey: publicPem,
      apiBase: "https://license.example.com",
      storage,
      machineId: () => "device-a",
      now: () => now,
      fetch: async () => {
        throw new Error("network should not be required");
      },
    });
    const status = await client.getStatus();
    expect(status.state).toBe("licensed");
    expect(status.offline).toBe(true);
    expect(status.maxMachines).toBe(2);
    expect(status.daysLeft).toBe(30);
    expect(status.machineHash).toBe(hash);

    const verified = await verifyOfflineToken(valid, {
      publicKey: publicPem,
      audience: "myapp",
      machineHash: hash,
      now,
    });
    expect(verified.ok).toBe(true);

    const tampered = `${valid.slice(0, -2)}${valid.endsWith("a") ? "b" : "a"}`;
    expect(
      (await verifyOfflineToken(tampered, { publicKey: publicPem, audience: "myapp", machineHash: hash, now })).ok,
    ).toBe(false);

    const copied = new LicenseClient({
      appSlug: "myapp",
      publicKey: publicPem,
      apiBase: "https://license.example.com",
      storage,
      machineId: () => "device-b",
      now: () => now,
    });
    expect((await copied.getStatus()).state).not.toBe("licensed");
    const wrongMid = await verifyOfflineToken(valid, {
      publicKey: publicPem,
      audience: "myapp",
      machineHash: otherHash,
      now,
    });
    expect(wrongMid).toMatchObject({ ok: false, reason: "mid" });

    const wrongAud = await token(privateKey, { aud: "other", mid: hash, exp: Math.floor(now / 1000) + 1000, max: 2 });
    expect(
      (await verifyOfflineToken(wrongAud, { publicKey: publicPem, audience: "myapp", machineHash: hash, now })).ok,
    ).toBe(false);

    const expired = await token(privateKey, { mid: hash, exp: Math.floor(now / 1000) - 10, max: 2 });
    const expiredCheck = await verifyOfflineToken(expired, {
      publicKey: publicPem,
      audience: "myapp",
      machineHash: hash,
      now,
    });
    expect(expiredCheck).toMatchObject({ ok: false, reason: "expired" });

    const hmac = await token(privateKey, { mid: hash, exp: Math.floor(now / 1000) + 1000, max: 1, alg: "HS256" });
    expect((await verifyOfflineToken(hmac, { publicKey: publicPem, audience: "myapp", machineHash: hash, now })).ok).toBe(false);
  });

  it("keeps a revoked license usable until the offline token expires, then locks", async () => {
    const { publicPem, privateKey } = await keyPair();
    let now = Date.parse("2026-06-01T00:00:00.000Z");
    const hash = await machineHash("myapp", "device-a");
    const exp = Math.floor(now / 1000) + 10 * 86_400;
    const signed = await token(privateKey, { mid: hash, exp, max: 2 });
    const storage = memory();
    storage.set("myapp:license_token", signed);
    storage.set("myapp:license_key", "MYAPP-00000-00000-00000-00000");
    const client = new LicenseClient({
      appSlug: "myapp",
      publicKey: publicPem,
      apiBase: "https://license.example.com",
      storage,
      machineId: () => "device-a",
      now: () => now,
      fetch: async () =>
        new Response(JSON.stringify({ error: "revoked" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }),
    });
    const refreshed = await client.refreshInBackground();
    expect(refreshed.state).toBe("licensed");
    expect(refreshed.warning).toBe("revoked");
    expect(refreshed.daysLeft).toBe(10);
    now = exp * 1000 + 1000;
    const locked = await client.getStatus();
    expect(locked.state).toBe("revoked");
    expect(locked.daysLeft).toBe(0);
  });
});

describe("offline trial", () => {
  it("starts from the local install time without a network and does not reset when the clock moves backward", async () => {
    const { publicPem } = await keyPair();
    let now = Date.parse("2026-06-01T00:00:00.000Z");
    const client = new LicenseClient({
      appSlug: "myapp",
      publicKey: publicPem,
      apiBase: "https://license.example.com",
      storage: memory(),
      machineId: () => "device-a",
      trialDays: 30,
      now: () => now,
      fetch: async () => {
        throw new Error("offline");
      },
    });
    const started = await client.startTrial();
    expect(started.state).toBe("trial");
    expect(started.offline).toBe(true);
    expect(started.daysLeft).toBe(30);
    now += 10 * DAY;
    expect((await client.getStatus()).daysLeft).toBe(20);
    now -= 10 * DAY;
    const rolledBack = await client.getStatus();
    expect(rolledBack.daysLeft).toBe(20);
    expect(rolledBack.expiresAt).toBe(started.expiresAt);
  });

  it("keeps the earlier server start after a reinstall comes back online", async () => {
    const { publicPem, privateKey } = await keyPair();
    const now = Date.parse("2026-06-21T00:00:00.000Z");
    const hash = await machineHash("myapp", "device-a");
    const startedAt = "2026-06-01T00:00:00.000Z";
    const expiresAt = "2026-07-01T00:00:00.000Z";
    const signed = await token(privateKey, {
      mid: hash,
      exp: Math.floor(Date.parse(expiresAt) / 1000),
      iat: Math.floor(now / 1000),
      kind: "trial",
    });
    const client = new LicenseClient({
      appSlug: "myapp",
      publicKey: publicPem,
      apiBase: "https://license.example.com",
      storage: memory(),
      machineId: () => "device-a",
      trialDays: 30,
      now: () => now,
      fetch: async () =>
        new Response(JSON.stringify({ token: signed, started_at: startedAt, expires_at: expiresAt, machine_hash: hash }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    const status = await client.startTrial();
    expect(status.state).toBe("trial");
    expect(status.offline).toBe(false);
    expect(status.daysLeft).toBe(10);
    expect(status.expiresAt).toBe(expiresAt);
  });
});
