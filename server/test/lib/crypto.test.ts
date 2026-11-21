import { importSPKI, jwtVerify } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import {
  decryptSecret,
  encryptSecret,
  generateEd25519,
  generateLicenseKey,
  hashCode,
  hashLicenseKey,
  keyLast4,
  normalizeLicenseKey,
  publicKeyImports,
  randomDigits,
  signToken,
} from "../../src/lib/crypto";
import { sha256Hex } from "../../src/lib/util";
import { resetDb } from "../helpers/fixtures";

const HASH = "a".repeat(64);

beforeEach(async () => {
  await resetDb();
});

describe("crypto", () => {
  it("generates, normalizes, encrypts, and signs", async () => {
const key = generateLicenseKey("MYAPP");
expect(normalizeLicenseKey(key)).toBe(key);
expect(normalizeLicenseKey("NO")).toBeNull();
expect(normalizeLicenseKey("A-11111-11111-11111-11111")).toBeNull();
expect(normalizeLicenseKey("MY-1111-11111-11111-11111")).toBeNull();
expect(keyLast4(key)).toHaveLength(4);
expect(await hashLicenseKey(key)).toBe(await sha256Hex(key));
expect(randomDigits(0)).toBe("");
expect(randomDigits(4000)).toMatch(/^\d{4000}$/);
const secret = await encryptSecret("license-key", "pepper");
expect(await decryptSecret(secret, "pepper")).toBe("license-key");
expect(await hashCode("123456", 7, "pepper")).toHaveLength(64);
const pair = await generateEd25519();
expect(await publicKeyImports(pair.publicKeyPem)).toBe(true);
expect(await publicKeyImports("nope")).toBe(false);
const token = await signToken({
      privateKeyPem: pair.privateKeyPem,
      iss: "https://license.example.com",
      aud: "myapp",
      sub: "1",
      mid: HASH,
      exp: Math.floor(Date.now() / 1000) + 60,
    });
const checked = await jwtVerify(token, await importSPKI(pair.publicKeyPem, "EdDSA"), {
      issuer: "https://license.example.com",
      audience: "myapp",
    });
expect(checked.payload.mid).toBe(HASH);
  });
});

describe("key normalization", () => {
it("normalizes case, spaces, and Crockford ambiguous characters", () => {
    expect(normalizeLicenseKey(" myapp-00oi1-lllll-ooooo-11111 ")).toBe("MYAPP-00011-11111-00000-11111");
    expect(normalizeLicenseKey("MYAPP-0000U-00000-00000-00000")).toBeNull();
  });
});
