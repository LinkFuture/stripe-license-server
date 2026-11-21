import { importPKCS8, importSPKI, SignJWT } from "jose";
import { bytesToB64, b64ToBytes, pemFromBuffer, sha256Hex } from "./util";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUP = /^[0-9A-HJKMNP-TV-Z]{5}$/;

export function generateLicenseKey(prefix: string): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes, (b) => ALPHABET[b & 31]);
  const groups = [0, 5, 10, 15].map((i) => chars.slice(i, i + 5).join(""));
  return `${prefix}-${groups.join("-")}`;
}

/** Canonical form is PREFIX-XXXXX-XXXXX-XXXXX-XXXXX. Prefix is not remapped. */
export function normalizeLicenseKey(input: string): string | null {
  const compact = input.trim().toUpperCase().replace(/\s+/g, "");
  const parts = compact.split("-").filter((p) => p.length > 0);
  if (parts.length !== 5) return null;
  const [prefix, ...groups] = parts;
  if (!prefix || !/^[A-Z0-9]{2,12}$/.test(prefix)) return null;
  const mapped = groups.map((g) => g.replace(/[IL]/g, "1").replace(/O/g, "0"));
  if (mapped.some((g) => !GROUP.test(g))) return null;
  return `${prefix}-${mapped.join("-")}`;
}

export async function hashLicenseKey(canonical: string): Promise<string> {
  return sha256Hex(canonical);
}

export function keyLast4(canonical: string): string {
  return canonical.slice(-4);
}

export async function generateEd25519(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = (await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer;
  const pkcs8 = (await crypto.subtle.exportKey("pkcs8", kp.privateKey)) as ArrayBuffer;
  return {
    publicKeyPem: pemFromBuffer("PUBLIC KEY", spki),
    privateKeyPem: pemFromBuffer("PRIVATE KEY", pkcs8),
  };
}

export async function publicKeyImports(pem: string): Promise<boolean> {
  try {
    await importSPKI(pem, "EdDSA");
    return true;
  } catch {
    return false;
  }
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(plaintext: string, secret: string): Promise<string> {
  const key = await aesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return bytesToB64(out);
}

export async function decryptSecret(payload: string, secret: string): Promise<string> {
  const bytes = b64ToBytes(payload);
  const iv = bytes.slice(0, 12);
  const ct = bytes.slice(12);
  const key = await aesKey(secret);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(plain);
}

export async function signToken(opts: {
  privateKeyPem: string;
  iss: string;
  aud: string;
  sub: string;
  mid: string;
  exp: number;
  iat?: number;
  extra?: Record<string, unknown>;
}): Promise<string> {
  const key = await importPKCS8(opts.privateKeyPem, "EdDSA");
  const iat = opts.iat ?? Math.floor(Date.now() / 1000);
  return new SignJWT({ mid: opts.mid, ...(opts.extra ?? {}) })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuer(opts.iss)
    .setAudience(opts.aud)
    .setSubject(opts.sub)
    .setIssuedAt(iat)
    .setExpirationTime(opts.exp)
    .sign(key);
}

export function randomDigits(length: number): string {
  let out = "";
  while (out.length < length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= 250) continue;
      out += String(byte % 10);
      if (out.length === length) return out;
    }
  }
  return out;
}

export async function hashCode(code: string, licenseId: number, pepper: string): Promise<string> {
  return sha256Hex(`${pepper}:${licenseId}:${code}`);
}
