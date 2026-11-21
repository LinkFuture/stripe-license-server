import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { Env } from "./types";

export function nowIso(now = new Date()): string {
  return now.toISOString();
}

export function addDays(isoOrDate: string | Date, days: number): string {
  const t = typeof isoOrDate === "string" ? Date.parse(isoOrDate) : isoOrDate.getTime();
  return new Date(t + days * 86_400_000).toISOString();
}

export function intEnv(value: string | undefined, fallback: number): number {
  if (value === undefined || value === "") return fallback;
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.floor(n);
}

export function clientIp(c: Context): string {
  const cf = c.req.header("cf-connecting-ip");
  if (cf) return cf.trim();
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]?.trim() || "unknown";
  return "unknown";
}

export function jsonError(
  c: Context,
  status: ContentfulStatusCode,
  error: string,
  extra?: Record<string, unknown>,
) {
  return c.json({ error, ...extra }, status);
}

export async function readJson(c: Context): Promise<
  { ok: true; body: Record<string, unknown> } | { ok: false }
> {
  try {
    const body = await c.req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false };
    return { ok: true, body: body as Record<string, unknown> };
  } catch {
    return { ok: false };
  }
}

export function str(value: unknown, max = 500): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, max);
}

export function clamp(value: string | null, max: number): string | null {
  if (value === null) return null;
  return value.slice(0, max);
}

const MAIL_ADDRESS = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

/** Accepts `addr` or `Display Name <addr>`. Rejects newlines and empty names. */
export function parseMailFrom(input: string): string | null {
  const value = input.trim();
  if (!value || value.length > 200 || /[\r\n]/.test(value)) return null;
  const wrapped = value.match(/^(.*) <([^<>]+)>$/);
  if (wrapped) {
    const name = wrapped[1].trim().replace(/^"|"$/g, "");
    const address = wrapped[2].trim();
    if (!name || name.length > 80 || /[<>"]/.test(name)) return null;
    if (!MAIL_ADDRESS.test(address)) return null;
    return `${name} <${address}>`;
  }
  if (!MAIL_ADDRESS.test(value)) return null;
  return value;
}

export function licenseIssuer(env: Env): string | null {
  const value = env.LICENSE_ISSUER?.trim();
  return value || null;
}

/** Per-app `mail_from` wins. Otherwise `MAIL_FROM`. Empty or invalid is unset. */
export function resolveMailFrom(env: Env, appMailFrom: string | null | undefined): string | null {
  const preferred = appMailFrom?.trim();
  if (preferred) return parseMailFrom(preferred);
  const fallback = env.MAIL_FROM?.trim();
  if (!fallback) return null;
  return parseMailFrom(fallback);
}

export function resolveReplyTo(env: Env): string | null {
  const value = env.MAIL_REPLY_TO?.trim();
  if (!value) return null;
  return parseMailFrom(value);
}

export function appKeySecretName(slug: string): string {
  return `APP_KEY_${slug.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
}

export function appPrivateKey(env: Env, slug: string): string | undefined {
  const name = appKeySecretName(slug);
  const value = (env as unknown as Record<string, unknown>)[name];
  return typeof value === "string" && value.trim() ? value : undefined;
}

export function extendEnv(env: Env, extra: Record<string, string | undefined>): Env {
  return new Proxy(env, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && prop in extra && extra[prop] !== undefined) {
        return extra[prop];
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

export async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ba = enc.encode(a);
  const bb = enc.encode(b);
  const len = Math.max(ba.length, bb.length);
  let diff = ba.length ^ bb.length;
  for (let i = 0; i < len; i++) {
    diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

export async function timingSafeEqualHash(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const ba = new Uint8Array(da);
  const bb = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

export function pemFromBuffer(label: string, data: ArrayBuffer): string {
  const bytes = new Uint8Array(data);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

export function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function machineHashOk(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value.toLowerCase());
}

export function normalizeMachineHash(value: string): string {
  return value.toLowerCase();
}

export function parsePositiveInt(value: unknown, max = 10_000): number | null {
  const raw = typeof value === "number" ? value : typeof value === "string" ? value.trim() : null;
  if (raw === null || raw === "") return null;
  const n = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > max) return null;
  return n;
}

export function emailOk(value: string): boolean {
  return value.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function likeContains(q: string): string {
  return `%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

export function pageParams(url: URL): { page: number; perPage: number; offset: number } | null {
  const pageRaw = url.searchParams.get("page");
  const page = pageRaw === null || pageRaw === "" ? 1 : Number(pageRaw);
  if (!Number.isInteger(page) || page < 1 || page > 100_000) return null;
  const perPage = 50;
  return { page, perPage, offset: (page - 1) * perPage };
}
