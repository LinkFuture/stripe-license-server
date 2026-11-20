import { env } from "cloudflare:test";
import { createAppHandler } from "../src/app";
import { generateEd25519 } from "../src/crypto";
import type { Env, OutboundEmail } from "../src/types";
import { extendEnv } from "../src/util";

export const emails: OutboundEmail[] = [];

export function handler() {
  return createAppHandler({
    sendEmail: async (_env, message) => {
      emails.push(message);
    },
  });
}

export async function resetDb(db: D1Database = env.DB): Promise<void> {
  emails.length = 0;
  for (const table of [
    "events",
    "email_codes",
    "activations",
    "trials",
    "licenses",
    "rate_limits",
    "apps",
  ]) {
    await db.prepare(`DELETE FROM ${table}`).run();
  }
}

export interface SeededApp {
  env: Env;
  slug: string;
  prefix: string;
  name: string;
  publicKey: string;
  privateKey: string;
}

export async function seedApp(
  base: Env = env,
  opts: {
    slug?: string;
    prefix?: string;
    name?: string;
    trialDays?: number;
    offlineGraceDays?: number;
    inactiveReleaseDays?: number;
    resetLimit?: number;
    resetWindowDays?: number;
    includeKey?: boolean;
    extra?: Record<string, string>;
  } = {},
): Promise<SeededApp> {
  const slug = opts.slug ?? "myapp";
  const prefix = opts.prefix ?? "MYAPP";
  const name = opts.name ?? "My App";
  const keys = await generateEd25519();
  await base.DB.prepare(
    `INSERT INTO apps (
       slug, name, key_prefix, public_key, trial_days, offline_grace_days,
       inactive_release_days, reset_limit, reset_window_days
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      slug,
      name,
      prefix,
      keys.publicKeyPem,
      opts.trialDays ?? 30,
      opts.offlineGraceDays ?? 30,
      opts.inactiveReleaseDays ?? 90,
      opts.resetLimit ?? 3,
      opts.resetWindowDays ?? 30,
    )
    .run();
  const secret = `APP_KEY_${slug.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
  const extra: Record<string, string> = { ...(opts.extra ?? {}) };
  if (opts.includeKey !== false) extra[secret] = keys.privateKeyPem;
  return {
    env: extendEnv(base, extra),
    slug,
    prefix,
    name,
    publicKey: keys.publicKeyPem,
    privateKey: keys.privateKeyPem,
  };
}

export async function stripeSignature(payload: string, secret: string, timestamp = Math.floor(Date.now() / 1000)): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${payload}`));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `t=${timestamp},v1=${hex}`;
}

export function checkoutPayload(opts: {
  sessionId: string;
  paymentIntent?: string | null;
  email?: string | null;
  metadata?: Record<string, string> | null;
  amount?: number;
}): string {
  const metadata = opts.metadata === null ? {} : opts.metadata ?? { app: "myapp", max_machines: "2" };
  return JSON.stringify({
    id: `evt_${opts.sessionId}`,
    type: "checkout.session.completed",
    data: {
      object: {
        id: opts.sessionId,
        object: "checkout.session",
        payment_intent: opts.paymentIntent === undefined ? `pi_${opts.sessionId}` : opts.paymentIntent,
        customer_details: opts.email === null ? {} : { email: opts.email ?? "buyer@example.com" },
        metadata,
        amount_total: opts.amount ?? 2000,
        payment_status: "paid",
      },
    },
  });
}

export async function postWebhook(app: ReturnType<typeof handler>, runtime: Env, payload: string, secret = "whsec_test_secret", timestamp?: number): Promise<Response> {
  const signature = await stripeSignature(payload, secret, timestamp);
  return app.request(
    "/v1/stripe/webhook",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
      body: payload,
    },
    runtime,
  );
}

export function machine(char: string): string {
  return char.repeat(64);
}

export function keyFromEmail(text: string): string {
  const match = text.match(/[A-Z0-9]{2,12}(?:-[0-9A-HJKMNP-TV-Z]{5}){4}/);
  if (!match) throw new Error(`no key in email: ${text}`);
  return match[0];
}

export async function issueKey(
  app: ReturnType<typeof handler>,
  seeded: SeededApp,
  opts: {
    sessionId: string;
    paymentIntent?: string | null;
    email?: string;
    maxMachines?: string;
    metadata?: Record<string, string> | null;
  },
): Promise<string> {
  const before = emails.length;
  const payload = checkoutPayload({
    sessionId: opts.sessionId,
    paymentIntent: opts.paymentIntent,
    email: opts.email,
    metadata:
      opts.metadata === null
        ? null
        : opts.metadata ?? { app: seeded.slug, max_machines: opts.maxMachines ?? "2" },
  });
  const res = await postWebhook(app, seeded.env, payload);
  if (res.status !== 200) throw new Error(`webhook ${res.status}: ${await res.text()}`);
  const sent = emails.slice(before);
  if (sent.length === 0) throw new Error("expected a license email");
  return keyFromEmail(sent.map((message) => message.text).join("\n"));
}

export async function postJson(app: ReturnType<typeof handler>, runtime: Env, path: string, body: unknown, ip = "203.0.113.10"): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await app.request(
    path,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "cf-connecting-ip": ip },
      body: JSON.stringify(body),
    },
    runtime,
  );
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

export function num(value: unknown): number {
  return Number(value ?? 0);
}
