import { timingSafeEqual } from "./util";

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Stripe webhook signature, HMAC-SHA256 over `${timestamp}.${rawBody}` with the signing secret. */
export async function verifyStripeSignature(
  payload: string,
  header: string | undefined,
  secret: string | undefined,
  nowSec = Math.floor(Date.now() / 1000),
  toleranceSec = 300,
): Promise<boolean> {
  if (!header || !secret) return false;
  let timestamp = "";
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === "t") timestamp = v;
    else if (k === "v1" && v && signatures.length < 5) signatures.push(v.toLowerCase());
  }
  if (!/^\d+$/.test(timestamp) || signatures.length === 0) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(nowSec - ts) > toleranceSec) return false;
  const expected = await hmacHex(secret, `${timestamp}.${payload}`);
  let ok = false;
  for (const sig of signatures) {
    if (timingSafeEqual(sig, expected)) ok = true;
  }
  return ok;
}

export function stripeId(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (value && typeof value === "object" && "id" in value) {
    const id = (value as { id?: unknown }).id;
    if (typeof id === "string" && id.trim()) return id.trim();
  }
  return null;
}

export interface ParsedCheckout {
  sessionId: string;
  paymentIntent: string | null;
  email: string | null;
  app: string | null;
  maxMachinesRaw: unknown;
}

export function parseCheckout(object: Record<string, unknown>): ParsedCheckout {
  const details = object.customer_details;
  let email: string | null = null;
  if (details && typeof details === "object" && "email" in details) {
    const value = (details as { email?: unknown }).email;
    if (typeof value === "string") email = value;
  }
  if (!email && typeof object.customer_email === "string") email = object.customer_email;
  const metadata =
    object.metadata && typeof object.metadata === "object"
      ? (object.metadata as Record<string, unknown>)
      : {};
  return {
    sessionId: typeof object.id === "string" ? object.id : "",
    paymentIntent: stripeId(object.payment_intent),
    email: email?.trim().toLowerCase() || null,
    app: typeof metadata.app === "string" ? metadata.app.trim().toLowerCase() : null,
    maxMachinesRaw: metadata.max_machines,
  };
}

export function isFullRefund(object: Record<string, unknown>): boolean {
  if (object.refunded === true) return true;
  const amount = typeof object.amount === "number" ? object.amount : null;
  const refunded = typeof object.amount_refunded === "number" ? object.amount_refunded : null;
  if (amount === null || refunded === null) return false;
  return amount > 0 && refunded >= amount;
}
