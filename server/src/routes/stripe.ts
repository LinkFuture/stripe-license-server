import type { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { handleChargeRefunded, handleCheckoutCompleted, handleDisputeCreated } from "../lib/issue";
import { verifyStripeSignature } from "../lib/stripe";
import type { Env, SendEmail } from "../lib/types";
import { clientIp, jsonError } from "../lib/util";

export function mountStripeRoutes(
  app: Hono<{ Bindings: Env }>,
  deps: { send: SendEmail; now: () => Date },
): void {
  app.post("/v1/stripe/webhook", async (c) => {
    const payload = await c.req.text();
    const header = c.req.header("stripe-signature");
    const ok = await verifyStripeSignature(payload, header, c.env.STRIPE_WEBHOOK_SECRET);
    if (!ok) return jsonError(c, 400, "invalid_signature");
    let event: { type?: string; data?: { object?: Record<string, unknown> } };
    try {
      event = JSON.parse(payload) as { type?: string; data?: { object?: Record<string, unknown> } };
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    const object = event.data?.object;
    if (!event.type || !object) return c.json({ received: true });
    const ip = clientIp(c);
    const now = deps.now();
    if (event.type === "checkout.session.completed") {
      const result = await handleCheckoutCompleted(c.env, deps.send, object, ip, now);
      return c.json({ received: true }, result.status as ContentfulStatusCode);
    }
    if (event.type === "charge.refunded") {
      await handleChargeRefunded(c.env, object, ip, now);
      return c.json({ received: true });
    }
    if (event.type === "charge.dispute.created") {
      await handleDisputeCreated(c.env, object, ip, now);
      return c.json({ received: true });
    }
    return c.json({ received: true });
  });
}
