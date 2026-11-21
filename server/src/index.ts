import { Hono } from "hono";
import { sendEmail as defaultSendEmail } from "./lib/email";
import type { AppDeps, Env } from "./lib/types";
import { mountAdminRoutes } from "./routes/admin";
import { mountLicenseRoutes } from "./routes/licenses";
import { mountStripeRoutes } from "./routes/stripe";

export function createAppHandler(deps: AppDeps = {}) {
  const send = deps.sendEmail ?? defaultSendEmail;
  const now = deps.now ?? (() => new Date());
  const app = new Hono<{ Bindings: Env }>();

  app.onError((error, c) => {
    console.log(JSON.stringify({ event: "unhandled", error: String(error) }));
    if (error instanceof Error && error.message === "issuer_not_configured") {
      return c.json({ error: "issuer_not_configured" }, 500);
    }
    return c.json({ error: "internal" }, 500);
  });

  app.get("/api/health", (c) => c.json({ ok: true }));

  mountStripeRoutes(app, { send, now });
  mountLicenseRoutes(app, { send, now });
  mountAdminRoutes(app, { now });

  return app;
}

export default createAppHandler();
