import { Hono, type Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import {
  adminAuthorized,
  createApp,
  deleteActivation,
  listActivations,
  listApps,
  listLicenses,
  patchApp,
  revokeLicense,
  stats,
} from "./admin";
import { sendEmail as defaultSendEmail } from "./email";
import { handleChargeRefunded, handleCheckoutCompleted, handleDisputeCreated } from "./issue";
import { HttpError, activate, confirmReset, deactivate, recover, requestReset, startTrial, validate } from "./licensing";
import { getAppBySlug } from "./db";
import { hitLimit, limits } from "./rate-limit";
import { verifyStripeSignature } from "./stripe";
import type { AppDeps, Env } from "./types";
import { clientIp, jsonError, readJson, sha256Hex, str } from "./util";

async function guarded(
  c: { json: (body: unknown, status?: number) => Response },
  fn: () => Promise<Record<string, unknown>>,
): Promise<Response> {
  try {
    return c.json(await fn());
  } catch (error) {
    if (error instanceof HttpError) return c.json({ error: error.code, ...error.extra }, error.status);
    throw error;
  }
}

export function createAppHandler(deps: AppDeps = {}) {
  const send = deps.sendEmail ?? defaultSendEmail;
  const nowFn = deps.now ?? (() => new Date());
  const app = new Hono<{ Bindings: Env }>();

  app.onError((error, c) => {
    console.log(JSON.stringify({ event: "unhandled", error: String(error) }));
    return c.json({ error: "internal" }, 500);
  });

  app.get("/health", (c) => c.json({ ok: true }));

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
    const now = nowFn();
    if (event.type === "checkout.session.completed") {
      const result = await handleCheckoutCompleted(c.env, send, object, ip, now);
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

  app.use("/v1/:app/*", async (c, next) => {
    const lim = limits(c.env);
    const blocked = await hitLimit(c.env.DB, `ip:${clientIp(c)}`, lim.ipPerMin, 60, nowFn());
    if (blocked) return jsonError(c, 429, "rate_limited");
    await next();
  });

  async function load(c: Context<{ Bindings: Env }>) {
    const slug = c.req.param("app") ?? "";
    const row = await getAppBySlug(c.env.DB, slug);
    if (!row) return { error: jsonError(c, 404, "app_not_found") };
    if (row.status !== "active") return { error: jsonError(c, 403, "app_disabled") };
    return { app: row };
  }

  app.post("/v1/:app/trial", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    return guarded(c, () =>
      startTrial({ env: c.env, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/activate", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const lim = limits(c.env);
    const ipBlocked = await hitLimit(
      c.env.DB,
      `activate-ip:${clientIp(c)}`,
      lim.activateIpPerMin,
      60,
      nowFn(),
    );
    if (ipBlocked) return jsonError(c, 429, "rate_limited");
    const rawKey = str(body.body.key, 80) ?? "";
    const keyBlocked = await hitLimit(
      c.env.DB,
      `activate-raw:${await sha256Hex(rawKey.toUpperCase())}`,
      lim.activateKeyPerMin,
      60,
      nowFn(),
    );
    if (keyBlocked) return jsonError(c, 429, "rate_limited");
    return guarded(c, () =>
      activate({ env: c.env, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/validate", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    return guarded(c, () =>
      validate({ env: c.env, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/deactivate", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    return guarded(c, () =>
      deactivate({ env: c.env, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/recover", async (c) => {
    const row = await getAppBySlug(c.env.DB, c.req.param("app") ?? "");
    if (!row) return jsonError(c, 404, "app_not_found");
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const lim = limits(c.env);
    const blocked = await hitLimit(c.env.DB, `recover-ip:${clientIp(c)}`, lim.recoverIpPerMin, 60, nowFn());
    if (blocked) return jsonError(c, 429, "rate_limited");
    if (row.status !== "active") {
      return c.json({ ok: true, message: "If a license exists for this email, it has been sent." });
    }
    return guarded(c, () =>
      recover({ env: c.env, send, app: row, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/reset-machines/request", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const lim = limits(c.env);
    const blocked = await hitLimit(c.env.DB, `reset-ip:${clientIp(c)}`, lim.resetIpPerMin, 60, nowFn());
    if (blocked) return jsonError(c, 429, "rate_limited");
    return guarded(c, () =>
      requestReset({ env: c.env, send, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.post("/v1/:app/reset-machines/confirm", async (c) => {
    const loaded = await load(c);
    if ("error" in loaded && loaded.error) return loaded.error;
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const lim = limits(c.env);
    const blocked = await hitLimit(c.env.DB, `reset-ip:${clientIp(c)}`, lim.resetIpPerMin, 60, nowFn());
    if (blocked) return jsonError(c, 429, "rate_limited");
    return guarded(c, () =>
      confirmReset({ env: c.env, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
    );
  });

  app.use("/admin/*", async (c, next) => {
    if (!(await adminAuthorized(c.env, c.req.header("authorization")))) {
      return jsonError(c, 401, "unauthorized");
    }
    await next();
  });

  app.post("/admin/apps", async (c) => {
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const result = await createApp(c.env, body.body, nowFn());
    return c.json(result.body, result.status);
  });

  app.get("/admin/apps", async (c) => c.json({ apps: await listApps(c.env) }));

  app.patch("/admin/apps/:slug", async (c) => {
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const result = await patchApp(c.env, c.req.param("slug") ?? "", body.body);
    return c.json(result.body, result.status);
  });

  app.get("/admin/licenses", async (c) => {
    const result = await listLicenses(c.env, new URL(c.req.url), nowFn());
    return c.json(result.body, result.status);
  });

  app.post("/admin/licenses/:id/revoke", async (c) => {
    const id = Number(c.req.param("id"));
    if (!Number.isInteger(id) || id < 1) return jsonError(c, 400, "invalid_id");
    const result = await revokeLicense(c.env, id, clientIp(c), nowFn());
    return c.json(result.body, result.status);
  });

  app.get("/admin/activations", async (c) => {
    const result = await listActivations(c.env, new URL(c.req.url));
    return c.json(result.body, result.status);
  });

  app.delete("/admin/activations/:id", async (c) => {
    const id = Number(c.req.param("id"));
    if (!Number.isInteger(id) || id < 1) return jsonError(c, 400, "invalid_id");
    const result = await deleteActivation(c.env, id, clientIp(c), nowFn());
    return c.json(result.body, result.status);
  });

  app.get("/admin/stats", async (c) => {
    const result = await stats(c.env, new URL(c.req.url), nowFn());
    return c.json(result.body, result.status);
  });

  return app;
}
