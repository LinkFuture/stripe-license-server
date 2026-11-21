import type { Context, Hono } from "hono";
import { getAppBySlug } from "../lib/db";
import {
  HttpError,
  activate,
  confirmReset,
  deactivate,
  recover,
  requestReset,
  startTrial,
  validate,
} from "../lib/licensing";
import { hitLimit, limits } from "../lib/rate-limit";
import type { Env, SendEmail } from "../lib/types";
import { clientIp, jsonError, readJson, sha256Hex, str } from "../lib/util";

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

async function load(c: Context<{ Bindings: Env }>) {
  const slug = c.req.param("app") ?? "";
  const row = await getAppBySlug(c.env.DB, slug);
  if (!row) return { error: jsonError(c, 404, "app_not_found") };
  if (row.status !== "active") return { error: jsonError(c, 403, "app_disabled") };
  return { app: row };
}

export function mountPublicRoutes(
  app: Hono<{ Bindings: Env }>,
  deps: { send: SendEmail; now: () => Date },
): void {
  const nowFn = deps.now;

  app.use("/v1/:app/*", async (c, next) => {
    const lim = limits(c.env);
    const blocked = await hitLimit(c.env.DB, `ip:${clientIp(c)}`, lim.ipPerMin, 60, nowFn());
    if (blocked) return jsonError(c, 429, "rate_limited");
    await next();
  });

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
      recover({ env: c.env, send: deps.send, app: row, body: body.body, ip: clientIp(c), now: nowFn() }),
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
      requestReset({ env: c.env, send: deps.send, app: loaded.app, body: body.body, ip: clientIp(c), now: nowFn() }),
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
}
