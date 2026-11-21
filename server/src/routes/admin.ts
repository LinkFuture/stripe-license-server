import type { Hono } from "hono";
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
} from "../lib/admin";
import type { Env } from "../lib/types";
import { clientIp, jsonError, readJson } from "../lib/util";

function scoped(url: string, app: string): URL {
  const next = new URL(url);
  next.searchParams.set("app", app);
  return next;
}

export function mountAdminRoutes(app: Hono<{ Bindings: Env }>, deps: { now: () => Date }): void {
  const nowFn = deps.now;

  app.use("/api/admin/*", async (c, next) => {
    if (!(await adminAuthorized(c.env, c.req.header("authorization")))) {
      return jsonError(c, 401, "unauthorized");
    }
    await next();
  });
  app.use("/api/:app/admin/*", async (c, next) => {
    if (!(await adminAuthorized(c.env, c.req.header("authorization")))) {
      return jsonError(c, 401, "unauthorized");
    }
    await next();
  });

  app.post("/api/admin/apps", async (c) => {
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const result = await createApp(c.env, body.body, nowFn());
    return c.json(result.body, result.status);
  });

  app.get("/api/admin/apps", async (c) => c.json({ apps: await listApps(c.env) }));

  app.patch("/api/admin/apps/:slug", async (c) => {
    const body = await readJson(c);
    if (!body.ok) return jsonError(c, 400, "invalid_json");
    const result = await patchApp(c.env, c.req.param("slug") ?? "", body.body);
    return c.json(result.body, result.status);
  });

  app.get("/api/:app/admin/licenses", async (c) => {
    const result = await listLicenses(c.env, scoped(c.req.url, c.req.param("app") ?? ""), nowFn());
    return c.json(result.body, result.status);
  });

  app.post("/api/:app/admin/licenses/:id/revoke", async (c) => {
    const id = Number(c.req.param("id"));
    if (!Number.isInteger(id) || id < 1) return jsonError(c, 400, "invalid_id");
    const result = await revokeLicense(c.env, id, clientIp(c), nowFn(), c.req.param("app") ?? "");
    return c.json(result.body, result.status);
  });

  app.get("/api/:app/admin/activations", async (c) => {
    const result = await listActivations(c.env, scoped(c.req.url, c.req.param("app") ?? ""));
    return c.json(result.body, result.status);
  });

  app.delete("/api/:app/admin/activations/:id", async (c) => {
    const id = Number(c.req.param("id"));
    if (!Number.isInteger(id) || id < 1) return jsonError(c, 400, "invalid_id");
    const result = await deleteActivation(c.env, id, clientIp(c), nowFn(), c.req.param("app") ?? "");
    return c.json(result.body, result.status);
  });

  app.get("/api/:app/admin/stats", async (c) => {
    const result = await stats(c.env, scoped(c.req.url, c.req.param("app") ?? ""), nowFn());
    return c.json(result.body, result.status);
  });
}
