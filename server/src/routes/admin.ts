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

export function mountAdminRoutes(app: Hono<{ Bindings: Env }>, deps: { now: () => Date }): void {
  const nowFn = deps.now;

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
}
