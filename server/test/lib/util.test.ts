import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import type { Env } from "../../src/lib/types";
import {
  addDays,
  appPrivateKey,
  b64ToBytes,
  bytesToB64,
  clamp,
  clientIp,
  emailOk,
  extendEnv,
  intEnv,
  jsonError,
  licenseIssuer,
  likeContains,
  machineHashOk,
  normalizeMachineHash,
  nowIso,
  pageParams,
  parseMailFrom,
  parsePositiveInt,
  pemFromBuffer,
  readJson,
  resolveMailFrom,
  resolveReplyTo,
  sha256Hex,
  str,
  timingSafeEqual,
  timingSafeEqualHash,
} from "../../src/lib/util";
import { resetDb } from "../helpers/fixtures";

const NOW = new Date("2026-06-01T00:00:00.000Z");

function headerContext(headers: Record<string, string | undefined>) {
  return {
    req: {
      header(name: string) {
        return headers[name.toLowerCase()];
      },
    },
  } as Parameters<typeof clientIp>[0];
}

beforeEach(async () => {
  await resetDb();
});

describe("util", () => {
  it("covers parsing, mail, paging, and comparisons", async () => {
    expect(nowIso()).toContain("T");
    expect(nowIso(NOW)).toBe("2026-06-01T00:00:00.000Z");
    expect(str("hello")).toBe("hello");
    expect(addDays(NOW, 1)).toBe("2026-06-02T00:00:00.000Z");
    expect(addDays("2026-06-01T00:00:00.000Z", 2)).toContain("2026-06-03");
    expect(intEnv(undefined, 3)).toBe(3);
    expect(intEnv("", 3)).toBe(3);
    expect(intEnv("nope", 3)).toBe(3);
    expect(intEnv("4.9", 3)).toBe(4);
    expect(clientIp(headerContext({ "cf-connecting-ip": " 1.1.1.1 " }))).toBe("1.1.1.1");
    expect(clientIp(headerContext({ "x-forwarded-for": "2.2.2.2, 3.3.3.3" }))).toBe("2.2.2.2");
    expect(clientIp(headerContext({ "x-forwarded-for": "," }))).toBe("unknown");
    expect(clientIp(headerContext({}))).toBe("unknown");
    const response = jsonError(
      { json: (body: unknown, status?: number) => new Response(JSON.stringify(body), { status }) } as never,
      400,
      "bad",
      { extra: 1 },
    );
    expect(await response.json()).toMatchObject({ error: "bad", extra: 1 });
    const good = await readJson({ req: { json: async () => ({ a: 1 }) } } as never);
    const arrayBody = await readJson({ req: { json: async () => [] } } as never);
    const broken = await readJson({ req: { json: async () => { throw new Error("x"); } } } as never);
    expect(good.ok && good.body.a).toBe(1);
    expect(arrayBody.ok).toBe(false);
    expect(broken.ok).toBe(false);
    expect(str(1, 4)).toBeNull();
    expect(str("  ", 4)).toBeNull();
    expect(str("abcdef", 3)).toBe("abc");
    expect(clamp(null, 2)).toBeNull();
    expect(clamp("abcd", 2)).toBe("ab");
    expect(parseMailFrom("")).toBeNull();
    expect(parseMailFrom("a@b.com\ncc")).toBeNull();
    expect(parseMailFrom("x".repeat(201))).toBeNull();
    expect(parseMailFrom('"Desk" <desk@example.com>')).toBe("Desk <desk@example.com>");
    expect(parseMailFrom("<> <a@b.com>")).toBeNull();
    expect(parseMailFrom(`${"n".repeat(81)} <a@b.com>`)).toBeNull();
    expect(parseMailFrom('bad"name <a@b.com>')).toBeNull();
    expect(parseMailFrom("Name <not-an-email>")).toBeNull();
    expect(parseMailFrom("not-an-email")).toBeNull();
    expect(parseMailFrom("bare@example.com")).toBe("bare@example.com");
    expect(licenseIssuer({} as Env)).toBeNull();
    expect(licenseIssuer({ LICENSE_ISSUER: "  iss  " } as Env)).toBe("iss");
    expect(resolveMailFrom({ MAIL_FROM: "bad" } as Env, "  ")).toBeNull();
    expect(resolveMailFrom({ MAIL_FROM: "ok@example.com" } as Env, "Nope")).toBeNull();
    expect(resolveMailFrom({ MAIL_FROM: "ok@example.com" } as Env, null)).toBe("ok@example.com");
    expect(resolveReplyTo({} as Env)).toBeNull();
    expect(resolveReplyTo({ MAIL_REPLY_TO: "nope" } as Env)).toBeNull();
    expect(appPrivateKey(env, "missing")).toBeUndefined();
    expect(appPrivateKey(extendEnv(env, { APP_KEY_MYAPP: "   " }), "myapp")).toBeUndefined();
    expect(appPrivateKey(extendEnv(env, { APP_KEY_MYAPP: "pem" }), "myapp")).toBe("pem");
    const proxied = extendEnv(env, { MAIL_FROM: undefined, EXTRA: "x" });
    expect(proxied.MAIL_FROM).toBe(env.MAIL_FROM);
    expect((proxied as Env & { EXTRA: string }).EXTRA).toBe("x");
    expect(await sha256Hex("abc")).toHaveLength(64);
    expect(timingSafeEqual("ab", "a")).toBe(false);
    expect(timingSafeEqual("ab", "ab")).toBe(true);
    expect(await timingSafeEqualHash("a", "b")).toBe(false);
    expect(await timingSafeEqualHash("a", "a")).toBe(true);
    expect(pemFromBuffer("TEST", new ArrayBuffer(0))).toContain("BEGIN TEST");
    expect(pemFromBuffer("TEST", new Uint8Array(80).buffer)).toContain("\n");
    expect(b64ToBytes(bytesToB64(new Uint8Array([1, 2, 3])))).toEqual(new Uint8Array([1, 2, 3]));
    expect(machineHashOk("AB".repeat(32))).toBe(true);
    expect(machineHashOk("zz")).toBe(false);
    expect(normalizeMachineHash("AB")).toBe("ab");
    expect(parsePositiveInt(true)).toBeNull();
    expect(parsePositiveInt("")).toBeNull();
    expect(parsePositiveInt("1.5")).toBeNull();
    expect(parsePositiveInt(0)).toBeNull();
    expect(parsePositiveInt("2")).toBe(2);
    expect(emailOk(`${"a".repeat(320)}@b.co`)).toBe(false);
    expect(emailOk("a@b.co")).toBe(true);
    expect(likeContains("100%_\\x")).toBe("%100\\%\\_\\\\x%");
    expect(pageParams(new URL("https://x.test/?page=0"))).toBeNull();
    expect(pageParams(new URL("https://x.test/?page=2"))).toEqual({ page: 2, perPage: 50, offset: 50 });
    expect(pageParams(new URL("https://x.test/"))).toEqual({ page: 1, perPage: 50, offset: 0 });
  });
});
