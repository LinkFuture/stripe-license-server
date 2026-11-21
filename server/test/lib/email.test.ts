import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { licenseEmail, resetCodeEmail, sendEmail } from "../../src/lib/email";
import { resetDb } from "../helpers/fixtures";

beforeEach(async () => {
  await resetDb();
});

describe("email", () => {
  it("skips, sends, and reports Resend failures", async () => {
    expect(licenseEmail("App", ["A", "B"])).toContain("keys");
    expect(licenseEmail("App", ["A"])).toContain("Your license key for App");
    expect(resetCodeEmail("App", "123456")).toContain("123456");
    await expect(sendEmail(env, { from: "", to: "a@b.co", subject: "s", text: "t" })).rejects.toThrow("mail_from_unset");
    const original = globalThis.fetch;
    try {
      await sendEmail({ ...env, RESEND_API_KEY: "" }, { from: "App <a@b.co>", to: "a@b.co", subject: "s", text: "t" });
      let body: Record<string, unknown> = {};
      globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;
      await sendEmail(env, { from: "App <a@b.co>", replyTo: "r@b.co", to: "a@b.co", subject: "s", text: "t" });
      expect(body.reply_to).toBe("r@b.co");
      globalThis.fetch = (async () => new Response("nope-body", { status: 500 })) as typeof fetch;
      await expect(sendEmail(env, { from: "App <a@b.co>", to: "a@b.co", subject: "s", text: "t" })).rejects.toThrow(/resend_500/);
    } finally {
      globalThis.fetch = original;
    }
  });
});
