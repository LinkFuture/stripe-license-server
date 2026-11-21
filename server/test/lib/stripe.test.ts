import { beforeEach, describe, expect, it } from "vitest";
import { isFullRefund, parseCheckout, stripeId, verifyStripeSignature } from "../../src/lib/stripe";
import { resetDb, stripeSignature } from "../helpers/fixtures";

beforeEach(async () => {
  await resetDb();
});

describe("stripe helpers", () => {
  it("rejects bad signatures and parses checkout objects", async () => {
    const payload = "{\"id\":\"cs_1\"}";
    const now = 1_700_000_000;
    const header = await stripeSignature(payload, "whsec_test_secret", now);
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret", now)).toBe(true);
    expect(await verifyStripeSignature(payload, undefined, "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, header, undefined, now)).toBe(false);
    expect(await verifyStripeSignature(payload, "noequals", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, "t=abc,v1=aa", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, "t=1", "whsec_test_secret", now)).toBe(false);
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret", now + 10_000)).toBe(false);
    expect(await verifyStripeSignature(payload, `t=${"9".repeat(400)},v1=ab`, "whsec_test_secret", now)).toBe(false);
    const extras = Array.from({ length: 6 }, () => "v1=abcd").join(",");
    expect(await verifyStripeSignature(payload, `t=${now},${extras}`, "whsec_test_secret", now)).toBe(false);
    const wrong = header.replace(/v1=([0-9a-f]+)/, (_m, hex: string) => `v1=${"0".repeat(hex.length)}`);
    expect(await verifyStripeSignature(payload, `${wrong},v1=abcd`, "whsec_test_secret", now)).toBe(false);
    expect(stripeId("  pi_1  ")).toBe("pi_1");
    expect(stripeId("")).toBeNull();
    expect(stripeId({ id: " pi_2 " })).toBe("pi_2");
    expect(stripeId({ id: "  " })).toBeNull();
    expect(stripeId({ nope: 1 })).toBeNull();
    expect(stripeId(null)).toBeNull();
    const parsed = parseCheckout({
      id: "cs_9",
      customer_details: { email: " Buyer@Example.com " },
      payment_intent: { id: "pi_9" },
      metadata: { app: " MyApp ", max_machines: "2" },
    });
    expect(parsed).toMatchObject({ sessionId: "cs_9", email: "buyer@example.com", app: "myapp", paymentIntent: "pi_9" });
    expect(parseCheckout({ customer_email: "a@b.co", metadata: "nope" }).email).toBe("a@b.co");
    expect(parseCheckout({ customer_details: { email: 1 } }).email).toBeNull();
    expect(parseCheckout({}).sessionId).toBe("");
    expect(isFullRefund({ refunded: true })).toBe(true);
    expect(isFullRefund({ amount: "2", amount_refunded: 2 })).toBe(false);
    expect(isFullRefund({ amount: 0, amount_refunded: 0 })).toBe(false);
    expect(isFullRefund({ amount: 5, amount_refunded: 5 })).toBe(true);
    expect(isFullRefund({ amount: 5 })).toBe(false);
  });
});

describe("stripe signatures", () => {
it("accepts a current stripe signature and rejects a wrong secret", async () => {
    const payload = "{\"ok\":true}";
    const header = await stripeSignature(payload, "whsec_test_secret");
    expect(await verifyStripeSignature(payload, header, "whsec_test_secret")).toBe(true);
    expect(await verifyStripeSignature(payload, header, "whsec_other")).toBe(false);
  });
});
