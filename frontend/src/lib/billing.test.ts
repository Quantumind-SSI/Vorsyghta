import { describe, expect, it } from "vitest";

import { billingStatusSchema } from "@/lib/api/schemas";
import {
  billingStatusLabel,
  decideBillingNextStep,
  hasEntitledAccess,
  hasProductAccess,
  isAllowedStripeUrl,
} from "@/lib/billing";

function status(
  value: string,
  entitled: boolean,
  billingRequired = true,
  checkoutAvailable = value === "checkout_pending" || value === "unknown",
  portalAvailable = !checkoutAvailable,
) {
  return billingStatusSchema.parse({
    status: value,
    entitled,
    billing_required: billingRequired,
    trial_available: true,
    checkout_available: checkoutAvailable,
    portal_available: portalAvailable,
    trial_started_at: null,
    trial_ends_at: null,
    entitlement_ends_at: entitled ? "2999-01-01T00:00:00Z" : null,
    cancel_at_period_end: false,
  });
}

describe("billing state decisions", () => {
  it("grants application access only for entitled access states", () => {
    expect(hasEntitledAccess(status("trialing", true))).toBe(true);
    expect(hasEntitledAccess(status("active", true))).toBe(true);
    expect(hasEntitledAccess(status("active", false))).toBe(false);
    expect(hasEntitledAccess({ ...status("active", true), status: "canceled" })).toBe(false);
    expect(
      hasEntitledAccess(status("active", true), new Date("2999-01-01T00:00:00Z")),
    ).toBe(false);
  });

  it("selects checkout or management without granting access", () => {
    expect(hasProductAccess(status("unknown", false, false))).toBe(true);
    expect(decideBillingNextStep(status("unknown", false, false))).toBe("open-app");
    expect(decideBillingNextStep(status("unknown", false))).toBe("start-checkout");
    expect(decideBillingNextStep(status("checkout_pending", false))).toBe("start-checkout");
    expect(decideBillingNextStep(status("incomplete", false))).toBe("manage-billing");
    expect(decideBillingNextStep(status("canceled", false, true, true, true))).toBe("start-checkout");
    expect(decideBillingNextStep(status("past_due", false))).toBe("manage-billing");
    expect(decideBillingNextStep(status("active", true))).toBe("open-app");
    expect(decideBillingNextStep(status("unknown", false, true, false, false))).toBe("contact-support");
  });

  it("formats API status values for people", () => {
    expect(billingStatusLabel("incomplete_expired")).toBe("incomplete expired");
  });
});

describe("Stripe hosted URL policy", () => {
  it("allows only the expected HTTPS host for each destination", () => {
    expect(isAllowedStripeUrl("https://checkout.stripe.com/c/pay/cs_test_123", "checkout")).toBe(true);
    expect(isAllowedStripeUrl("https://billing.stripe.com/p/session/test_123", "portal")).toBe(true);
    expect(isAllowedStripeUrl("https://checkout.stripe.com.evil.example/path", "checkout")).toBe(false);
    expect(isAllowedStripeUrl("http://checkout.stripe.com/path", "checkout")).toBe(false);
    expect(isAllowedStripeUrl("https://checkout.stripe.com:444/path", "checkout")).toBe(false);
    expect(isAllowedStripeUrl("https://user@billing.stripe.com/path", "portal")).toBe(false);
  });
});
