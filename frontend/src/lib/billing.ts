import type { BillingStatus, BillingStatusValue } from "@/lib/api/schemas";

const ENTITLED_STATES: ReadonlySet<BillingStatusValue> = new Set([
  "trialing",
  "active",
]);

export type BillingDecision =
  | "contact-support"
  | "manage-billing"
  | "open-app"
  | "start-checkout";

export function hasProductAccess(billing: BillingStatus, now = new Date()): boolean {
  return !billing.billingRequired || hasEntitledAccess(billing, now);
}

export function hasEntitledAccess(billing: BillingStatus, now = new Date()): boolean {
  if (!billing.entitled || !ENTITLED_STATES.has(billing.status) || billing.entitlementEnd === null) {
    return false;
  }
  return Date.parse(billing.entitlementEnd) > now.getTime();
}

export function decideBillingNextStep(billing: BillingStatus): BillingDecision {
  if (hasProductAccess(billing)) {
    return "open-app";
  }
  if (billing.checkoutAvailable) {
    return "start-checkout";
  }
  return billing.portalAvailable ? "manage-billing" : "contact-support";
}

export function billingStatusLabel(status: BillingStatusValue): string {
  return status.replaceAll("_", " ");
}

export function isAllowedStripeUrl(value: string, destination: "checkout" | "portal"): boolean {
  try {
    const url = new URL(value);
    const expectedHost = destination === "checkout" ? "checkout.stripe.com" : "billing.stripe.com";
    return (
      url.protocol === "https:" &&
      url.hostname === expectedHost &&
      url.port === "" &&
      url.username === "" &&
      url.password === ""
    );
  } catch {
    return false;
  }
}
