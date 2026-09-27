"use server";

import { redirect } from "next/navigation";

import { createCheckoutSession, createPortalSession } from "@/lib/api/client";
import type { ActionState } from "@/lib/action-state";
import { isAllowedStripeUrl } from "@/lib/billing";
import { getSessionState } from "@/lib/session";

async function authenticatedToken(returnPath: string): Promise<string | null> {
  const session = await getSessionState();
  if (session.state === "authenticated") return session.token;
  if (session.state === "missing" || session.state === "invalid") {
    redirect(`/sign-in?next=${encodeURIComponent(returnPath)}`);
  }
  return null;
}

export async function startCheckoutAction(
  _previousState: ActionState,
  _formData: FormData,
): Promise<ActionState> {
  void _previousState;
  void _formData;
  const token = await authenticatedToken("/start-trial");
  if (token === null) {
    return { status: "error", message: "Your session is unavailable. Sign in again to continue." };
  }

  const checkout = await createCheckoutSession(token);
  if (!checkout.ok) {
    if (checkout.kind === "unauthorized") redirect("/sign-in?next=%2Fstart-trial");
    const message =
      checkout.kind === "conflict"
        ? "Checkout cannot start for the current billing state. Review billing or contact support."
        : checkout.kind === "forbidden"
          ? "Only the billing owner can start checkout for this workspace."
        : "Checkout is unavailable. No payment details were collected.";
    return { status: "error", message };
  }
  if (!isAllowedStripeUrl(checkout.data.url, "checkout")) {
    return { status: "error", message: "Checkout returned an invalid destination and was blocked." };
  }
  redirect(checkout.data.url);
}

export async function openPortalAction(
  _previousState: ActionState,
  _formData: FormData,
): Promise<ActionState> {
  void _previousState;
  void _formData;
  const token = await authenticatedToken("/app/settings/billing");
  if (token === null) {
    return { status: "error", message: "Your session is unavailable. Sign in again to continue." };
  }

  const portal = await createPortalSession(token);
  if (!portal.ok) {
    if (portal.kind === "unauthorized") {
      redirect("/sign-in?next=%2Fapp%2Fsettings%2Fbilling");
    }
    const message =
      portal.kind === "conflict"
        ? "Billing management is not available for the current account state."
        : portal.kind === "forbidden"
          ? "Only the billing owner can manage this subscription."
        : "The billing portal is temporarily unavailable. Please try again shortly.";
    return { status: "error", message };
  }
  if (!isAllowedStripeUrl(portal.data.url, "portal")) {
    return { status: "error", message: "The portal returned an invalid destination and was blocked." };
  }
  redirect(portal.data.url);
}
