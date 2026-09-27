import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { openPortalAction } from "@/actions/billing";
import { BillingActionForm } from "@/components/billing-action-form";
import { fetchBillingStatus } from "@/lib/api/client";
import { billingStatusLabel, decideBillingNextStep, hasProductAccess } from "@/lib/billing";
import { formatDateTime } from "@/lib/format";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Billing settings",
  description: "Review verified subscription state and open Stripe-hosted billing management.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export default async function BillingSettingsPage() {
  const session = await requireSession("/app/settings/billing");
  if (session.state === "unavailable") {
    return <BillingUnavailable detail="Identity verification is unavailable. Billing controls remain disabled." />;
  }

  const result = await fetchBillingStatus(session.token);
  if (!result.ok && (result.kind === "unauthorized" || result.kind === "forbidden")) {
    redirect("/sign-in?next=%2Fapp%2Fsettings%2Fbilling");
  }
  if (!result.ok) {
    return <BillingUnavailable detail="The billing API did not return a valid subscription state." />;
  }

  const billing = result.data;
  const hasAccess = hasProductAccess(billing);
  const nextStep = decideBillingNextStep(billing);
  return (
    <main className="app-main" id="main-content">
      <div className="settings-heading">
        <p className="eyebrow">Account settings</p>
        <h1>Billing</h1>
        <p>Subscription access is based on the backend projection of verified Stripe events.</p>
      </div>
      <section className="billing-settings-card" aria-labelledby="subscription-heading">
        <div>
          <p className="card-kicker">Verified state</p>
          <h2 id="subscription-heading" className="capitalize">{billingStatusLabel(billing.status)}</h2>
          <span className={`status-chip ${hasAccess ? "status-chip--good" : "status-chip--warn"}`}>
            {hasAccess ? "Product access available" : "Access not entitled"}
          </span>
        </div>
        <dl className="definition-list">
          <div><dt>Trial started</dt><dd>{formatDateTime(billing.trialStartedAt)}</dd></div>
          <div><dt>Trial ends</dt><dd>{formatDateTime(billing.trialEnd)}</dd></div>
          <div><dt>Entitlement ends</dt><dd>{formatDateTime(billing.entitlementEnd)}</dd></div>
          <div><dt>Cancel at period end</dt><dd>{billing.cancelAtPeriodEnd ? "Yes" : "No"}</dd></div>
          <div><dt>Billing required</dt><dd>{billing.billingRequired ? "Yes" : "No, self-hosted mode"}</dd></div>
        </dl>
        <div className="billing-settings-card__action">
          {!billing.billingRequired ? (
            <Link className="button button--primary" href="/app">Return to workspace</Link>
          ) : nextStep === "start-checkout" ? (
            <Link className="button button--primary" href="/start-trial">Review Team offer</Link>
          ) : nextStep === "manage-billing" ? (
            <BillingActionForm
              action={openPortalAction}
              label="Open Stripe billing portal"
              pendingLabel="Opening secure portal..."
              secondary
            />
          ) : (
            <a className="button button--secondary" href="mailto:commercial@vorsyghta.io?subject=Billing%20state%20review">Contact support</a>
          )}
          <p>Payment details are collected and managed on Stripe-hosted pages, not by this frontend.</p>
        </div>
      </section>
    </main>
  );
}

function BillingUnavailable({ detail }: { detail: string }) {
  return (
    <main className="centered-state centered-state--app" id="main-content">
      <p className="eyebrow">Billing unavailable</p>
      <h1>Subscription state cannot be verified.</h1>
      <p>{detail}</p>
      <div className="button-row">
        <Link className="button button--light" href="/start-trial">Review trial</Link>
        <a className="button button--outline-dark" href="mailto:commercial@vorsyghta.io">Contact commercial</a>
      </div>
    </main>
  );
}
