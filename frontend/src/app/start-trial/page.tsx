import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { startCheckoutAction } from "@/actions/billing";
import { BillingActionForm } from "@/components/billing-action-form";
import { LegalLinks } from "@/components/legal-links";
import { PublicHeader } from "@/components/public-header";
import { fetchBillingOffer, fetchBillingStatus } from "@/lib/api/client";
import { billingStatusLabel, decideBillingNextStep, hasProductAccess } from "@/lib/billing";
import { formatBillingInterval, formatDateTime, formatMoney } from "@/lib/format";
import { registrationPath } from "@/lib/navigation";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Start Team trial",
  description: "Review the live Team offer and continue to Stripe-hosted Checkout.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

type TrialPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function ReturnNotice({
  state,
  reason,
  hasAccess,
  billingRequired,
}: {
  state: string | undefined;
  reason: string | undefined;
  hasAccess: boolean;
  billingRequired: boolean;
}) {
  if (state === "canceled") {
    return <p className="notice notice--warning" role="status">Checkout was canceled. Account access has not changed.</p>;
  }
  if (state === "success" && billingRequired && !hasAccess) {
    return (
      <p className="notice notice--warning" role="status">
        Checkout returned, but access remains closed until a verified Stripe event updates billing status.
      </p>
    );
  }
  if (state === "success" && billingRequired && hasAccess) {
    return <p className="notice notice--success" role="status">Billing is verified and access is active.</p>;
  }
  if (reason === "not-entitled" && !hasAccess) {
    return <p className="notice notice--warning" role="status">Workspace access requires a current entitlement.</p>;
  }
  return null;
}

export default async function StartTrialPage({ searchParams }: TrialPageProps) {
  const session = await requireSession("/start-trial");
  if (session.state === "unavailable") {
    return <TrialUnavailable message="Identity verification is unavailable. Checkout is disabled." />;
  }

  const [offerResult, statusResult, query] = await Promise.all([
    fetchBillingOffer(),
    fetchBillingStatus(session.token),
    searchParams,
  ]);
  if (!statusResult.ok && (statusResult.kind === "unauthorized" || statusResult.kind === "forbidden")) {
    redirect("/sign-in?next=%2Fstart-trial");
  }

  const offer = offerResult.ok ? offerResult.data : null;
  const amount =
    offer?.unitAmount !== null && offer?.currency
      ? formatMoney(offer.unitAmount, offer.currency)
      : null;
  const billing = statusResult.ok ? statusResult.data : null;
  const hasAccess = billing ? hasProductAccess(billing) : false;
  const accountStateKnown = billing !== null;
  const trialAvailable = billing?.trialAvailable ?? false;
  const selfHostedAccess = billing?.billingRequired === false;
  const activeTrial = billing?.status === "trialing" && hasAccess;
  const activeSubscription = billing?.status === "active" && hasAccess;
  const nextStep = billing ? decideBillingNextStep(billing) : null;
  const checkoutOffer =
    offer !== null && amount !== null && offer.interval !== null && offer.trialDays !== null
      ? { ...offer, amount, interval: offer.interval, trialDays: offer.trialDays }
      : null;

  return (
    <div className="account-shell account-shell--trial">
      <PublicHeader />
      <main className="trial-main" id="main-content">
        <div className="page-width trial-heading">
          <p className="eyebrow">Team access</p>
          <h1>
            {selfHostedAccess
              ? "Open your self-hosted workspace"
              : activeTrial
                ? "Your Team trial is active"
                : activeSubscription
                  ? "Your Team subscription is active"
              : !accountStateKnown
                ? "Review Team access"
              : trialAvailable && offer?.trialDays
              ? `Start your ${offer.trialDays}-day Team trial`
              : trialAvailable
                ? "Start your Team trial"
                : "Restart your Team subscription"}
          </h1>
          <p>
            {selfHostedAccess
              ? "This deployment does not require a Stripe subscription."
              : "Review live offer and entitlement data before leaving Vorsyghta for Stripe-hosted Checkout."}
          </p>
        </div>

        <div className="page-width trial-grid">
          <section className="trial-card" aria-labelledby="offer-heading">
            <p className="card-kicker">Live offer</p>
            <h2 id="offer-heading">Team</h2>
            {checkoutOffer ? (
              <>
                <p className="trial-price"><strong>{checkoutOffer.amount}</strong> {formatBillingInterval(checkoutOffer.interval, checkoutOffer.intervalCount)}</p>
                <dl className="definition-list">
                  <div><dt>Trial</dt><dd>{activeTrial ? `Active until ${formatDateTime(billing?.trialEnd ?? null)}` : !accountStateKnown ? "Eligibility unavailable" : trialAvailable ? `${checkoutOffer.trialDays} days` : "Already used"}</dd></div>
                  <div><dt>Due at Checkout</dt><dd>{activeTrial || activeSubscription ? "Checkout completed" : !accountStateKnown ? "Unavailable" : trialAvailable ? "No subscription charge" : "Shown by Stripe before confirmation"}</dd></div>
                  <div><dt>Payment method</dt><dd>Card required through Stripe</dd></div>
                  <div><dt>First charge</dt><dd>{activeTrial ? `Stripe attempts it at the trial end: ${formatDateTime(billing?.trialEnd ?? null)}` : activeSubscription ? "See the Stripe billing portal" : trialAvailable ? "Stripe attempts it 14 days after successful Checkout" : "Stripe attempts it when Checkout completes"}</dd></div>
                </dl>
                <p className="muted-copy">
                  Stripe Checkout shows the exact charge date and amount before card submission.
                  The subscription then renews at the disclosed cadence until canceled. Taxes may apply.
                </p>
                <p className="muted-copy">
                  OnePay-issued Mastercard cards are submitted as standard Mastercard payments
                  through Stripe; acceptance depends on Stripe, Mastercard, and the issuer.
                  Vorsyghta does not guarantee acceptance.
                </p>
              </>
            ) : (
              <div className="unavailable-block" role="status">
                <strong>Offer unavailable</strong>
                <p>The billing API did not return a configured, valid amount. Checkout is disabled.</p>
              </div>
            )}
            <LegalLinks />
          </section>

          <section className="trial-card trial-card--status" aria-labelledby="status-heading">
            <p className="card-kicker">Current account</p>
            <h2 id="status-heading">Billing status</h2>
            <ReturnNotice
              state={firstValue(query.checkout)}
              reason={firstValue(query.reason)}
              hasAccess={hasAccess}
              billingRequired={billing?.billingRequired ?? true}
            />
            {billing ? (
              <>
                <dl className="definition-list">
                  <div><dt>Status</dt><dd className="capitalize">{billingStatusLabel(billing.status)}</dd></div>
                  <div><dt>Access</dt><dd>{hasAccess ? "Available" : "Not entitled"}</dd></div>
                  <div><dt>Billing policy</dt><dd>{billing.billingRequired ? "Subscription required" : "Self-hosted access"}</dd></div>
                  <div><dt>Trial ends</dt><dd>{formatDateTime(billing.trialEnd)}</dd></div>
                  <div><dt>Entitlement ends</dt><dd>{formatDateTime(billing.entitlementEnd)}</dd></div>
                </dl>
                {nextStep === "start-checkout" && checkoutOffer ? (
                  <BillingActionForm
                    action={startCheckoutAction}
                    label={trialAvailable ? `Continue to Stripe for ${checkoutOffer.trialDays}-day trial` : "Continue to Stripe"}
                    pendingLabel="Creating secure checkout..."
                  />
                ) : null}
                {nextStep === "open-app" ? (
                  <Link className="button button--primary" href="/app">Open workspace</Link>
                ) : null}
                {nextStep === "manage-billing" ? (
                  <Link className="button button--secondary" href="/app/settings/billing">Manage billing</Link>
                ) : null}
                {nextStep === "contact-support" ? (
                  <a className="button button--secondary" href="mailto:commercial@vorsyghta.io?subject=Billing%20state%20review">Contact support</a>
                ) : null}
              </>
            ) : (
              <div className="unavailable-block" role="status">
                <strong>Billing status unavailable</strong>
                <p>Entitlement could not be verified. Checkout and application access remain closed.</p>
              </div>
            )}
            <p className="trial-card__identity">Signed in as {session.user.email ?? session.user.user_id}</p>
          </section>
        </div>
        <p className="page-width trial-onboarding-link">
          Need a new organization workspace? <Link href={registrationPath("/start-trial")}>Create an account</Link>.
        </p>
      </main>
    </div>
  );
}

function TrialUnavailable({ message }: { message: string }) {
  return (
    <div className="account-shell account-shell--trial">
      <PublicHeader />
      <main className="centered-state" id="main-content">
        <p className="eyebrow">Fail closed</p>
        <h1>Trial setup is unavailable.</h1>
        <p>{message}</p>
        <div className="button-row">
          <Link className="button button--light" href="/sign-in?next=%2Fstart-trial">Try sign-in again</Link>
          <Link className="button button--outline-dark" href={registrationPath("/start-trial")}>Create account</Link>
          <a className="button button--outline-dark" href="mailto:commercial@vorsyghta.io">Contact commercial</a>
        </div>
      </main>
    </div>
  );
}
