import type { Metadata } from "next";
import Link from "next/link";

import { LegalLinks } from "@/components/legal-links";
import { PublicFooter } from "@/components/public-footer";
import { PublicHeader } from "@/components/public-header";
import { fetchBillingOffer } from "@/lib/api/client";
import { formatBillingInterval, formatMoney } from "@/lib/format";
import { registrationPath } from "@/lib/navigation";

export const metadata: Metadata = {
  title: "Pricing",
  description: "Live Team offer details and sales-assisted Vorsyghta plans.",
};

export const dynamic = "force-dynamic";

export default async function PricingPage() {
  const result = await fetchBillingOffer();
  const offer = result.ok ? result.data : null;
  const amount =
    offer?.unitAmount !== null && offer?.currency
      ? formatMoney(offer.unitAmount, offer.currency)
      : null;
  const pricedOffer =
    offer !== null && amount !== null && offer.interval !== null && offer.trialDays !== null
      ? { ...offer, amount, interval: offer.interval, trialDays: offer.trialDays }
      : null;

  return (
    <div className="marketing-shell marketing-shell--light">
      <PublicHeader />
      <main id="main-content">
        <section className="pricing-hero section-light">
          <div className="page-width pricing-hero__inner">
            <p className="eyebrow eyebrow--ink">Plans and access</p>
            <h1>A clear path from trial to controlled deployment.</h1>
            <p>
              Team uses a live Stripe offer. Enterprise and Mission are scoped with the
              Vorsyghta team before commercial terms are agreed.
            </p>
          </div>
        </section>

        <section className="section-light pricing-section" aria-labelledby="plans-heading">
          <div className="page-width">
            <h2 className="visually-hidden" id="plans-heading">Available plans</h2>
            <div className="pricing-grid">
              <article className="price-card price-card--team">
                <div className="price-card__label">Self-service</div>
                <h3>Team</h3>
                {pricedOffer ? (
                  <>
                    <p className="price-card__price">
                      <strong>{pricedOffer.amount}</strong>
                      <span>{formatBillingInterval(pricedOffer.interval, pricedOffer.intervalCount)}</span>
                    </p>
                    <p className="price-card__trial">{pricedOffer.trialDays}-day trial before recurring billing</p>
                    <ul>
                      <li>Card required before the trial begins</li>
                      <li>Read-only tenant health and recorded activity</li>
                      <li>Hosted subscription management</li>
                    </ul>
                    <Link className="button button--primary" href={registrationPath("/start-trial")}>
                      Create account and start trial
                    </Link>
                    <p className="price-card__fineprint">
                      After successful Checkout, Stripe starts the 14-day trial and attempts the first
                      recurring charge 14 days later. Stripe Checkout shows the exact charge date and
                      amount before card submission. Taxes may apply.
                    </p>
                    <p className="price-card__fineprint">
                      OnePay-issued Mastercard cards are submitted as standard Mastercard payments
                      through Stripe; acceptance depends on Stripe, Mastercard, and the issuer.
                      Vorsyghta does not guarantee acceptance.
                    </p>
                    <p className="price-card__fineprint">
                      Already registered? <Link href="/sign-in?next=%2Fstart-trial">Sign in to continue</Link>.
                    </p>
                  </>
                ) : (
                  <div className="unavailable-block" role="status">
                    <strong>Team checkout is unavailable</strong>
                    <p>
                      The billing service did not return a configured, valid offer. No amount
                      has been estimated or substituted.
                    </p>
                    <a className="button button--secondary" href="mailto:commercial@vorsyghta.io?subject=Vorsyghta%20Team%20offer">
                      Contact commercial
                    </a>
                    <Link className="text-link" href={registrationPath("/start-trial")}>
                      Create an account
                    </Link>
                  </div>
                )}
                <LegalLinks />
              </article>

              <article className="price-card price-card--enterprise">
                <div className="price-card__label">Sales assisted</div>
                <h3>Enterprise</h3>
                <p className="price-card__statement">For regulated organizations defining deployment, identity, and integration requirements.</p>
                <ul>
                  <li>Deployment and data-boundary review</li>
                  <li>Identity and integration scoping</li>
                  <li>Commercial licensing discussion</li>
                </ul>
                <a className="button button--light" href="mailto:commercial@vorsyghta.io?subject=Vorsyghta%20Enterprise%20demo">
                  Request Enterprise demo
                </a>
                <p className="price-card__fineprint">Price and terms are provided only through a sales-assisted agreement.</p>
              </article>

              <article className="price-card">
                <div className="price-card__label">Mission scoped</div>
                <h3>Mission</h3>
                <p className="price-card__statement">For specialized research and coordinated cyber-operation requirements.</p>
                <ul>
                  <li>Use-case and authorization review</li>
                  <li>Environment-specific capability scoping</li>
                  <li>Commercial licensing discussion</li>
                </ul>
                <a className="button button--secondary" href="mailto:commercial@vorsyghta.io?subject=Vorsyghta%20Mission%20demo">
                  Request Mission demo
                </a>
                <p className="price-card__fineprint">No public amount is asserted for this sales-assisted plan.</p>
              </article>
            </div>
          </div>
        </section>
      </main>
      <PublicFooter />
    </div>
  );
}
