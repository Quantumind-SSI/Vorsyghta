import type { Metadata } from "next";
import Link from "next/link";

import { LegalLinks } from "@/components/legal-links";

export const metadata: Metadata = {
  title: "Terms of service",
  description: "Terms governing use of Vorsyghta, including trial terms.",
};

const SECTIONS: ReadonlyArray<{ heading: string; body: string }> = [
  {
    heading: "Agreement",
    body: "By creating an account or starting a trial you agree to these terms, the privacy notice, and the acceptable-use policy. If you use the service for an organization, you confirm you are authorized to bind it.",
  },
  {
    heading: "The service",
    body: "Vorsyghta provides authorized security validation: scoped assessments, findings, reports, and threat intelligence. Results carry provenance labels (measured, simulated, AI-generated, fallback). A simulated or AI-generated result is not evidence that an attack, detection, or remediation occurred.",
  },
  {
    heading: "Authorized use only",
    body: "You may run assessments only against targets you are authorized to test, within an approved engagement scope. Production targets, external hosts, and third-party systems are prohibited without documented authorization. The acceptable-use policy governs prohibited conduct.",
  },
  {
    heading: "Trials",
    body: "The Team trial is 14 days from activation, requires a payment method collected by Stripe, and converts to a paid subscription unless cancelled before the trial ends. The amount due today, the renewal amount, currency, cadence, and renewal date are shown before checkout. Cancellation takes effect at the end of the billing period; access continues to that boundary.",
  },
  {
    heading: "Billing",
    body: "Stripe is the payment authority. Subscriptions renew automatically until cancelled. Failed payments suspend access under the strict policy. Prices, taxes, and invoices are presented through Stripe.",
  },
  {
    heading: "Acceptable use and suspension",
    body: "We may suspend or terminate access for breach of the acceptable-use policy, unauthorized targeting, abuse of trials, or non-payment. Where feasible we give notice and a cure period for remediable breaches.",
  },
  {
    heading: "Data and security",
    body: "You are responsible for the targets you authorize and the data you ingest. We provide authentication, tenant isolation, audit logging, and secret-management primitives; card data never enters Vorsyghta systems.",
  },
  {
    heading: "Liability",
    body: "The service is provided as-is to the extent permitted by law. Nothing in these terms limits liability that cannot be limited by law. Each party remains responsible for its own regulatory obligations.",
  },
];

export default function TermsPage() {
  return (
    <main className="legal-main" id="main-content">
      <p className="eyebrow">Legal</p>
      <h1>Terms of service</h1>
      <p className="legal-updated">
        These terms include trial terms. The acceptable-use policy and privacy notice form part
        of the agreement.
      </p>
      {SECTIONS.map((section) => (
        <section key={section.heading}>
          <h2>{section.heading}</h2>
          <p>{section.body}</p>
        </section>
      ))}
      <LegalLinks />
      <p><Link href="/">Return to home</Link></p>
    </main>
  );
}
