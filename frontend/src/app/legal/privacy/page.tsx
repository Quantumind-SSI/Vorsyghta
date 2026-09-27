import type { Metadata } from "next";
import Link from "next/link";

import { LegalLinks } from "@/components/legal-links";

export const metadata: Metadata = {
  title: "Privacy notice",
  description: "How Vorsyghta collects, uses, and protects personal data.",
};

const SECTIONS: ReadonlyArray<{ heading: string; body: string }> = [
  {
    heading: "Who we are",
    body: "Vorsyghta is an authorized security validation platform. For privacy contacts, see the security and support links in the footer. The data controller for the hosted service is the Vorsyghta operating entity identified in the terms of service.",
  },
  {
    heading: "What we collect",
    body: "Account data (email, name if provided, organization and workspace details), billing metadata (subscription status and Stripe customer identifiers — never card data), and service telemetry (request logs, audit events). Card numbers, security codes, and magnetic-stripe data never enter Vorsyghta infrastructure: collection is performed by Stripe.",
  },
  {
    heading: "Why we process it",
    body: "To provide the contracted service (creating and maintaining your tenant and workspace), to bill for it, to secure it (authentication, audit, abuse prevention), and to communicate service notices such as trial reminders and payment failures.",
  },
  {
    heading: "Lawful basis",
    body: "Contract performance for service delivery and billing; legitimate interests for service security, abuse prevention, and product telemetry; consent where required for optional communications.",
  },
  {
    heading: "Retention",
    body: "Account and billing records are retained for the life of the subscription plus the period required by tax and accounting rules. Audit and telemetry records are retained per the audit retention policy disclosed before trial enrollment. Data is deleted or anonymized when retention expires.",
  },
  {
    heading: "Your rights",
    body: "Subject to applicable law (including UK/EU GDPR), you can request access, correction, deletion, restriction, portability, and object to processing. Requests route through the contact links; we respond within the statutory period.",
  },
  {
    heading: "Processors and sharing",
    body: "Stripe (payment processing), cloud infrastructure providers, and the LLM provider configured for your workspace. We do not sell personal data. Processor changes are disclosed before they take effect.",
  },
  {
    heading: "International transfers",
    body: "Where data is processed outside your jurisdiction, transfers rely on appropriate safeguards such as adequacy decisions or standard contractual clauses.",
  },
];

export default function PrivacyPage() {
  return (
    <main className="legal-main" id="main-content">
      <p className="eyebrow">Legal</p>
      <h1>Privacy notice</h1>
      <p className="legal-updated">
        This notice describes the hosted-service posture. Self-hosted deployments control their
        own data boundary; the hosted notice applies only where Vorsyghta operates the service.
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
