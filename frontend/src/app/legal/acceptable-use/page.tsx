import type { Metadata } from "next";
import Link from "next/link";

import { LegalLinks } from "@/components/legal-links";

export const metadata: Metadata = {
  title: "Acceptable use policy",
  description: "Authorized-use and prohibited-conduct policy for Vorsyghta.",
};

const PROHIBITED: ReadonlyArray<string> = [
  "Testing, scanning, or attacking any target you are not authorized to test — including production systems, third-party services, and external hosts outside an approved engagement scope.",
  "Using the platform for actual malicious activity: unauthorized access, credential theft, data exfiltration, harassment, or any illegal purpose.",
  "Bypassing, disabling, or attempting to circumvent safety controls, engagement approval, command validation, rate limits, or network isolation.",
  "Ingesting data you have no right to process, or personal data without a lawful basis.",
  "Presenting simulated, AI-generated, or fallback results as measured outcomes to a customer, auditor, or regulator.",
  "Sharing trial access, creating duplicate accounts to evade trial limits, or providing false billing or identity information.",
  "Interfering with other tenants, probing the platform itself for vulnerabilities without authorization, or exceeding reasonable resource use.",
];

const REQUIREMENTS: ReadonlyArray<string> = [
  "Written authorization for scope and targets before any live run (the engagement approval workflow records it).",
  "Isolated labs, test tenants, or sanctioned targets only — the sanctioned-target policy defines what qualifies.",
  "Results are used with their provenance labels intact.",
  "Data handling, retention, and disclosure obligations are agreed before ingestion.",
];

export default function AcceptableUsePage() {
  return (
    <main className="legal-main" id="main-content">
      <p className="eyebrow">Legal</p>
      <h1>Acceptable use policy</h1>
      <p className="legal-updated">
        This policy governs use of the hosted service. Self-hosted deployments enforce the same
        rules for their own operators; the LLM scope bounds in the repository apply to any
        agent the platform drives.
      </p>
      <section>
        <h2>Authorized use</h2>
        <p>
          Vorsyghta is built for authorized security testing, training, control validation,
          compliance evidence, and vulnerability research under authorized scope — never for
          malicious activity.
        </p>
        <ul>
          {REQUIREMENTS.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </section>
      <section>
        <h2>Prohibited conduct</h2>
        <ul>
          {PROHIBITED.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </section>
      <section>
        <h2>Enforcement</h2>
        <p>
          Violations may result in suspension or termination of access, and where relevant,
          notification to affected parties or authorities. We may suspend immediately where an
          unauthorized target is being contacted.
        </p>
      </section>
      <LegalLinks />
      <p><Link href="/">Return to home</Link></p>
    </main>
  );
}
