import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { saveOnboardingProfileAction } from "@/actions/onboarding";
import { OnboardingForm } from "@/components/onboarding-form";
import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding — role selection & organization profile",
  description: "Select your role and organizational context for tailored assessment experiences.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

const PERSONAS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "viewer", label: "Viewer / Stakeholder" },
  { value: "analyst", label: "Security Analyst" },
  { value: "pilot_sponsor", label: "Pilot Sponsor / Approver" },
  { value: "admin", label: "System Administrator" },
];

const SIZES = ["1-10", "11-50", "51-200", "201-1000", "1000+"] as const;
const MATURITIES: ReadonlyArray<{ value: string; label: string }> = [
  { value: "none", label: "No dedicated security team" },
  { value: "ad_hoc", label: "Ad-hoc / part-time" },
  { value: "defined", label: "Defined team and processes" },
  { value: "managed", label: "Managed / 24-7 operations" },
];
const FRAMEWORKS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "pci_dss", label: "PCI-DSS" },
  { value: "ndpr", label: "NDPR" },
  { value: "gdpr", label: "GDPR" },
  { value: "soc_2", label: "SOC 2" },
  { value: "iso_27001", label: "ISO 27001" },
  { value: "cbn", label: "CBN" },
  { value: "hipaa", label: "HIPAA" },
];

export default async function OnboardingProfilePage() {
  const session = await requireSession("/onboarding/profile");
  if (session.state === "unavailable") redirect("/sign-in?next=%2Fonboarding%2Fprofile");
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fonboarding%2Fprofile");
  if (!billing.ok || !hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  return (
    <main className="app-main onboarding-main" id="main-content">
      <OnboardingStepNav current={1} />
      <div className="app-page-heading onboarding-heading">
        <div>
          <p className="eyebrow">Onboarding · step 1 of 5</p>
          <h1>Role selection & organization profile</h1>
          <p>
            Select your role — this determines your access level and the onboarding journey you'll experience.
            Then provide your organization details to tailor assessments and reports.
          </p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <OnboardingForm action={saveOnboardingProfileAction} submitLabel="Save and continue">
          <fieldset className="onboarding-field">
            <legend>Select your role</legend>
            {PERSONAS.map((persona, index) => (
              <label className="onboarding-choice" key={persona.value}>
                <input type="radio" name="persona" value={persona.value} required defaultChecked={index === 0} />
                <span>{persona.label}</span>
              </label>
            ))}
          </fieldset>
          <div className="onboarding-field">
            <label htmlFor="industry">Industry vertical</label>
            <input id="industry" name="industry" type="text" required minLength={2} maxLength={80} placeholder="Fintech, healthcare, logistics…" />
          </div>
          <div className="onboarding-field">
            <label htmlFor="company_size">Company size</label>
            <select id="company_size" name="company_size" required defaultValue="">
              <option value="" disabled>Select a size band</option>
              {SIZES.map((size) => <option key={size} value={size}>{size} people</option>)}
            </select>
          </div>
          <div className="onboarding-field">
            <label htmlFor="regions">Operating regions</label>
            <input id="regions" name="regions" type="text" required minLength={2} maxLength={160} placeholder="e.g. UK, EU, Nigeria" />
          </div>
          <fieldset className="onboarding-field">
            <legend>Security-team maturity</legend>
            {MATURITIES.map((maturity, index) => (
              <label className="onboarding-choice" key={maturity.value}>
                <input type="radio" name="security_maturity" value={maturity.value} required defaultChecked={index === 0} />
                <span>{maturity.label}</span>
              </label>
            ))}
          </fieldset>
          <fieldset className="onboarding-field">
            <legend>Compliance obligations in scope (select all that apply)</legend>
            <div className="onboarding-choices-grid">
              {FRAMEWORKS.map((framework) => (
                <label className="onboarding-choice" key={framework.value}>
                  <input type="checkbox" name="compliance_frameworks" value={framework.value} />
                  <span>{framework.label}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <p className="onboarding-skip">
            <Link className="button button--small button--outline-dark" href="/onboarding">Back</Link>
          </p>
        </OnboardingForm>
      </section>
    </main>
  );
}