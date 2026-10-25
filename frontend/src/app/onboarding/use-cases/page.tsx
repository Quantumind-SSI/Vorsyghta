import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { saveOnboardingUseCasesAction } from "@/actions/onboarding";
import { OnboardingForm } from "@/components/onboarding-form";
import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding — use cases",
  description: "Select capabilities, persona, and organizations for assessment defaults and report templates.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

const CAPABILITIES: ReadonlyArray<{ value: string; label: string; hint: string }> = [
  { value: "colour_teams", label: "Colour-team exercises", hint: "Red attacks, Blue defends, Purple coaches" },
  { value: "intelligence_stack", label: "Threat intelligence", hint: "CVE, KEV, OSINT, digital twin" },
  { value: "zero_day_research", label: "Zero-day research", hint: "Fuzzing, SAST, crash triage" },
  { value: "quantum_pqc", label: "Quantum / PQC readiness", hint: "Crypto inventory, migration planning" },
  { value: "saas_product", label: "Evidence workspace", hint: "Findings, reports, provenance" },
  { value: "simulation_paradigms", label: "Advanced simulation", hint: "Six paradigm engines" },
  { value: "rl_rlhf", label: "Agent training (RL/RLHF)", hint: "Learned reward models" },
];
const PERSONAS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "viewer", label: "Viewer / Stakeholder" },
  { value: "analyst", label: "Security Analyst" },
  { value: "pilot_sponsor", label: "Pilot Sponsor / Approver" },
  { value: "admin", label: "System Administrator" },
];
const TENANTS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "default", label: "Select your organization" },
  // Tenants will be populated after onboarding or fetched from session
];

export default async function OnboardingUseCasesPage() {
  const session = await requireSession("/onboarding/use-cases");
  if (session.state === "unavailable") redirect("/sign-in?next=%2Fonboarding%2Fuse-cases");
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fonboarding%2Fuse-cases");
  if (!billing.ok || !hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  // Load tenant options for the signed-in user
  let tenantOptions: Array<{ value: string; label: string }> = [{ value: "default", label: "Select your organization" }];
  try {
    const { fetchCurrentUser } = await import("@/lib/api/client");
    const user = await fetchCurrentUser(session.token);
    if (user.ok && user.data.tenant_id) {
      const tenantName = user.data.tenant?.name || user.data.tenant_id;
      tenantOptions = [{ value: user.data.tenant_id, label: tenantName }];
    }
  } catch {}

  return (
    <main className="app-main onboarding-main" id="main-content">
      <OnboardingStepNav current={2} />
      <div className="app-page-heading onboarding-heading">
        <div>
          <p className="eyebrow">Onboarding · step 2 of 5</p>
          <h1>Use cases & persona</h1>
          <p>Select what you need — this sets assessment defaults and report templates.</p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <OnboardingForm action={saveOnboardingUseCasesAction} submitLabel="Save and continue">
          <fieldset className="onboarding-field">
            <legend>Primary persona</legend>
            {PERSONAS.map((persona, index) => (
              <label className="onboarding-choice" key={persona.value}>
                <input type="radio" name="persona" value={persona.value} required defaultChecked={index === 0} />
                <span>{persona.label}</span>
              </label>
            ))}
          </fieldset>
          <fieldset className="onboarding-field">
            <legend>Organization / Tenant</legend>
            <div className="onboarding-field">
              <Link className="button button--primary" href="/onboarding-enterprise/welcome">Select your organization</Link>
              <p className="onboarding-note">
                Choose or add the organization you want to onboard. This sets tenant context for the workspace.
              </p>
            </div>
          </fieldset>
          <fieldset className="onboarding-field">
            <legend>Capabilities you need (select at least one)</legend>
            <div className="onboarding-choices-grid">
              {CAPABILITIES.map((capability) => (
                <label className="onboarding-choice onboarding-choice--card" key={capability.value}>
                  <input type="checkbox" name="capabilities" value={capability.value} />
                  <span><strong>{capability.label}</strong><small>{capability.hint}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="onboarding-field">
            <label htmlFor="success_criteria">How will you measure success? (optional)</label>
            <textarea id="success_criteria" name="success_criteria" maxLength={600} rows={3} placeholder="e.g. detection coverage mapped to MITRE, executive-ready AAR per quarter" />
          </div>
          <p className="onboarding-skip">
            <Link className="button button--small button--outline-dark" href="/onboarding/profile">Back</Link>
          </p>
        </OnboardingForm>
      </section>
    </main>
  );
}