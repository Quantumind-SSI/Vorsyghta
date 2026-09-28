import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { saveOnboardingEnvironmentsAction } from "@/actions/onboarding";
import { OnboardingForm } from "@/components/onboarding-form";
import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding — environments",
  description: "What you plan to connect: containers, cloud, files, APIs, infrastructure, media.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

const ADAPTERS: ReadonlyArray<{ value: string; label: string; hint: string }> = [
  { value: "containers", label: "Containers", hint: "Docker/Compose clusters, container images" },
  { value: "cloud", label: "Cloud", hint: "AWS / Azure / GCP storage, IAM, network, compute" },
  { value: "files", label: "Files", hint: "OneDrive, SharePoint, Google Drive" },
  { value: "web_apps_apis", label: "Web apps & APIs", hint: "REST/GraphQL, OpenAPI specs, webhooks" },
  { value: "external_infrastructure", label: "External infrastructure", hint: "Network topology, firewalls, DNS, VPN" },
  { value: "directories_crm", label: "Directories & CRM", hint: "M365, Entra ID, Salesforce, HubSpot" },
  { value: "media", label: "Media & other formats", hint: "VM images, packet captures, artifacts" },
];
const CLOUDS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
  { value: "huawei", label: "Huawei Cloud" },
];

export default async function OnboardingEnvironmentsPage() {
  const session = await requireSession("/onboarding/environments");
  if (session.state === "unavailable") redirect("/sign-in?next=%2Fonboarding%2Fenvironments");
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fonboarding%2Fenvironments");
  if (!billing.ok || !hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  return (
    <main className="app-main onboarding-main" id="main-content">
      <OnboardingStepNav current={3} />
      <div className="app-page-heading onboarding-heading">
        <div>
          <p className="eyebrow">Onboarding · step 3 of 4</p>
          <h1>Environments</h1>
          <p>
            Tell us what you plan to connect. This sets the Environments hub defaults and the
            digital-twin ingestion path. Connections themselves are made later in
            Environments — never here.
          </p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <OnboardingForm action={saveOnboardingEnvironmentsAction} submitLabel="Save and continue">
          <fieldset className="onboarding-field">
            <legend>Environments you plan to connect (select all that apply)</legend>
            <div className="onboarding-choices-grid">
              {ADAPTERS.map((adapter) => (
                <label className="onboarding-choice onboarding-choice--card" key={adapter.value}>
                  <input type="checkbox" name="adapter_categories" value={adapter.value} />
                  <span><strong>{adapter.label}</strong><small>{adapter.hint}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset className="onboarding-field">
            <legend>Cloud providers in use (select all that apply)</legend>
            <div className="onboarding-choices-grid">
              {CLOUDS.map((cloud) => (
                <label className="onboarding-choice" key={cloud.value}>
                  <input type="checkbox" name="cloud_providers" value={cloud.value} />
                  <span>{cloud.label}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset className="onboarding-field onboarding-field--required">
            <legend>Target authorization</legend>
            <label className="onboarding-choice">
              <input type="checkbox" name="sanctioned_targets_only" value="true" required />
              <span>
                I will run assessments only against sanctioned targets, isolated labs, or
                environments my organization is authorized to test.
              </span>
            </label>
          </fieldset>
          <p className="onboarding-skip">
            <Link className="button button--small button--outline-dark" href="/onboarding/use-cases">Back</Link>
          </p>
        </OnboardingForm>
      </section>
    </main>
  );
}
