import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding",
  description: "Guided onboarding: organization profile, use cases, environments, activation.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export default async function OnboardingEntryPage() {
  const session = await requireSession("/onboarding");
  if (session.state === "unavailable") redirect("/sign-in?next=%2Fonboarding");
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fonboarding");
  if (!billing.ok || !hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  return (
    <main className="app-main onboarding-main" id="main-content">
      <OnboardingStepNav current={1} />
      <div className="app-page-heading onboarding-heading">
        <div>
          <p className="eyebrow">Guided onboarding</p>
          <h1>Set up your workspace</h1>
          <p>
            Four short steps: your organization profile, the capabilities you need, the
            environments you plan to connect, and activation. Answers are saved to your tenant
            as you go — nothing is sent by email, and no email verification is required.
          </p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <ul className="onboarding-summary">
          <li><strong>1 — Organization profile:</strong> industry, size, regions, maturity, compliance obligations.</li>
          <li><strong>2 — Use cases:</strong> which capabilities you need and how you measure success.</li>
          <li><strong>3 — Environments:</strong> containers, cloud, files, APIs, infrastructure, media you plan to connect.</li>
          <li><strong>4 — Review & activate:</strong> terms acceptance and workspace entry.</li>
        </ul>
        <p className="panel-footnote">
          Start at step 1 — the wizard resumes at your first incomplete step.
        </p>
        <div className="onboarding-actions">
          <a className="button button--primary" href="/onboarding/profile">Start onboarding</a>
        </div>
      </section>
    </main>
  );
}
