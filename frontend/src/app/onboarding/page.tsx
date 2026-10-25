import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchCurrentUser, fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding",
  description: "Guided onboarding: role selection, organization profile, use cases, environments, and activation.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export default async function OnboardingEntryPage() {
  const session = await requireSession("/onboarding");
  if (session.state === "unavailable") redirect("/sign-in");

  // Check if user is already verified and is a Viewer - skip onboarding
  try {
    const user = await fetchCurrentUser(session.token);
    if (user.ok && user.data.role === "viewer" && user.data.is_verified) {
      // Viewer role with verified email - skip straight to app
      redirect("/app");
    }
  } catch {
    // If we can't fetch the user, continue with onboarding
  }

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
            Select your role — this determines your access level and the onboarding journey you'll experience.
          </p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <ul className="onboarding-summary">
          <li><strong>1 — Role selection:</strong> choose your persona and access level.</li>
          <li><strong>2 — Organization profile:</strong> industry, size, regions, maturity, compliance obligations.</li>
          <li><strong>3 — Use cases:</strong> which capabilities you need and how you measure success.</li>
          <li><strong>4 — Environments:</strong> containers, cloud, files, APIs, infrastructure, media you plan to connect.</li>
          <li><strong>5 — Review & activate:</strong> terms acceptance and workspace entry.</li>
        </ul>
        <p className="panel-footnote">
          Start at step 1 — the wizard resumes at your first incomplete step.
        </p>
        <div className="onboarding-actions">
          <a className="button button--primary" href="/onboarding/profile">Select Role</a>
        </div>
      </section>
    </main>
  );
}