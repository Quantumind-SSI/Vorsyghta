import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { activateOnboardingAction } from "@/actions/onboarding";
import { OnboardingForm } from "@/components/onboarding-form";
import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";
import { OnboardingStepNav } from "@/components/onboarding-step-nav";

export const metadata: Metadata = {
  title: "Onboarding — review and activate",
  description: "Review your answers, accept the terms, and enter the workspace.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

export default async function OnboardingReviewPage() {
  const session = await requireSession("/onboarding/review");
  if (session.state === "unavailable") redirect("/sign-in?next=%2Fonboarding%2Freview");
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fonboarding%2Freview");
  if (!billing.ok || !hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  return (
    <main className="app-main onboarding-main" id="main-content">
      <OnboardingStepNav current={4} />
      <div className="app-page-heading onboarding-heading">
        <div>
          <p className="eyebrow">Onboarding · step 4 of 4</p>
          <h1>Review & activate</h1>
          <p>Your answers are saved to your tenant. Accept the terms to enter the workspace.</p>
        </div>
      </div>
      <section className="data-panel onboarding-panel">
        <ul className="onboarding-summary">
          <li>Organization profile, use cases, and environment intent saved as tenant-scoped records.</li>
          <li>Assessments run only against sanctioned targets or authorized environments.</li>
          <li>Every result carries provenance — measured, simulated, AI-generated, or fallback.</li>
        </ul>
        <OnboardingForm action={activateOnboardingAction} submitLabel="Activate workspace">
          <fieldset className="onboarding-field onboarding-field--required">
            <legend>Acceptance</legend>
            <label className="onboarding-choice">
              <input type="checkbox" name="terms_accepted" value="true" required />
              <span>I accept the <Link href="/legal/terms">terms of service</Link> and <Link href="/legal/privacy">privacy notice</Link>.</span>
            </label>
            <label className="onboarding-choice">
              <input type="checkbox" name="acceptable_use_accepted" value="true" required />
              <span>I accept the <Link href="/legal/acceptable-use">acceptable-use policy</Link>: authorized targets only.</span>
            </label>
          </fieldset>
          <p className="onboarding-skip">
            <Link className="button button--small button--outline-dark" href="/onboarding/environments">Back</Link>
          </p>
        </OnboardingForm>
      </section>
    </main>
  );
}
