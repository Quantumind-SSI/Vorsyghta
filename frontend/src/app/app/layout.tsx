import Link from "next/link";
import type { ReactNode } from "react";

import { signOutAction } from "@/actions/auth";
import { getSessionState } from "@/lib/session";
import { redirect } from "next/navigation";

export default async function ApplicationLayout({ children }: Readonly<{ children: ReactNode }>) {
  const session = await getSessionState();
  if (session.state === "authenticated") {
    const store = await import("next/headers").then(m => m.cookies());
    const onboardingCookie = store.get("onboarding_complete");
    // Enforce onboarding for all signed-in users on every visit
    if (!onboardingCookie) {
      redirect("/onboarding");
    }
  }
  return (
    <div className="application-shell">
      <header className="app-header">
        <div className="app-header__inner">
          <Link className="wordmark" href="/app" aria-label="Vorsyghta workspace">
            <span className="wordmark__mark" aria-hidden="true">V</span>
            <span>Vorsyghta</span>
          </Link>
          <nav aria-label="Application navigation">
            <Link href="/app">Overview</Link>
            <Link href="/app/exercises">Exercises</Link>
            <Link href="/app/findings">Findings</Link>
            <Link href="/app/disclosures">Disclosures</Link>
            <Link href="/app/intelligence">Intelligence</Link>
            <Link href="/app/templates">Templates</Link>
            <Link href="/app/environments">Environments</Link>
            <Link href="/app/settings/billing">Billing</Link>
          </nav>
          <form action={signOutAction}>
            <button className="button button--small button--outline-dark" type="submit">Sign out</button>
          </form>
        </div>
      </header>
      {children}
    </div>
  );
}
