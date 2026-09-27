import type { Metadata } from "next";
import Link from "next/link";

import { LegalLinks } from "@/components/legal-links";
import { PublicHeader } from "@/components/public-header";
import { RegisterForm } from "@/components/register-form";
import { safeReturnPath } from "@/lib/navigation";

export const metadata: Metadata = {
  title: "Create account",
  description: "Create an isolated Vorsyghta organization and initial viewer account.",
  robots: { index: false, follow: false },
};

type RegisterPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function RegisterPage({ searchParams }: RegisterPageProps) {
  const query = await searchParams;
  const nextPath = safeReturnPath(firstValue(query.next) ?? "/start-trial");

  return (
    <div className="account-shell">
      <PublicHeader />
      <main className="account-main" id="main-content">
        <section className="auth-panel" aria-labelledby="register-heading">
          <div className="auth-panel__context">
            <p className="eyebrow">Self-service onboarding</p>
            <h1 id="register-heading">Create your organization workspace.</h1>
            <p>
              Registration creates one isolated organization and its initial Viewer account.
              Billing and trial access remain separate until completed through Stripe Checkout.
            </p>
            <dl className="security-notes">
              <div><dt>Initial role</dt><dd>Viewer</dd></div>
              <div><dt>Tenant</dt><dd>Dedicated organization</dd></div>
              <div><dt>Payment data</dt><dd>Not collected here</dd></div>
            </dl>
          </div>
          <div className="auth-panel__form">
            <p className="eyebrow eyebrow--ink">New account</p>
            <h2>Organization details</h2>
            <RegisterForm nextPath={nextPath} />
            <p className="auth-panel__support">
              Already registered? <Link href={`/sign-in?next=${encodeURIComponent(nextPath)}`}>Sign in</Link>.
            </p>
            <LegalLinks />
          </div>
        </section>
      </main>
    </div>
  );
}
