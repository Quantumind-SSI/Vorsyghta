import type { Metadata } from "next";
import Link from "next/link";

import { PublicHeader } from "@/components/public-header";
import { SignInForm } from "@/components/sign-in-form";
import { registrationPath, safeReturnPath } from "@/lib/navigation";

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in to an existing Vorsyghta account.",
  robots: { index: false, follow: false },
};

type SignInPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function SignInPage({ searchParams }: SignInPageProps) {
  const query = await searchParams;
  const nextPath = safeReturnPath(firstValue(query.next));
  const status = firstValue(query.status);

  return (
    <div className="account-shell">
      <PublicHeader />
      <main className="account-main" id="main-content">
        <section className="auth-panel" aria-labelledby="sign-in-heading">
          <div className="auth-panel__context">
            <p className="eyebrow">Controlled access</p>
            <h1 id="sign-in-heading">Sign in to your evidence workspace.</h1>
            <p>
              Credentials are sent by a Next.js Server Action to the Vorsyghta API.
              The verified bearer token is stored only in an HttpOnly session cookie.
            </p>
            <dl className="security-notes">
              <div><dt>Browser storage</dt><dd>No bearer token</dd></div>
              <div><dt>Session policy</dt><dd>HttpOnly, SameSite=Lax</dd></div>
              <div><dt>Identity check</dt><dd>Verified with /api/auth/me</dd></div>
            </dl>
          </div>
          <div className="auth-panel__form">
            <p className="eyebrow eyebrow--ink">Existing account</p>
            <h2>Welcome back</h2>
            {status === "account-created" ? (
              <p className="notice notice--success" role="status">Account created. Sign in to continue.</p>
            ) : null}
            <SignInForm nextPath={nextPath} />
            <p className="auth-panel__support">
              New to Vorsyghta? <Link href={registrationPath("/start-trial")}>Create an account</Link>.
            </p>
            <p className="auth-panel__support">
              Need commercial access? <a href="mailto:commercial@vorsyghta.io">Contact the Vorsyghta team</a>.
            </p>
            <Link className="back-link" href="/">Return to product overview</Link>
          </div>
        </section>
      </main>
    </div>
  );
}
