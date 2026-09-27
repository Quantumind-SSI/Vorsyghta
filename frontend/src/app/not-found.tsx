import Link from "next/link";

import { PublicHeader } from "@/components/public-header";

export default function NotFound() {
  return (
    <div className="account-shell">
      <PublicHeader />
      <main className="centered-state" id="main-content">
        <p className="eyebrow">404 / route not found</p>
        <h1>There is no evidence at this address.</h1>
        <p>Check the URL, return to the product overview, or sign in to an existing workspace.</p>
        <div className="button-row">
          <Link className="button button--light" href="/">Product overview</Link>
          <Link className="button button--outline-dark" href="/sign-in">Sign in</Link>
        </div>
      </main>
    </div>
  );
}
