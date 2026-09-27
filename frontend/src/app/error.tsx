"use client";

import Link from "next/link";

export default function ErrorBoundary({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="centered-state centered-state--error" id="main-content">
      <p className="eyebrow">Request interrupted</p>
      <h1>This view could not be rendered.</h1>
      <p>No fallback data has been substituted. Retry the request or return to the public site.</p>
      <div className="button-row">
        <button className="button button--light" type="button" onClick={reset}>Try again</button>
        <Link className="button button--outline-dark" href="/">Return home</Link>
      </div>
    </main>
  );
}
