import type { Metadata } from "next";
import { Suspense } from "react";
import { VerifyEmailClient } from "@/components/verify-email-client";

export const metadata: Metadata = {
  title: "Verify Email",
  robots: { index: false, follow: false },
};

export default function VerifyEmailPage() {
  return (
    <main className="app-main" id="main-content">
      <Suspense fallback={<p>Loading verification…</p>}>
        <VerifyEmailClient />
      </Suspense>
    </main>
  );
}
