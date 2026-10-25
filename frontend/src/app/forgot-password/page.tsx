import type { Metadata } from "next";
import { Suspense } from "react";
import { ForgotPasswordClient } from "../../../components/forgot-password-client";

export const metadata: Metadata = {
  title: "Forgot password",
  description: "Reset your password",
};

export default function ForgotPasswordPage() {
  return (
    <main className="centered-state" id="main-content">
      <Suspense fallback={<p>Loading…</p>}>
        <ForgotPasswordClient />
      </Suspense>
    </main>
  );
}
