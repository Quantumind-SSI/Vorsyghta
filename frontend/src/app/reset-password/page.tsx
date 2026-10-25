import type { Metadata } from "next";
import { Suspense } from "react";
import { ResetPasswordClient } from "@/components/reset-password-client";

export const metadata: Metadata = {
  title: "Reset password",
  description: "Set a new password",
};

export default function ResetPasswordPage() {
  return (
    <main className="centered-state" id="main-content">
      <Suspense fallback={<p>Loading…</p>}>
        <ResetPasswordClient />
      </Suspense>
    </main>
  );
}
