import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Forgot password",
  description: "Password recovery is not yet available.",
};

export default function ForgotPasswordPage() {
  return (
    <main className="centered-state" id="main-content">
      <p className="eyebrow">Not available yet</p>
      <h1>Password recovery is not available</h1>
      <p>
        Vorsyghta does not yet offer self-service password recovery, and no reset email was
        sent. When password reset ships, this page will offer a verified, token-based reset
        flow with email delivery.
      </p>
      <p>
        Until then, contact support through the links below. An administrator can rotate
        credentials for your tenant.
      </p>
      <p><Link href="/sign-in">Back to sign in</Link></p>
    </main>
  );
}
