import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Add organization",
  robots: { index: false, follow: false },
};

export default function AddOrganizationPage() {
  return (
    <main className="app-main" id="main-content">
      <h1>Add another organization</h1>
      <p>This feature is under construction. For now, contact support to add an additional organization to your account.</p>
      <p><Link href="/onboarding/use-cases">Back to use cases</Link></p>
    </main>
  );
}
