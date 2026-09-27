import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { fetchBillingStatus, fetchTemplateDetail } from "@/lib/api/client";
import type { ApiResult } from "@/lib/api/client";
import type { TemplateDetail } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Template detail",
  description: "Scenario template parameters and safety flags. No execution here.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

function formatKey(key: string): string {
  return key.replaceAll("_", " ");
}

function TemplateContent({ detail }: { detail: TemplateDetail }) {
  const entries = Object.entries(detail.content);
  if (entries.length === 0) {
    return <p className="empty-state">The template file contains no parameters.</p>;
  }
  return (
    <dl className="health-list">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{formatKey(key)}</dt>
          <dd>
            {value === null || value === undefined
              ? "Not stated"
              : typeof value === "string" || typeof value === "number" || typeof value === "boolean"
                ? String(value)
                : <code className="table-id">{JSON.stringify(value)}</code>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function UnavailablePanel({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="data-panel data-panel--unavailable" role="status">
      <p className="card-kicker">Dependency unavailable</p>
      <h2>{title}</h2>
      <p>{detail}</p>
    </section>
  );
}

export default async function TemplateDetailPage({
  params,
}: Readonly<{ params: Promise<{ category: string; name: string }> }>) {
  const { category, name } = await params;
  const session = await requireSession(`/app/templates/${category}/${name}`);
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so template data remains hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) {
    redirect(`/sign-in?next=${encodeURIComponent(`/app/templates/${category}/${name}`)}`);
  }
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Template data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const detail: ApiResult<TemplateDetail> = await fetchTemplateDetail(session.token, category, name);
  if (!detail.ok && (detail.kind === "unauthorized" || detail.kind === "forbidden")) {
    redirect(`/sign-in?next=${encodeURIComponent(`/app/templates/${category}/${name}`)}`);
  }

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #1 — Colour-team operations</p>
          <h1>{name}</h1>
          <p>Category: {category === "root" ? "top-level" : category} · file: {detail.ok ? detail.data.file : "unavailable"}</p>
        </div>
        <Link className="button button--small button--outline-dark" href="/app/templates">Back to templates</Link>
      </div>

      {!detail.ok ? (
        <UnavailablePanel
          title={detail.kind === "not-found" ? "Template not found" : "Template unavailable"}
          detail={
            detail.kind === "not-found"
              ? "No template file matched this category and name. The catalog may have changed."
              : "The template endpoint did not return valid data. No substitute data is shown."
          }
        />
      ) : (
        <section className="data-panel" aria-labelledby="template-content-heading">
          <div className="data-panel__heading">
            <div><p className="card-kicker">Scenario parameters</p><h2 id="template-content-heading">Template content</h2></div>
            <span className="source-label">Source: templates router</span>
          </div>
          <TemplateContent detail={detail.data} />
        </section>
      )}
      <p className="panel-footnote">
        Execution, assessment creation, and target contact require an approved engagement and
        the canonical safety path — they are not available in this release.
      </p>
    </main>
  );
}
