import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchBillingStatus, fetchDisclosures } from "@/lib/api/client";
import type { ApiResult } from "@/lib/api/client";
import type { DisclosureList } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Disclosure register",
  description: "Responsible-disclosure records and CVD lifecycle state for this tenant.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "status-chip--bad",
  high: "status-chip--bad",
  medium: "status-chip--warn",
  low: "status-chip--good",
  info: "status-chip--idle",
  unknown: "status-chip--idle",
};

function DisclosuresTable({ disclosures }: { disclosures: DisclosureList }) {
  if (disclosures.length === 0) {
    return (
      <p className="empty-state">
        No disclosure records exist for this tenant. Records appear here after a research
        finding enters the coordinated-vulnerability-disclosure workflow.
      </p>
    );
  }
  return (
    <div className="table-scroll" role="region" aria-label="Disclosure records" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Disclosure records for this tenant</caption>
        <thead>
          <tr>
            <th>Finding</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>CVE</th>
            <th>Vendor / product</th>
            <th>Status</th>
            <th>Embargo</th>
          </tr>
        </thead>
        <tbody>
          {disclosures.map((record) => (
            <tr key={record.id}>
              <td><strong>{record.title}</strong><span className="table-id">{record.id}</span></td>
              <td><span className={`status-chip ${SEVERITY_CLASS[record.severity] ?? "status-chip--idle"}`}>{record.severity}</span></td>
              <td>{record.cvss_score.toFixed(1)}</td>
              <td>{record.cve_id ?? "Requested"}</td>
              <td>{record.vendor} · {record.product}</td>
              <td><span className="table-id">{record.status}</span></td>
              <td>{record.days_until_disclosure}d remaining</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

export default async function DisclosuresPage() {
  const session = await requireSession("/app/disclosures");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so disclosure data remains hidden." />;
  }
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fdisclosures");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Disclosure data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const disclosures: ApiResult<DisclosureList> = await fetchDisclosures(session.token);
  if (!disclosures.ok && (disclosures.kind === "unauthorized" || disclosures.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fdisclosures");

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #3 — Zero-day research</p>
          <h1>Disclosure register</h1>
          <p>
            Responsible-disclosure records with CVE state, embargo clocks, and vendor response.
            Read-only: creating, notifying vendors, and publishing are not exposed in the UI.
          </p>
        </div>
      </div>

      {!disclosures.ok ? (
        <UnavailablePanel
          title="Disclosure register unavailable"
          detail="The disclosures endpoint did not return valid data. No substitute data is shown."
        />
      ) : (
        <section className="data-panel" aria-labelledby="disclosures-heading">
          <div className="data-panel__heading">
            <div><p className="card-kicker">Coordinated vulnerability disclosure</p><h2 id="disclosures-heading">Disclosure records</h2></div>
            <span className="source-label">Source: disclosures API</span>
          </div>
          <DisclosuresTable disclosures={disclosures.data} />
        </section>
      )}
      <p className="panel-footnote">
        Disclosure records enforce the embargo — public disclosure is blocked until the embargo
        ends. PoC content is never rendered here.
      </p>
    </main>
  );
}
