import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchBillingStatus, fetchFindings } from "@/lib/api/client";
import type { ApiResult } from "@/lib/api/client";
import type { FindingList } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { formatDateTime } from "@/lib/format";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Findings register",
  description: "Recorded attack sequences and step reports for this tenant.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

function statusClass(status: string): string {
  if (status === "completed" && status.length > 0) return "status-chip--good";
  if (status === "running" || status === "pending") return "status-chip--warn";
  if (status === "failed" || status === "aborted" || status === "blocked") return "status-chip--bad";
  return "status-chip--idle";
}

function FindingsTable({ findings }: { findings: FindingList }) {
  if (findings.length === 0) {
    return (
      <p className="empty-state">
        No recorded attack sequences exist for this tenant. Findings appear here after an
        authorized assessment records results.
      </p>
    );
  }
  return (
    <div className="table-scroll" role="region" aria-label="Recorded attack sequences" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Recorded attack sequences for this tenant</caption>
        <thead>
          <tr>
            <th>Sequence</th>
            <th>Status</th>
            <th>Steps</th>
            <th>Target</th>
            <th>Engagement</th>
            <th>Recorded</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((record) => (
            <tr key={record.sequence_id}>
              <td>
                <strong>{record.name ?? record.sequence_id}</strong>
                <span className="table-id">{record.sequence_id}</span>
              </td>
              <td><span className={`status-chip ${statusClass(record.status)}`}>{record.status}</span></td>
              <td>{record.completed_steps}/{record.total_steps} ({record.successful_steps} ok, {record.failed_steps} failed)</td>
              <td>{record.target_system ?? "Not reported"}</td>
              <td>{record.exercise_id ?? "Not linked"}</td>
              <td>{record.created_at ? formatDateTime(record.created_at) : "Not reported"}</td>
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

export default async function FindingsPage() {
  const session = await requireSession("/app/findings");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so findings remain hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Ffindings");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Findings remain hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const findings: ApiResult<FindingList> = await fetchFindings(session.token);
  if (!findings.ok && (findings.kind === "unauthorized" || findings.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Ffindings");

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #1 — Colour-team operations</p>
          <h1>Findings register</h1>
          <p>
            Recorded attack sequences and step reports for this tenant. Read-only: finding
            confirmation, editing, and analyst validation are not exposed here.
          </p>
        </div>
      </div>

      {!findings.ok ? (
        <UnavailablePanel
          title="Findings unavailable"
          detail="The attack-tracking endpoint did not return valid data. No substitute data is shown."
        />
      ) : (
        <section className="data-panel" aria-labelledby="findings-heading">
          <div className="data-panel__heading">
            <div><p className="card-kicker">Most recent 50</p><h2 id="findings-heading">Recorded attack sequences</h2></div>
            <span className="source-label">Source: attack tracking</span>
          </div>
          <FindingsTable findings={findings.data} />
        </section>
      )}
      <p className="panel-footnote">
        A recorded sequence is an execution record, not a confirmed security finding. Analyst
        validation and report approval arrive with the operational workflow.
      </p>
    </main>
  );
}
