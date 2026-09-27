import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import type { ApiResult } from "@/lib/api/client";
import {
  fetchAttackStats,
  fetchBillingStatus,
  fetchHealth,
  fetchRecentToolUsage,
} from "@/lib/api/client";
import type { AttackStats, Health, ToolUsage } from "@/lib/api/schemas";
import { billingStatusLabel, hasProductAccess } from "@/lib/billing";
import { formatDateTime, formatDuration } from "@/lib/format";
import { canViewRawActivity, classifyActivityProvenance } from "@/lib/provenance";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Workspace overview",
  description: "Verified tenant health and recently recorded security activity.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

function hasAuthFailure<T>(result: ApiResult<T>): boolean {
  return !result.ok && (result.kind === "unauthorized" || result.kind === "forbidden");
}

function HealthPanel({ result }: { result: ApiResult<Health> }) {
  if (!result.ok) {
    return <UnavailablePanel title="System health unavailable" detail="The health endpoint did not return valid data." />;
  }
  const components = Object.entries(result.data.components);
  return (
    <section className="data-panel health-panel" aria-labelledby="health-heading">
      <div className="data-panel__heading">
        <div><p className="card-kicker">Live API response</p><h2 id="health-heading">System health</h2></div>
        <span className={`status-chip ${result.data.status === "healthy" ? "status-chip--good" : "status-chip--warn"}`}>
          {result.data.status}
        </span>
      </div>
      {components.length > 0 ? (
        <dl className="health-list">
          {components.map(([name, status]) => (
            <div key={name}><dt>{name.replaceAll("_", " ")}</dt><dd>{status}</dd></div>
          ))}
        </dl>
      ) : <p className="empty-state">The API returned no component health records.</p>}
      <p className="panel-footnote">API {result.data.version} / reported {formatDateTime(result.data.timestamp)}</p>
    </section>
  );
}

function StatsPanel({ result }: { result: ApiResult<AttackStats> }) {
  if (!result.ok) {
    return <UnavailablePanel title="Tracking totals unavailable" detail="No totals are shown because attack tracking could not be validated." />;
  }
  const stats = [
    ["Mixed-event sequences", result.data.total_sequences],
    ["Mixed-event tool records", result.data.total_tool_usage],
    ["Successful event records", result.data.successful_tool_usage],
    ["Mixed-event steps", result.data.total_steps],
  ] as const;
  return (
    <section className="data-panel stats-panel" aria-labelledby="stats-heading">
      <div className="data-panel__heading"><div><p className="card-kicker">Tenant-scoped aggregates</p><h2 id="stats-heading">Mixed recorded events</h2></div></div>
      <dl className="stat-grid">
        {stats.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value.toLocaleString("en-GB")}</dd></div>)}
      </dl>
      <p className="panel-footnote">
        Counts may combine API, orchestrated, agent-origin, and simulation-linked records.
        They are neither measured outcomes nor assurance scores.
      </p>
    </section>
  );
}

function ActivityPanel({ result }: { result: ApiResult<ToolUsage[]> }) {
  if (!result.ok) {
    return <UnavailablePanel title="Recent activity unavailable" detail="Recorded tool activity could not be loaded or validated." />;
  }
  return (
    <section className="data-panel activity-panel" aria-labelledby="activity-heading">
      <div className="data-panel__heading">
        <div><p className="card-kicker">Most recent 8</p><h2 id="activity-heading">Recorded tool activity</h2></div>
        <span className="source-label">Source: attack tracking</span>
      </div>
      {result.data.length === 0 ? (
        <p className="empty-state">No tool usage records exist for this tenant.</p>
      ) : (
        <div className="table-scroll" role="region" aria-label="Recorded tool activity" tabIndex={0}>
          <table>
            <caption className="visually-hidden">Eight most recent tool usage records for this tenant</caption>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Target</th>
                <th>Provenance</th>
                <th>Simulation</th>
                <th>Outcome</th>
                <th>Duration</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {result.data.map((record) => (
                <tr key={record.usage_id}>
                  <td><strong>{record.tool_name}</strong><span className="table-id">{record.mitre_technique_id ?? record.usage_id}</span></td>
                  <td>{record.target ?? "Not reported"}</td>
                  <td>
                    <strong>{classifyActivityProvenance(record)}</strong>
                    <span className="table-id">Invocation: {record.invocation_source ?? "Not reported"}</span>
                  </td>
                  <td><span className="table-id">{record.simulation_id ?? "Not linked"}</span></td>
                  <td><span className={`status-chip ${record.success ? "status-chip--good" : "status-chip--bad"}`}>{record.success ? "Succeeded" : "Failed"}</span></td>
                  <td>{formatDuration(record.duration_seconds)}</td>
                  <td>{formatDateTime(record.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="panel-footnote">A successful tool record does not by itself confirm a security finding.</p>
    </section>
  );
}

function ActivityScopePanel() {
  return (
    <section className="data-panel activity-panel data-panel--scope" aria-labelledby="activity-scope-heading">
      <p className="card-kicker">Role-scoped view</p>
      <h2 id="activity-scope-heading">Raw activity is restricted</h2>
      <p>
        Viewer accounts can see tenant-level aggregates, but per-invocation tool records are
        available only to analyst-capable roles. No raw activity request was made for this view.
      </p>
    </section>
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

export default async function AppOverviewPage() {
  const session = await requireSession("/app");
  if (session.state === "unavailable") {
    return <WorkspaceUnavailable title="Identity service unavailable" detail="The session could not be verified, so tenant data remains hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (hasAuthFailure(billing)) redirect("/sign-in?next=%2Fapp");
  if (!billing.ok) {
    return <WorkspaceUnavailable title="Entitlement unavailable" detail="Billing status could not be verified. Workspace data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const mayViewRawActivity = canViewRawActivity(session.user.role);
  const [health, stats, activity] = await Promise.all([
    fetchHealth(),
    fetchAttackStats(session.token),
    mayViewRawActivity ? fetchRecentToolUsage(session.token) : Promise.resolve(null),
  ]);
  if (hasAuthFailure(stats) || (activity !== null && hasAuthFailure(activity))) {
    redirect("/sign-in?next=%2Fapp");
  }

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Read-only foundation</p>
          <h1>Evidence workspace</h1>
          <p>Live service health and tenant-scoped records. No execution controls are exposed here.</p>
        </div>
        <dl className="identity-card">
          <div><dt>Identity</dt><dd>{session.user.email ?? session.user.user_id}</dd></div>
          <div><dt>Tenant</dt><dd>{session.user.tenant_id}</dd></div>
          <div><dt>Role</dt><dd className="capitalize">{session.user.role.replaceAll("_", " ")}</dd></div>
          <div><dt>Billing</dt><dd className="capitalize">{billingStatusLabel(billing.data.status)}</dd></div>
        </dl>
      </div>
      <div className="dashboard-grid">
        <HealthPanel result={health} />
        <StatsPanel result={stats} />
        {activity === null ? <ActivityScopePanel /> : <ActivityPanel result={activity} />}
      </div>
    </main>
  );
}

function WorkspaceUnavailable({ title, detail }: { title: string; detail: string }) {
  return (
    <main className="centered-state centered-state--app" id="main-content">
      <p className="eyebrow">Access closed</p>
      <h1>{title}</h1>
      <p>{detail}</p>
      <div className="button-row">
        <Link className="button button--light" href="/start-trial">Review billing</Link>
        <Link className="button button--outline-dark" href="/sign-in">Sign in again</Link>
      </div>
    </main>
  );
}
