import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchBillingStatus, fetchExercises } from "@/lib/api/client";
import type { ApiResult } from "@/lib/api/client";
import type { ExerciseList } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { formatDateTime } from "@/lib/format";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Exercises",
  description: "Completed colour-team exercises for this tenant.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

// /api/exercises/ requires analyst or higher (403 for viewers).
const MAY_VIEW_EXERCISES: Record<string, boolean> = {
  admin: true,
  analyst: true,
  viewer: false,
  pilot_sponsor: false,
};

function ExerciseScopePanel() {
  return (
    <section className="data-panel activity-panel data-panel--scope" aria-labelledby="exercise-scope-heading">
      <p className="card-kicker">Role-scoped view</p>
      <h2 id="exercise-scope-heading">Exercises are restricted</h2>
      <p>
        Viewer accounts can see tenant-level aggregates, but exercise records are available
        only to analyst-capable roles. No exercise request was made for this view.
      </p>
    </section>
  );
}

function ExercisesTable({ data }: { data: ExerciseList["exercises"] }) {
  if (data.length === 0) {
    return (
      <p className="empty-state">
        No completed exercises exist for this tenant. Exercises appear here after
        <code> vorsyghta exercise run</code> or an orchestrated run completes.
      </p>
    );
  }
  return (
    <div className="table-scroll" role="region" aria-label="Completed exercises" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Completed exercises for this tenant</caption>
        <thead>
          <tr>
            <th>Exercise</th>
            <th>Status</th>
            <th>Red stages</th>
            <th>Blue alerts</th>
            <th>AAR</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {data.map((exercise) => (
            <tr key={exercise.exercise_id}>
              <td><strong>{exercise.scenario_name}</strong><span className="table-id">{exercise.exercise_id}</span></td>
              <td><span className="table-id">{exercise.status}</span></td>
              <td>{exercise.red_team_stages}</td>
              <td>{exercise.blue_team_alerts}</td>
              <td>
                <span className={`status-chip ${exercise.has_aar ? "status-chip--good" : "status-chip--idle"}`}>
                  {exercise.has_aar ? "Available" : "None"}
                </span>
              </td>
              <td>{formatDateTime(exercise.start_time)}</td>
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

export default async function ExercisesPage() {
  const session = await requireSession("/app/exercises");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so exercise data remains hidden." />;
  }
  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fexercises");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Exercise data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const mayView = MAY_VIEW_EXERCISES[session.user.role] ?? false;
  const exercises: ApiResult<ExerciseList> | null = mayView ? await fetchExercises(session.token) : null;
  if (exercises !== null && !exercises.ok && (exercises.kind === "unauthorized" || exercises.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fexercises");

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #1 — Colour teams + orchestrator</p>
          <h1>Exercises</h1>
          <p>
            Completed colour-team exercises for this tenant. Read-only: run, steer, and halt
            are not exposed in this release.
          </p>
        </div>
        {exercises !== null && exercises.ok ? (
          <dl className="identity-card">
            <div><dt>Exercises</dt><dd>{exercises.data.total.toLocaleString("en-GB")}</dd></div>
          </dl>
        ) : null}
      </div>

      {exercises === null ? (
        <ExerciseScopePanel />
      ) : !exercises.ok ? (
        <UnavailablePanel
          title="Exercises unavailable"
          detail="The exercises endpoint did not return valid data. No substitute data is shown."
        />
      ) : (
        <section className="data-panel" aria-labelledby="exercises-heading">
          <div className="data-panel__heading">
            <div><p className="card-kicker">Completed runs</p><h2 id="exercises-heading">Exercise history</h2></div>
            <span className="source-label">Source: exercises API</span>
          </div>
          <ExercisesTable data={exercises.data.exercises} />
        </section>
      )}
      <p className="panel-footnote">
        Exercise alerts derive from the orchestration path. Until the measured-detection
        milestone lands, detection counts are not assurance scores.
      </p>
    </main>
  );
}
