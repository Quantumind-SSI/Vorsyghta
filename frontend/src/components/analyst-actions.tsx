"use client";
import { useState } from "react";

export function AnalystActions() {
  const [status, setStatus] = useState<string | null>(null);
  const [traces, setTraces] = useState<string[]>([]);
  const [hasTarget, setHasTarget] = useState(false);

  // Placeholder target check – replace with real API call to list environments/targets
  const checkTarget = () => {
    // TODO: fetch environments and verify connected target exists for tenant
    // For now assume no target connected
    return false;
  };

  const run = async (team: string) => {
    if (!checkTarget()) {
      setStatus("Action blocked: no connected target");
      setTraces((t) => [...t, "Rule enforced – actions require a connected target"]);
      return;
    }
    setStatus(`Starting ${team} team activity...`);
    setTraces([`Requesting ${team} team run`]);
    try {
      const res = await fetch("http://localhost:8001/api/exercises/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_name: `${team} team exercise`,
          threat_type: "CUSTOM",
          teams: [team],
          target_systems: [],
          attack_vectors: [],
        }),
      });
      const data = await res.json();
      setStatus(`Exercise ${data.exercise_id} started`);
      setTraces((t) => [...t, `Exercise ID: ${data.exercise_id}`, `Status: ${data.status}`]);
    } catch (e: any) {
      setStatus("Failed to start activity");
      setTraces((t) => [...t, `Error: ${e.message}`]);
    }
  };

  return (
    <div>
      <div className="button-row">
        <button className="button button--light" disabled={!checkTarget()} onClick={() => run("red")}>Start Red Team Activity</button>
        <button className="button button--light" disabled={!checkTarget()} onClick={() => run("blue")}>Start Blue Team Activity</button>
        <button className="button button--light" disabled={!checkTarget()} onClick={() => run("purple")}>Start Purple Team Activity</button>
      </div>
      {!checkTarget() && (
        <p className="panel-footnote">Actions are blocked until a connected target is configured for this tenant.</p>
      )}
      {status && <p className="panel-footnote">{status}</p>}
      {traces.length > 0 && (
        <pre className="data-panel" style={{ whiteSpace: "pre-wrap" }}>
          {traces.join("\n")}
        </pre>
      )}
    </div>
  );
}
