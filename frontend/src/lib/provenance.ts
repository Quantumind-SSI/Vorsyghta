import type { CurrentUser, ToolUsage } from "@/lib/api/schemas";

export type ActivityProvenance =
  | "Agent-origin event"
  | "Origin not reported"
  | "Recorded event"
  | "Simulation-linked event"
  | "Simulation-linked, agent-origin event";

export function canViewRawActivity(role: CurrentUser["role"]): boolean {
  return role !== "viewer";
}

export function classifyActivityProvenance(
  record: Pick<ToolUsage, "invocation_source" | "simulation_id">,
): ActivityProvenance {
  const source = record.invocation_source?.trim().toLowerCase() ?? "";
  const simulationLinked = Boolean(record.simulation_id?.trim()) || source.includes("simulat");
  const agentOrigin = /(^|[^a-z])(agent|autonomous|llm)([^a-z]|$)/.test(source);
  if (simulationLinked && agentOrigin) return "Simulation-linked, agent-origin event";
  if (simulationLinked) return "Simulation-linked event";
  if (agentOrigin) return "Agent-origin event";
  return source ? "Recorded event" : "Origin not reported";
}
