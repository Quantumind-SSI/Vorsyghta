import { describe, expect, it } from "vitest";

import { canViewRawActivity, classifyActivityProvenance } from "@/lib/provenance";

describe("activity access scope", () => {
  it("does not expose raw activity to viewer users", () => {
    expect(canViewRawActivity("viewer")).toBe(false);
    expect(canViewRawActivity("analyst")).toBe(true);
    expect(canViewRawActivity("pilot_sponsor")).toBe(true);
    expect(canViewRawActivity("admin")).toBe(true);
  });
});

describe("activity provenance", () => {
  it("labels simulation and agent origins without calling them measured", () => {
    expect(
      classifyActivityProvenance({ invocation_source: "sequence_orchestrator", simulation_id: "sim-1" }),
    ).toBe("Simulation-linked event");
    expect(
      classifyActivityProvenance({ invocation_source: "ai_attack_agent", simulation_id: null }),
    ).toBe("Agent-origin event");
    expect(
      classifyActivityProvenance({ invocation_source: "autonomous_agent", simulation_id: "sim-2" }),
    ).toBe("Simulation-linked, agent-origin event");
  });

  it("keeps ordinary and unknown origins explicit", () => {
    expect(classifyActivityProvenance({ invocation_source: "api", simulation_id: null })).toBe(
      "Recorded event",
    );
    expect(classifyActivityProvenance({ invocation_source: null, simulation_id: null })).toBe(
      "Origin not reported",
    );
  });
});
