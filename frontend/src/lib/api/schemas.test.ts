import { describe, expect, it } from "vitest";

import {
  attackStatsSchema,
  billingOfferSchema,
  billingStatusSchema,
  findingListSchema,
  healthSchema,
  registrationResponseSchema,
  templateCatalogSchema,
  templateDetailSchema,
  threatIntelListsSchema,
  toolUsageListSchema,
} from "@/lib/api/schemas";

describe("FastAPI response validation", () => {
  it("normalizes a complete billing offer", () => {
    const result = billingOfferSchema.parse({
      name: "Vorsyghta Team",
      description: "Team subscription",
      unit_amount: 4900,
      currency: "gbp",
      interval: "month",
      interval_count: 1,
      trial_days: 14,
    });

    expect(result).toEqual({
      name: "Vorsyghta Team",
      description: "Team subscription",
      unitAmount: 4900,
      currency: "GBP",
      interval: "month",
      intervalCount: 1,
      trialDays: 14,
    });
  });

  it("rejects incomplete configured offer data", () => {
    const result = billingOfferSchema.safeParse({
      name: "Vorsyghta Team",
      description: null,
      currency: "GBP",
      trial_days: 14,
    });

    expect(result.success).toBe(false);
  });

  it("normalizes the exact billing status contract", () => {
    const status = billingStatusSchema.parse({
      status: "trialing",
      entitled: true,
      billing_required: true,
      trial_available: true,
      checkout_available: false,
      portal_available: true,
      trial_started_at: "2026-09-14T12:00:00",
      trial_ends_at: "2999-09-28T12:00:00Z",
      entitlement_ends_at: "2999-09-28T12:00:00Z",
      cancel_at_period_end: false,
    });

    expect(status.status).toBe("trialing");
    expect(status.entitled).toBe(true);
    expect(status.trialStartedAt).toBe("2026-09-14T12:00:00.000Z");
    expect(status.trialEnd).toBe("2999-09-28T12:00:00.000Z");
    expect(billingStatusSchema.safeParse({ status: "active", entitled: true }).success).toBe(false);
  });

  it("rejects semantically invalid entitled billing responses", () => {
    const base = {
      entitled: true,
      billing_required: true,
      trial_available: true,
      checkout_available: false,
      portal_available: true,
      trial_started_at: null,
      trial_ends_at: null,
      entitlement_ends_at: "2999-01-01T00:00:00Z",
      cancel_at_period_end: false,
    };
    expect(billingStatusSchema.safeParse({ ...base, status: "canceled" }).success).toBe(false);
    expect(
      billingStatusSchema.safeParse({
        ...base,
        status: "active",
        entitlement_ends_at: "2000-01-01T00:00:00Z",
      }).success,
    ).toBe(false);
    expect(
      billingStatusSchema.safeParse({ ...base, status: "trialing", entitlement_ends_at: null })
        .success,
    ).toBe(false);
  });

  it("validates the registration response without exposing identifiers to the browser", () => {
    expect(
      registrationResponseSchema.parse({
        message: "User registered",
        tenant_id: "tenant_123",
        user_id: "user_123",
      }),
    ).toEqual({
      message: "User registered",
      tenant_id: "tenant_123",
      user_id: "user_123",
    });
    expect(
      registrationResponseSchema.safeParse({ message: "Created", tenant_id: "tenant_123" })
        .success,
    ).toBe(false);
  });

  it("rejects malformed health and tracking responses", () => {
    expect(healthSchema.safeParse({ status: "healthy", components: [] }).success).toBe(false);
    expect(
      attackStatsSchema.safeParse({
        total_sequences: -1,
        sequences_pending: 0,
        sequences_running: 0,
        sequences_completed: 0,
        sequences_failed: 0,
        sequences_aborted: 0,
        total_tool_usage: 0,
        successful_tool_usage: 0,
        tools_by_name: [],
        total_steps: 0,
      }).success,
    ).toBe(false);
  });

  it("rejects contradictory health and per-tool aggregates", () => {
    expect(
      healthSchema.safeParse({
        status: "healthy",
        timestamp: "2026-09-14T12:00:00Z",
        version: "0.1.0",
        components: { api: "healthy", database: "unavailable" },
      }).success,
    ).toBe(false);
    expect(
      attackStatsSchema.safeParse({
        total_sequences: 2,
        sequences_pending: 0,
        sequences_running: 0,
        sequences_completed: 2,
        sequences_failed: 0,
        sequences_aborted: 0,
        total_tool_usage: 1,
        successful_tool_usage: 1,
        tools_by_name: [{ tool: "nmap", count: 1, successes: 2 }],
        total_steps: 1,
      }).success,
    ).toBe(false);
  });

  it("bounds recent activity to the requested eight records", () => {
    const record = {
      usage_id: "usage-1",
      tool_name: "nmap",
      command: null,
      target: "lab-target",
      success: true,
      return_code: 0,
      duration_seconds: 1.2,
      timed_out: false,
      mitre_technique_id: null,
      attack_phase: null,
      invoked_by: null,
      invocation_source: null,
      exercise_id: null,
      simulation_id: null,
      started_at: "2026-09-14T10:00:00Z",
      completed_at: "2026-09-14T10:00:01Z",
    };

    expect(toolUsageListSchema.safeParse(Array.from({ length: 8 }, () => record)).success).toBe(true);
    expect(toolUsageListSchema.safeParse(Array.from({ length: 9 }, () => record)).success).toBe(false);
  });

  it("validates the threat intelligence aggregate contract", () => {
    const result = threatIntelListsSchema.parse({
      actors: [
        {
          actor_id: "actor-1",
          name: "Financial Threat Group",
          aliases: ["FTG"],
          description: null,
          actor_type: "organized",
          target_industries: ["fintech"],
          target_regions: ["EU"],
          sophistication_level: 80,
          primary_motivation: "financial",
          is_active: true,
          confidence_level: "high",
          sources: ["nvd"],
          shared_with_teams: ["red", "blue"],
          first_seen: "2026-01-01T00:00:00Z",
          last_seen: "2026-09-01T00:00:00Z",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: null,
        },
      ],
      campaigns: [],
      indicators: [
        {
          indicator_id: "ind-1",
          campaign_id: "camp-1",
          indicator_type: "ip",
          indicator_value: "203.0.113.10",
          description: null,
          indicator_state: "active",
          threat_score: 70,
          confidence_level: "medium",
          mitre_technique: "T1071",
          sources: [],
          first_seen: null,
          last_seen: null,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      ttps: [],
    });

    expect(result.actors).toHaveLength(1);
    expect(result.actors[0]?.name).toBe("Financial Threat Group");
    expect(result.indicators[0]?.indicator_value).toBe("203.0.113.10");
    expect(result.campaigns).toEqual([]);
  });

  it("rejects malformed threat intelligence records", () => {
    const base = {
      actors: [],
      campaigns: [],
      indicators: [],
      ttps: [],
    };
    expect(
      threatIntelListsSchema.safeParse({
        ...base,
        actors: [{ actor_id: "actor-1", name: "X", actor_type: "type", is_active: "yes" }],
      }).success,
    ).toBe(false);
    expect(
      threatIntelListsSchema.safeParse({
        ...base,
        indicators: [{ indicator_id: "ind-1", indicator_type: "ip", indicator_value: "", indicator_state: "active" }],
      }).success,
    ).toBe(false);
  });

  it("validates the template catalog and detail contracts", () => {
    const catalog = templateCatalogSchema.parse({
      categories: {
        root: [{ category: "root", name: "executive_phishing", file: "executive_phishing.yaml", threat_type: "phishing", severity: "high", target_role: "executive" }],
        zestpayment: [],
      },
      total: 1,
    });
    expect(catalog.total).toBe(1);
    expect(catalog.categories.root?.[0]?.severity).toBe("high");
    expect(templateCatalogSchema.safeParse({ categories: {}, total: -1 }).success).toBe(false);
    expect(
      templateCatalogSchema.safeParse({ categories: { root: [{ category: "root", name: "", file: "x.yaml" }] }, total: 1 }).success,
    ).toBe(false);
    expect(
      templateDetailSchema.safeParse({ category: "root", file: "x.yaml", content: "not-an-object" }).success,
    ).toBe(false);
    expect(templateDetailSchema.parse({ category: "root", file: "x.yaml", content: { template_id: "x_v1" } }).content).toEqual({
      template_id: "x_v1",
    });
  });

  it("validates the findings register contract", () => {
    const record = {
      sequence_id: "seq-1",
      name: "BEC sequence",
      description: null,
      status: "completed",
      total_steps: 5,
      completed_steps: 5,
      successful_steps: 4,
      failed_steps: 1,
      overall_success: true,
      target_system: "lab-target",
      exercise_id: null,
      created_at: "2026-09-14T10:00:00Z",
    };
    expect(findingListSchema.parse([record])[0]?.status).toBe("completed");
    expect(findingListSchema.safeParse([{ ...record, total_steps: -1 }]).success).toBe(false);
    expect(findingListSchema.safeParse([{ ...record, sequence_id: "" }]).success).toBe(false);
    expect(findingListSchema.safeParse([{ ...record, status: 7 }]).success).toBe(false);
  });
});
