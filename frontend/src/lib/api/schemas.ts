import { z } from "zod";

import { normalizeApiTimestamp } from "@/lib/time";

const boundedText = z.string().min(1).max(512);
const nullableText = z.string().max(4096).nullable();
const apiTimestampSchema = z
  .string()
  .max(64)
  .transform((value, context) => {
    const normalized = normalizeApiTimestamp(value);
    if (normalized === null) {
      context.addIssue({ code: "custom", message: "Expected an ISO 8601 timestamp" });
      return z.NEVER;
    }
    return normalized;
  });
const nullableDate = apiTimestampSchema.nullable();
const entitledStatuses = new Set(["trialing", "active"]);

export const tokenResponseSchema = z.object({
  access_token: z.string().min(1).max(3800),
  token_type: z.literal("bearer"),
  user_id: boundedText,
  role: z.enum(["admin", "analyst", "viewer", "pilot_sponsor"]),
  tenant_id: boundedText,
  requires_email_verification: z.boolean().optional(),
});

export const currentUserSchema = z.object({
  user_id: boundedText,
  tenant_id: boundedText,
  role: z.enum(["admin", "analyst", "viewer", "pilot_sponsor"]),
  email: z.string().email().max(254).nullable().optional(),
  is_verified: z.boolean().optional(),
  tenant: z.object({ name: z.string() }).optional(),
});

export const registrationResponseSchema = z.object({
  message: z.literal("User registered"),
  tenant_id: boundedText,
  user_id: boundedText,
});

export const billingStatusValueSchema = z.enum([
  "checkout_pending",
  "trialing",
  "active",
  "incomplete",
  "incomplete_expired",
  "past_due",
  "unpaid",
  "paused",
  "canceled",
  "unknown",
]);

export const billingOfferSchema = z
  .object({
    name: z.string().min(1).max(250),
    description: z.string().max(2000).nullable(),
    unit_amount: z.number().int().nonnegative(),
    currency: z.string().regex(/^[A-Za-z]{3}$/),
    interval: z.enum(["day", "week", "month", "year"]),
    interval_count: z.number().int().positive().max(365),
    trial_days: z.literal(14),
  })
  .transform((offer) => {
    return {
      name: offer.name,
      description: offer.description,
      unitAmount: offer.unit_amount,
      currency: offer.currency.toUpperCase(),
      interval: offer.interval,
      intervalCount: offer.interval_count,
      trialDays: offer.trial_days,
    };
  });

export const billingStatusSchema = z
  .object({
    status: billingStatusValueSchema,
    entitled: z.boolean(),
    billing_required: z.boolean(),
    trial_available: z.boolean(),
    checkout_available: z.boolean(),
    portal_available: z.boolean(),
    trial_started_at: nullableDate,
    trial_ends_at: nullableDate,
    entitlement_ends_at: nullableDate,
    cancel_at_period_end: z.boolean(),
  })
  .superRefine((value, context) => {
    if (!value.entitled) return;
    const entitlementEnd = value.entitlement_ends_at;
    const validStatus = entitledStatuses.has(value.status);
    const futureBoundary = entitlementEnd !== null && Date.parse(entitlementEnd) > Date.now();
    if (!validStatus || !futureBoundary) {
      context.addIssue({
        code: "custom",
        path: ["entitled"],
        message: "Entitled billing state requires an active status and future boundary",
      });
    }
  })
  .transform((value) => ({
    status: value.status,
    entitled: value.entitled,
    billingRequired: value.billing_required,
    trialAvailable: value.trial_available,
    checkoutAvailable: value.checkout_available,
    portalAvailable: value.portal_available,
    trialStartedAt: value.trial_started_at,
    trialEnd: value.trial_ends_at,
    entitlementEnd: value.entitlement_ends_at,
    cancelAtPeriodEnd: value.cancel_at_period_end,
  }));

export const hostedUrlSchema = z
  .object({
    url: z.string().url(),
    expires_at: nullableDate.optional(),
  })
  .transform((value) => ({ url: value.url, expiresAt: value.expires_at ?? null }));

export const healthSchema = z
  .object({
    status: z.enum(["healthy", "degraded"]),
    timestamp: apiTimestampSchema,
    version: boundedText,
    components: z.record(z.string().min(1).max(100), z.string().min(1).max(100)),
  })
  .superRefine((value, context) => {
    if (value.status === "healthy" && Object.values(value.components).some((state) => state !== "healthy")) {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Healthy status requires every component to be healthy",
      });
    }
  });

const toolCountSchema = z.object({
  tool: z.string().min(1).max(200),
  count: z.number().int().nonnegative(),
  successes: z.number().int().nonnegative(),
});

export const attackStatsSchema = z
  .object({
    total_sequences: z.number().int().nonnegative(),
    sequences_pending: z.number().int().nonnegative(),
    sequences_running: z.number().int().nonnegative(),
    sequences_completed: z.number().int().nonnegative(),
    sequences_failed: z.number().int().nonnegative(),
    sequences_aborted: z.number().int().nonnegative(),
    total_tool_usage: z.number().int().nonnegative(),
    successful_tool_usage: z.number().int().nonnegative(),
    tools_by_name: z.array(toolCountSchema).max(1000),
    total_steps: z.number().int().nonnegative(),
  })
  .superRefine((value, context) => {
    if (value.tools_by_name.some((tool) => tool.successes > tool.count)) {
      context.addIssue({
        code: "custom",
        path: ["tools_by_name"],
        message: "A tool cannot have more successes than recorded uses",
      });
    }
  });

export const toolUsageSchema = z.object({
  usage_id: boundedText,
  tool_name: z.string().min(1).max(200),
  command: nullableText,
  target: nullableText,
  success: z.boolean(),
  return_code: z.number().int().nullable(),
  duration_seconds: z.number().nonnegative().nullable(),
  timed_out: z.boolean(),
  mitre_technique_id: z.string().max(100).nullable(),
  attack_phase: z.string().max(100).nullable(),
  invoked_by: z.string().max(200).nullable(),
  invocation_source: z.string().max(200).nullable(),
  exercise_id: z.string().max(512).nullable(),
  simulation_id: z.string().max(512).nullable(),
  started_at: nullableDate,
  completed_at: nullableDate,
});

export const toolUsageListSchema = z.array(toolUsageSchema).max(8);

// --- Threat intelligence (read-only MVP surface) -----------------------------

const boundedText2048 = z.string().min(1).max(2048);
const optionalBoundedText = z.string().max(2048).nullable();
const stringList = z.array(z.string().max(256)).max(200);

export const threatActorSchema = z.object({
  actor_id: boundedText2048,
  name: boundedText2048,
  aliases: stringList,
  description: optionalBoundedText,
  actor_type: boundedText,
  target_industries: stringList,
  target_regions: stringList,
  sophistication_level: z.number().int().min(0).max(100).nullable(),
  primary_motivation: optionalBoundedText,
  is_active: z.boolean(),
  confidence_level: boundedText,
  sources: stringList,
  shared_with_teams: stringList,
  first_seen: nullableDate,
  last_seen: nullableDate,
  created_at: apiTimestampSchema,
  updated_at: nullableDate,
});

export const threatCampaignSchema = z.object({
  campaign_id: boundedText2048,
  actor_id: boundedText2048,
  name: boundedText2048,
  description: optionalBoundedText,
  campaign_status: boundedText,
  start_date: nullableDate,
  end_date: nullableDate,
  target_organizations: stringList,
  target_sectors: stringList,
  target_geography: stringList,
  mitre_techniques: stringList,
  mitre_tactics: stringList,
  impact_assessment: optionalBoundedText,
  estimated_impact_usd: z.number().nullable(),
  confidence_level: boundedText,
  sources: stringList,
  shared_with_teams: stringList,
  created_at: apiTimestampSchema,
  updated_at: nullableDate,
});

export const threatIndicatorSchema = z.object({
  indicator_id: boundedText2048,
  campaign_id: boundedText2048,
  indicator_type: boundedText,
  indicator_value: boundedText2048,
  description: optionalBoundedText,
  indicator_state: boundedText,
  threat_score: z.number().int().min(0).max(100).nullable(),
  confidence_level: boundedText,
  mitre_technique: optionalBoundedText,
  sources: stringList,
  first_seen: nullableDate,
  last_seen: nullableDate,
  created_at: apiTimestampSchema,
});

export const threatTtpSchema = z.object({
  ttp_id: boundedText2048,
  campaign_id: boundedText2048,
  mitre_technique_id: optionalBoundedText,
  mitre_tactic: optionalBoundedText,
  ttp_name: boundedText2048,
  ttp_category: boundedText,
  description: optionalBoundedText,
  observed_procedure: optionalBoundedText,
  detection_recommendations: optionalBoundedText,
  detection_data_sources: stringList,
  confidence_level: boundedText,
  sources: stringList,
  shared_with_teams: stringList,
  created_at: apiTimestampSchema,
});

export const threatIntelListsSchema = z.object({
  actors: z.array(threatActorSchema).max(200),
  campaigns: z.array(threatCampaignSchema).max(200),
  indicators: z.array(threatIndicatorSchema).max(200),
  ttps: z.array(threatTtpSchema).max(200),
});

// --- Scenario templates (browse + validate only, never execution) ------------

export const templateSummarySchema = z.object({
  category: boundedText,
  name: boundedText,
  file: boundedText,
  threat_type: optionalBoundedText,
  severity: optionalBoundedText,
  target_role: optionalBoundedText,
});

export const templateCatalogSchema = z.object({
  categories: z.record(z.string().max(64), z.array(templateSummarySchema).max(500)),
  total: z.number().int().nonnegative(),
});

export const templateDetailSchema = z.object({
  category: boundedText,
  file: boundedText,
  content: z.record(z.string().max(128), z.unknown()),
});

// --- Findings register (read-only view of recorded attack results) -----------

export const findingRecordSchema = z.object({
  sequence_id: boundedText2048,
  name: optionalBoundedText,
  description: optionalBoundedText,
  status: boundedText,
  total_steps: z.number().int().nonnegative(),
  completed_steps: z.number().int().nonnegative(),
  successful_steps: z.number().int().nonnegative(),
  failed_steps: z.number().int().nonnegative(),
  overall_success: z.boolean().nullable(),
  target_system: optionalBoundedText,
  exercise_id: optionalBoundedText,
  created_at: nullableDate,
});

export const findingListSchema = z.array(findingRecordSchema).max(200);

// --- Onboarding (post-registration wizard; persisted as knowledge entries) ---

const COMPLIANCE_FRAMEWORKS = ["pci_dss", "ndpr", "gdpr", "soc_2", "iso_27001", "cbn", "hipaa"] as const;
const ADAPTER_CATEGORIES = ["containers", "cloud", "files", "web_apps_apis", "external_infrastructure", "directories_crm", "media"] as const;
const CAPABILITIES = ["colour_teams", "intelligence_stack", "zero_day_research", "quantum_pqc", "saas_product", "simulation_paradigms", "rl_rlhf"] as const;
const PERSONAS = ["ciso", "red_team_lead", "analyst", "pilot_sponsor"] as const;
const MATURITIES = ["none", "ad_hoc", "defined", "managed"] as const;

export const onboardingProfileSchema = z.object({
  industry: z.string().trim().min(2).max(80),
  company_size: z.enum(["1-10", "11-50", "51-200", "201-1000", "1000+"]),
  regions: z.string().trim().min(2).max(160),
  security_maturity: z.enum(MATURITIES),
  compliance_frameworks: z.array(z.enum(COMPLIANCE_FRAMEWORKS)).max(COMPLIANCE_FRAMEWORKS.length),
});

export const onboardingUseCasesSchema = z.object({
  capabilities: z.array(z.enum(CAPABILITIES)).min(1).max(CAPABILITIES.length),
  persona: z.enum(PERSONAS),
  success_criteria: z.string().trim().max(600),
});

export const onboardingEnvironmentsSchema = z.object({
  adapter_categories: z.array(z.enum(ADAPTER_CATEGORIES)).max(ADAPTER_CATEGORIES.length),
  cloud_providers: z.array(z.enum(["aws", "azure", "gcp", "huawei"])).max(4),
  sanctioned_targets_only: z.literal(true),
});

export const onboardingReviewSchema = z.object({
  terms_accepted: z.literal(true),
  acceptable_use_accepted: z.literal(true),
});

// --- Exercise console (read-only view of completed colour-team exercises) ----

export const exerciseSummarySchema = z.object({
  exercise_id: z.string().min(1).max(64),
  scenario_name: z.string().min(1).max(256),
  status: z.string().min(1).max(40),
  start_time: apiTimestampSchema,
  end_time: nullableDate,
  red_team_stages: z.number().int().nonnegative(),
  blue_team_alerts: z.number().int().nonnegative(),
  has_aar: z.boolean(),
  has_score: z.boolean(),
});

export const exerciseListSchema = z.object({
  total: z.number().int().nonnegative(),
  exercises: z.array(exerciseSummarySchema).max(200),
});

// --- Disclosure register (read-only view of the CVD lifecycle) ---------------

export const disclosureRecordSchema = z.object({
  id: z.string().min(1).max(64),
  engagement_id: z.string().min(1).max(64),
  finding_id: z.string().min(1).max(64),
  title: z.string().min(1).max(512),
  cve_id: z.string().max(32).nullable(),
  severity: z.enum(["critical", "high", "medium", "low", "info", "unknown"]),
  cvss_score: z.number().min(0).max(10),
  vendor: z.string().min(1).max(256),
  product: z.string().min(1).max(256),
  status: z.string().min(1).max(64),
  vendor_response: z.string().max(64),
  notified_at: z.string().max(64).nullable(),
  patch_released_at: z.string().max(64).nullable(),
  public_disclosure_date: z.string().max(64).nullable(),
  embargo_end_date: z.string().max(64).nullable(),
  embargo_days: z.number().int().nonnegative(),
  days_until_disclosure: z.number().int(),
});

export const disclosureListSchema = z.array(disclosureRecordSchema).max(200);

export type TokenResponse = z.infer<typeof tokenResponseSchema>;
export type CurrentUser = z.infer<typeof currentUserSchema>;
export type ThreatActor = z.infer<typeof threatActorSchema>;
export type ThreatCampaign = z.infer<typeof threatCampaignSchema>;
export type ThreatIndicator = z.infer<typeof threatIndicatorSchema>;
export type ThreatTtp = z.infer<typeof threatTtpSchema>;
export type ThreatIntelLists = z.infer<typeof threatIntelListsSchema>;
export type TemplateSummary = z.infer<typeof templateSummarySchema>;
export type TemplateCatalog = z.infer<typeof templateCatalogSchema>;
export type TemplateDetail = z.infer<typeof templateDetailSchema>;
export type FindingRecord = z.infer<typeof findingRecordSchema>;
export type FindingList = z.infer<typeof findingListSchema>;
export type OnboardingProfile = z.infer<typeof onboardingProfileSchema>;
export type OnboardingUseCases = z.infer<typeof onboardingUseCasesSchema>;
export type OnboardingEnvironments = z.infer<typeof onboardingEnvironmentsSchema>;
export type ExerciseSummary = z.infer<typeof exerciseSummarySchema>;
export type ExerciseList = z.infer<typeof exerciseListSchema>;
export type DisclosureRecord = z.infer<typeof disclosureRecordSchema>;
export type DisclosureList = z.infer<typeof disclosureListSchema>;
export type BillingOffer = z.infer<typeof billingOfferSchema>;
export type BillingStatus = z.infer<typeof billingStatusSchema>;
export type BillingStatusValue = z.infer<typeof billingStatusValueSchema>;
export type Health = z.infer<typeof healthSchema>;
export type AttackStats = z.infer<typeof attackStatsSchema>;
export type ToolUsage = z.infer<typeof toolUsageSchema>;
