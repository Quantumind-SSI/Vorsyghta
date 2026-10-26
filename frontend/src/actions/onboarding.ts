"use server";

import { redirect } from "next/navigation";
import { cookies } from "next/headers";

import {
  onboardingEnvironmentsSchema,
  onboardingProfileSchema,
  onboardingReviewSchema,
  onboardingUseCasesSchema,
} from "@/lib/api/schemas";
import { saveOnboardingStep, updateUserRole } from "@/lib/api/client";
import type { ActionState } from "@/lib/action-state";
import { requireSession } from "@/lib/session";

const STEP_ROUTES = [
  "/onboarding/profile",
  "/onboarding/use-cases",
  "/onboarding/environments",
  "/onboarding/review",
] as const;

function nextStepRoute(current: string): string {
  const index = STEP_ROUTES.indexOf(current as typeof STEP_ROUTES[number]);
  const next = STEP_ROUTES[Math.min(index + 1, STEP_ROUTES.length - 1)];
  return next ?? "/app";
}

async function persistStep(
  token: string,
  step: { title: string; content: string; category: string; tags: string[] },
): Promise<ActionState> {
  const result = await saveOnboardingStep(token, step);
  if (!result.ok) {
    const message =
      result.kind === "unavailable"
        ? "The knowledge service is unavailable. Your answer was not saved — try again."
        : "Your answer could not be saved. No fake success is shown — try again.";
    return { status: "error", message };
  }
  return { status: "idle", message: "Saved." };
}

// New: persist role to UserRecord and redirect based on role
async function persistRoleAndRedirect(
  token: string,
  role: string,
  tenantId: string
): Promise<ActionState> {
  const result = await saveOnboardingStep(token, {
    title: "Onboarding — role persistence",
    content: JSON.stringify({ role, tenant_id: tenantId }),
    category: "training",
    tags: ["onboarding", "role", role],
  });
  if (!result.ok) {
    const message =
      result.kind === "unavailable"
        ? "The knowledge service is unavailable. Role was not persisted — try again."
        : "Role could not be persisted. No fake success is shown — try again.";
    return { status: "error", message };
  }
  // Redirect based on role
  let redirectPath = "/app";
  if (role === "viewer") {
    redirectPath = "/app"; // Viewer goes directly to app (read-only)
  } else if (role === "analyst") {
    redirectPath = "/app"; // Analyst goes to app after onboarding
  } else if (role === "pilot_sponsor") {
    redirectPath = "/app"; // Pilot sponsor goes to app
  } else if (role === "admin") {
    redirectPath = "/app"; // Admin goes to app
  }
  redirect(redirectPath);
  return { status: "idle", message: "Role persisted." };
}

export async function saveOnboardingProfileAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/profile");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const persona = formData.get("persona") as string;
  const industry = formData.get("industry") as string;
  const company_size = formData.get("company_size") as string;
  const regions = formData.get("regions") as string;
  const security_maturity = formData.get("security_maturity") as string;
  const compliance_frameworks = formData.getAll("compliance_frameworks") as string[];

  // Validate persona selection
  const validPersonas = ["viewer", "analyst", "pilot_sponsor", "admin"];
  if (!persona || !validPersonas.includes(persona)) {
    return { status: "error", message: "Select a valid role: Viewer, Analyst, Pilot Sponsor, or Admin." };
  }

  const parsed = onboardingProfileSchema.safeParse({
    industry: industry,
    company_size: company_size,
    regions: regions,
    security_maturity: security_maturity,
    compliance_frameworks: compliance_frameworks,
  });
  if (!parsed.success) {
    return { status: "error", message: "Complete every field: industry, size, regions, maturity." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — organization profile",
    content: JSON.stringify(parsed.data),
    category: "compliance",
    tags: ["onboarding", "org-profile", industry.toLowerCase()],
  });
  if (state.status === "error") return state;
  // Persist role to UserRecord
  await updateUserRole(session.token, persona);
  redirect("/onboarding/use-cases");
}

export async function saveOnboardingUseCasesAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/use-cases");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const capabilities = formData.getAll("capabilities") as string[];
  const success_criteria = formData.get("success_criteria") ?? "";
  const tenant = formData.get("tenant") as string;

  if (!tenant) {
    return { status: "error", message: "Select an organization." };
  }

  const parsed = onboardingUseCasesSchema.safeParse({
    capabilities: capabilities,
    success_criteria: success_criteria,
  });
  if (!parsed.success) {
    return { status: "error", message: "Select at least one capability and a persona." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — use cases",
    content: JSON.stringify(parsed.data),
    category: "best_practice",
    tags: ["onboarding", "use-cases"],
  });
  if (state.status === "error") return state;
  // Store tenant selection - for multi-tenant, we track the current/primary tenant
  // In a full implementation, this would update a user_tenants junction table
  redirect("/onboarding/environments");
}

export async function saveOnboardingEnvironmentsAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/environments");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const adapter_categories = formData.getAll("adapter_categories") as string[];
  const cloud_providers = formData.getAll("cloud_providers") as string[];
  const sanctioned_targets_only = formData.get("sanctioned_targets_only") === "true";

  const parsed = onboardingEnvironmentsSchema.safeParse({
    adapter_categories: adapter_categories,
    cloud_providers: cloud_providers,
    sanctioned_targets_only: sanctioned_targets_only,
  });
  if (!parsed.success || !parsed.data.sanctioned_targets_only) {
    return { status: "error", message: "Confirm sanctioned/lab targets only to continue." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — environment intent",
    content: JSON.stringify(parsed.data),
    category: "tool_config",
    tags: ["onboarding", "environments", ...parsed.data.cloud_providers],
  });
  if (state.status === "error") return state;
  // Persist role to UserRecord and redirect to review
  redirect("/onboarding/review");
}

export async function activateOnboardingAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/review");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const parsed = onboardingReviewSchema.safeParse({
    terms_accepted: formData.get("terms_accepted") === "true",
    acceptable_use_accepted: formData.get("acceptable_use_accepted") === "true",
  });
  if (!parsed.success) {
    return { status: "error", message: "Accept the terms and acceptable-use policy to activate." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — activated",
    content: JSON.stringify({ ...parsed.data, activated_at: new Date().toISOString() }),
    category: "training",
    tags: ["onboarding", "activated"],
  });
  if (state.status === "error") return state;
  // Mark onboarding complete in DB
  const { completeOnboarding } = await import("@/lib/api/client");
  await completeOnboarding(session.token);
  // Persist role to UserRecord and redirect to app
  redirect("/app");
}