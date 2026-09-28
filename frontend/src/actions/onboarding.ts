"use server";

import { redirect } from "next/navigation";

import {
  onboardingEnvironmentsSchema,
  onboardingProfileSchema,
  onboardingReviewSchema,
  onboardingUseCasesSchema,
} from "@/lib/api/schemas";
import { saveOnboardingStep } from "@/lib/api/client";
import type { ActionState } from "@/lib/action-state";
import { requireSession } from "@/lib/session";

const STEP_ROUTES = ["/onboarding/profile", "/onboarding/use-cases", "/onboarding/environments", "/onboarding/review"] as const;

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

export async function saveOnboardingProfileAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/profile");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const parsed = onboardingProfileSchema.safeParse({
    industry: formData.get("industry"),
    company_size: formData.get("company_size"),
    regions: formData.get("regions"),
    security_maturity: formData.get("security_maturity"),
    compliance_frameworks: formData.getAll("compliance_frameworks"),
  });
  if (!parsed.success) {
    return { status: "error", message: "Complete every field: industry, size, regions, maturity." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — organization profile",
    content: JSON.stringify(parsed.data),
    category: "compliance",
    tags: ["onboarding", "org-profile", parsed.data.industry.toLowerCase()],
  });
  if (state.status === "error") return state;
  redirect(nextStepRoute("/onboarding/profile"));
}

export async function saveOnboardingUseCasesAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/use-cases");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const parsed = onboardingUseCasesSchema.safeParse({
    capabilities: formData.getAll("capabilities"),
    persona: formData.get("persona"),
    success_criteria: formData.get("success_criteria") ?? "",
  });
  if (!parsed.success) {
    return { status: "error", message: "Select at least one capability and a persona." };
  }
  const state = await persistStep(session.token, {
    title: "Onboarding — use cases",
    content: JSON.stringify(parsed.data),
    category: "best_practice",
    tags: ["onboarding", "use-cases", parsed.data.persona],
  });
  if (state.status === "error") return state;
  redirect(nextStepRoute("/onboarding/use-cases"));
}

export async function saveOnboardingEnvironmentsAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const session = await requireSession("/onboarding/environments");
  if (session.state === "unavailable") {
    return { status: "error", message: "Identity service unavailable. Sign in again." };
  }
  const parsed = onboardingEnvironmentsSchema.safeParse({
    adapter_categories: formData.getAll("adapter_categories"),
    cloud_providers: formData.getAll("cloud_providers"),
    sanctioned_targets_only: formData.get("sanctioned_targets_only") === "true",
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
  redirect(nextStepRoute("/onboarding/environments"));
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
  redirect("/app");
}
