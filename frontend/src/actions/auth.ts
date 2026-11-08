"use server";

import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { z } from "zod";

import { authenticate, fetchCurrentUser, registerAccount } from "@/lib/api/client";
import type { ActionState } from "@/lib/action-state";
import { safeReturnPath } from "@/lib/navigation";
import { registrationInputSchema } from "@/lib/registration";
import { clearSession, setSessionToken } from "@/lib/session";

const credentialsSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(1024),
});

export async function signInAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const credentials = credentialsSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
  if (!credentials.success) {
    const emailInvalid = credentials.error.issues.some((issue) => issue.path[0] === "email");
    return emailInvalid
      ? { status: "error", field: "email", message: "Enter a valid email address." }
      : { status: "error", field: "password", message: "Enter your password." };
  }

  const token = await authenticate(credentials.data.email, credentials.data.password);
  if (!token.ok) {
    if (token.kind === "unavailable") {
      return { status: "error", message: "API is temporarily unavailable. Please try again shortly." };
    }
    if (token.kind === "request-failed") {
      return { status: "error", message: "Network error. Please check your connection and try again." };
    }
    if (token.kind === "invalid-response") {
      return { status: "error", message: "Service configuration error. Please contact support." };
    }
    return {
      status: "error",
      message:
        token.kind === "unauthorized"
          ? "Invalid email or password."
          : "Sign-in is temporarily unavailable. Please try again shortly.",
    };
  }
  if ((token as any).data.requires_email_verification) {
    await setSessionToken((token as any).data.access_token);
    redirect("/app");
  }

  const tokenUser = {
    user_id: (token as any).data.user_id,
    tenant_id: (token as any).data.tenant_id,
    role: (token as any).data.role,
  };

  const user = await fetchCurrentUser((token as any).data.access_token);
  const identityMatches =
    user.ok &&
    user.data.tenant_id === tokenUser.tenant_id &&
    user.data.role === tokenUser.role &&
    user.data.user_id === tokenUser.user_id;
  if (!identityMatches) {
    return { status: "error", message: "Your session could not be verified. Please try again." };
  }

  await setSessionToken((token as any).data.access_token);

  // Redirect based on onboarding completion from DB
  const onboardingComplete = user.ok && user.data.onboarding_complete;
  redirect(onboardingComplete ? "/app" : "/onboarding");
}

export async function registerAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const registration = registrationInputSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
    organization_name: formData.get("organization_name"),
  });
  if (!registration.success) {
    const field = registration.error.issues[0]?.path[0];
    if (field === "email") {
      return { status: "error", field, message: "Enter a valid email address." };
    }
    if (field === "organization_name") {
      return { status: "error", field, message: "Enter an organization name between 2 and 120 characters." };
    }
    return { status: "error", field: "password", message: "Use 12 to 72 characters and no more than 72 UTF-8 bytes." };
  }

  const result = await registerAccount(registration.data);
  if (!result.ok) {
    const message =
      result.kind === "conflict"
        ? "Registration could not be completed with these details. Sign in or use another email address."
        : "Registration is temporarily unavailable. Please try again shortly.";
    return { status: "error", message };
  }

  const next = safeReturnPath(formData.get("next"));
  if (next !== "/app" && next.startsWith("/app/")) {
    redirect(`/sign-in?${new URLSearchParams({ status: "account-created", next }).toString()}`);
  }
  redirect("/onboarding");
}

export async function signOutAction(): Promise<void> {
  await clearSession();
  // onboarding_complete cookie is intentionally preserved across sign-outs
  // so users do not repeat onboarding
  redirect("/sign-in");
}
