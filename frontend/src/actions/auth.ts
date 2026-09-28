"use server";

import { redirect } from "next/navigation";
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
    const message =
      token.kind === "unauthorized"
        ? "The email address or password is incorrect."
        : "Sign-in is temporarily unavailable. Please try again shortly.";
    return { status: "error", message };
  }

  const user = await fetchCurrentUser(token.data.access_token);
  const identityMatches =
    user.ok &&
    user.data.tenant_id === token.data.tenant_id &&
    user.data.role === token.data.role;
  if (!identityMatches) {
    return { status: "error", message: "Your session could not be verified. Please try again." };
  }

  await setSessionToken(token.data.access_token);
  redirect(safeReturnPath(formData.get("next")));
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
  redirect("/sign-in");
}
