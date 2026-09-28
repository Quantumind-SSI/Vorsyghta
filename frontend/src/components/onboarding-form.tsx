"use client";

import { useActionState } from "react";

import type { ActionState } from "@/lib/action-state";
import { initialActionState } from "@/lib/action-state";
import { SubmitButton } from "@/components/submit-button";

type OnboardingAction = (state: ActionState, formData: FormData) => Promise<ActionState>;

type OnboardingFormProps = {
  action: OnboardingAction;
  submitLabel: string;
  children: React.ReactNode;
};

export function OnboardingForm({ action, submitLabel, children }: OnboardingFormProps) {
  const [state, formAction] = useActionState(action, initialActionState);

  return (
    <form action={formAction}>
      {state.status === "error" ? (
        <p className="form-message form-message--error" role="alert">
          {state.message}
        </p>
      ) : null}
      {children}
      <div className="onboarding-actions">
        <SubmitButton pendingLabel="Saving...">{submitLabel}</SubmitButton>
      </div>
    </form>
  );
}
