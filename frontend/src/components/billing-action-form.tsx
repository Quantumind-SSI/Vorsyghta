"use client";

import { useActionState } from "react";

import type { ActionState } from "@/lib/action-state";
import { initialActionState } from "@/lib/action-state";
import { SubmitButton } from "@/components/submit-button";

type BillingAction = (state: ActionState, formData: FormData) => Promise<ActionState>;

type BillingActionFormProps = {
  action: BillingAction;
  label: string;
  pendingLabel: string;
  secondary?: boolean;
};

export function BillingActionForm({
  action,
  label,
  pendingLabel,
  secondary = false,
}: BillingActionFormProps) {
  const [state, formAction] = useActionState(action, initialActionState);

  return (
    <form className="billing-action" action={formAction}>
      {state.status === "error" ? (
        <p className="form-message form-message--error" role="alert">
          {state.message}
        </p>
      ) : null}
      <SubmitButton
        pendingLabel={pendingLabel}
        className={secondary ? "button button--secondary" : "button button--primary"}
      >
        {label}
      </SubmitButton>
    </form>
  );
}
