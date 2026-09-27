"use client";

import { useActionState } from "react";

import { registerAction } from "@/actions/auth";
import { SubmitButton } from "@/components/submit-button";
import { initialActionState } from "@/lib/action-state";

export function RegisterForm({ nextPath }: { nextPath: string }) {
  const [state, action] = useActionState(registerAction, initialActionState);
  const errorId = state.status === "error" ? "register-error" : undefined;

  return (
    <form className="auth-form" action={action} noValidate>
      <input type="hidden" name="next" value={nextPath} />
      <div className="field">
        <label htmlFor="organization_name">Organization name</label>
        <input
          id="organization_name"
          name="organization_name"
          type="text"
          autoComplete="organization"
          minLength={2}
          maxLength={120}
          aria-describedby={state.field === "organization_name" ? errorId : undefined}
          aria-invalid={state.field === "organization_name"}
          required
        />
      </div>
      <div className="field">
        <label htmlFor="register-email">Email address</label>
        <input
          id="register-email"
          name="email"
          type="email"
          autoComplete="email"
          inputMode="email"
          maxLength={254}
          aria-describedby={state.field === "email" ? errorId : undefined}
          aria-invalid={state.field === "email"}
          required
        />
      </div>
      <div className="field">
        <label htmlFor="register-password">Password</label>
        <input
          id="register-password"
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={72}
          aria-describedby={`password-requirements${state.field === "password" ? ` ${errorId}` : ""}`}
          aria-invalid={state.field === "password"}
          required
        />
        <p className="field-help" id="password-requirements">
          Use 12 to 72 characters. Multi-byte characters count toward the 72-byte limit.
        </p>
      </div>
      {state.status === "error" ? (
        <p className="form-message form-message--error" id="register-error" role="alert">
          {state.message}
        </p>
      ) : null}
      <SubmitButton pendingLabel="Creating account...">Create account</SubmitButton>
    </form>
  );
}
