"use client";

import Link from "next/link";
import { useActionState } from "react";

import { signInAction } from "@/actions/auth";
import { initialActionState } from "@/lib/action-state";
import { SubmitButton } from "@/components/submit-button";

type SignInFormProps = {
  nextPath: string;
};

export function SignInForm({ nextPath }: SignInFormProps) {
  const [state, action] = useActionState(signInAction, initialActionState);

  return (
    <form className="auth-form" action={action} noValidate>
      <input type="hidden" name="next" value={nextPath} />
      <div className="field">
        <label htmlFor="email">Email address</label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="username"
          inputMode="email"
          maxLength={254}
          aria-describedby={state.field === "email" ? "sign-in-error" : undefined}
          aria-invalid={state.field === "email"}
          required
        />
      </div>
      <div className="field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          maxLength={1024}
          aria-describedby={state.field === "password" ? "sign-in-error" : undefined}
          aria-invalid={state.field === "password"}
          required
        />
      </div>
      {state.status === "error" ? (
        <p className="form-message form-message--error" id="sign-in-error" role="alert">
          {state.message}
        </p>
      ) : null}
      <p className="field-aux">
        <Link href="/forgot-password">Forgot password?</Link>
        <span className="field-aux__hint">No verification email is used — sign-in works immediately after registration.</span>
      </p>
      <SubmitButton pendingLabel="Signing in...">Sign in securely</SubmitButton>
    </form>
  );
}
