"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";
import Link from "next/link";

export function ResetPasswordClient() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      setStatus("error");
      setMessage("Missing reset token.");
      return;
    }
    if (password !== confirm) {
      setStatus("error");
      setMessage("Passwords do not match.");
      return;
    }
    setStatus("loading");
    try {
      const res = await fetch("http://localhost:8001/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "Password reset successfully.");
      } else {
        setStatus("error");
        setMessage(data.detail || data.message || "Reset failed.");
      }
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again.");
    }
  };

  if (!token) {
    return (
      <>
        <h1>Invalid reset link</h1>
        <p>Missing token.</p>
        <p><Link href="/sign-in">Back to sign in</Link></p>
      </>
    );
  }

  return (
    <>
      <h1>Reset password</h1>
      {status === "success" ? (
        <div>
          <p>{message}</p>
          <p><Link href="/sign-in">Go to sign in</Link></p>
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="password">New password</label>
          <input
            id="password"
            type="password"
            required
            minLength={12}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <label htmlFor="confirm">Confirm password</label>
          <input
            id="confirm"
            type="password"
            required
            minLength={12}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
          {status === "error" && <p role="alert">{message}</p>}
          <button type="submit" disabled={status === "loading"}>
            {status === "loading" ? "Resetting…" : "Reset password"}
          </button>
          <p><Link href="/sign-in">Back to sign in</Link></p>
        </form>
      )}
    </>
  );
}
