"use client";

import { useState } from "react";
import Link from "next/link";

export function ForgotPasswordClient() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("loading");
    try {
      const res = await fetch("/api/auth/request-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "If an account exists, a reset link has been sent.");
      } else {
        setStatus("error");
        setMessage(data.detail || data.message || "Request failed.");
      }
    } catch {
      setStatus("error");
      setMessage("Network error. Please try again.");
    }
  };

  return (
    <>
      <p className="eyebrow">Password recovery</p>
      <h1>Forgot password</h1>
      {status === "success" ? (
        <div>
          <p>{message}</p>
          <p><Link href="/sign-in">Back to sign in</Link></p>
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />
          {status === "error" && <p role="alert">{message}</p>}
          <button type="submit" disabled={status === "loading"}>
            {status === "loading" ? "Sending…" : "Send reset link"}
          </button>
          <p><Link href="/sign-in">Back to sign in</Link></p>
        </form>
      )}
    </>
  );
}
