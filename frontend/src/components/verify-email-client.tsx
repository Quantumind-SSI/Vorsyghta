"use client";

import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";

export function VerifyEmailClient() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get("token");
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setMessage("Missing verification token.");
      return;
    }
    let mounted = true;
    (async () => {
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (!mounted) return;
        if (res.ok) {
          const data = await res.json();
          setStatus("success");
          setMessage(data.message || "Email verified.");
          setTimeout(() => router.push("/sign-in"), 2000);
        } else {
          setStatus("error");
          setMessage("Verification failed. Please try again.");
        }
      } catch {
        if (!mounted) return;
        setStatus("error");
        setMessage("Verification failed.");
      }
    })();
    return () => { mounted = false; };
  }, [token, router]);

  return (
    <div className="auth-panel">
      <h1>Email Verification</h1>
      {status === "loading" && <p>Verifying your email…</p>}
      {status === "success" && <p>{message} Redirecting to sign in…</p>}
      {status === "error" && <p>{message}</p>}
    </div>
  );
}
