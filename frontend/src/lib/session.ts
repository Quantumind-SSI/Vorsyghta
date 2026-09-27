import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { fetchCurrentUser } from "@/lib/api/client";
import type { CurrentUser } from "@/lib/api/schemas";
import { safeReturnPath } from "@/lib/navigation";
import { getSessionCookiePolicy, SESSION_COOKIE_NAME } from "@/lib/session-policy";

type AuthenticatedSession = {
  state: "authenticated";
  token: string;
  user: CurrentUser;
};

export type SessionState =
  | AuthenticatedSession
  | { state: "missing" }
  | { state: "invalid" }
  | { state: "unavailable" };

export async function setSessionToken(token: string): Promise<void> {
  const store = await cookies();
  store.set(SESSION_COOKIE_NAME, token, getSessionCookiePolicy(process.env.NODE_ENV));
}

export async function clearSession(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE_NAME);
}

export async function getSessionState(): Promise<SessionState> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE_NAME)?.value;
  if (!token) return { state: "missing" };

  const user = await fetchCurrentUser(token);
  if (user.ok) return { state: "authenticated", token, user: user.data };
  if (user.kind === "unauthorized" || user.kind === "forbidden") {
    return { state: "invalid" };
  }
  return { state: "unavailable" };
}

export async function requireSession(returnPath: string): Promise<AuthenticatedSession | { state: "unavailable" }> {
  const session = await getSessionState();
  const next = safeReturnPath(returnPath);
  if (session.state === "missing") {
    redirect(`/sign-in?next=${encodeURIComponent(next)}`);
  }
  if (session.state === "invalid") {
    redirect(`/sign-in?next=${encodeURIComponent(next)}`);
  }
  return session;
}
