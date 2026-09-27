export const SESSION_COOKIE_NAME = "vorsyghta_session";

export type SessionCookiePolicy = {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  priority: "high";
};

export function getSessionCookiePolicy(environment: string | undefined): SessionCookiePolicy {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: environment === "production",
    path: "/",
    priority: "high",
  };
}
