import { describe, expect, it } from "vitest";

import { getSessionCookiePolicy, SESSION_COOKIE_NAME } from "@/lib/session-policy";
import { registrationPath, safeReturnPath } from "@/lib/navigation";

describe("session cookie policy", () => {
  it("keeps the bearer token inaccessible to browser JavaScript", () => {
    expect(getSessionCookiePolicy("development")).toEqual({
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      path: "/",
      priority: "high",
    });
    expect(SESSION_COOKIE_NAME).toBe("vorsyghta_session");
  });

  it("requires transport security in production", () => {
    expect(getSessionCookiePolicy("production").secure).toBe(true);
    expect(getSessionCookiePolicy("test").secure).toBe(false);
  });
});

describe("post-authentication navigation", () => {
  it("allows only local protected destinations", () => {
    expect(safeReturnPath("/app/settings/billing?source=trial")).toBe(
      "/app/settings/billing?source=trial",
    );
    expect(safeReturnPath("/start-trial")).toBe("/start-trial");
    expect(safeReturnPath("https://attacker.example")).toBe("/app");
    expect(safeReturnPath("//attacker.example")).toBe("/app");
    expect(safeReturnPath("/pricing")).toBe("/app");
    expect(registrationPath("/start-trial")).toBe("/register?next=%2Fstart-trial");
    expect(registrationPath("https://attacker.example")).toBe("/register?next=%2Fapp");
  });
});
