import { describe, expect, it } from "vitest";

import { registrationInputSchema } from "@/lib/registration";

describe("registration input validation", () => {
  it("normalizes email and organization whitespace", () => {
    expect(
      registrationInputSchema.parse({
        email: " Owner@Example.test ",
        password: "correct-horse",
        organization_name: "  Acme   Security  ",
      }),
    ).toEqual({
      email: "owner@example.test",
      password: "correct-horse",
      organization_name: "Acme Security",
    });
  });

  it("enforces password character and UTF-8 byte bounds", () => {
    expect(
      registrationInputSchema.safeParse({
        email: "owner@example.test",
        password: "short",
        organization_name: "Acme",
      }).success,
    ).toBe(false);
    expect(
      registrationInputSchema.safeParse({
        email: "owner@example.test",
        password: "é".repeat(40),
        organization_name: "Acme",
      }).success,
    ).toBe(false);
    expect(
      registrationInputSchema.safeParse({
        email: "owner@example.test",
        password: "🔐".repeat(6),
        organization_name: "Acme",
      }).success,
    ).toBe(false);
  });
});
