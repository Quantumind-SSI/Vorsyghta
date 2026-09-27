import { describe, expect, it } from "vitest";

import { buildContentSecurityPolicy } from "@/lib/security-headers";

describe("content security policy", () => {
  it("uses a strict production nonce without unsafe inline scripts", () => {
    const policy = buildContentSecurityPolicy("nonce-value", "production");

    expect(policy).toContain("script-src 'self' 'nonce-nonce-value' 'strict-dynamic'");
    expect(policy).toContain("style-src 'self' 'nonce-nonce-value'");
    expect(policy).toContain("upgrade-insecure-requests");
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("'unsafe-eval'");
  });

  it("permits only the development features required by Next.js", () => {
    const policy = buildContentSecurityPolicy("nonce-value", "development");

    expect(policy).toContain("'unsafe-eval'");
    expect(policy).toContain("style-src 'self' 'nonce-nonce-value' 'unsafe-inline'");
    expect(policy).not.toContain("upgrade-insecure-requests");
  });
});
