import { describe, expect, it } from "vitest";

import { readBoundedBody, resolveApiBaseUrl } from "@/lib/api/http";

describe("API URL transport policy", () => {
  it("allows HTTPS and production loopback HTTP", () => {
    expect(
      resolveApiBaseUrl({
        configuredUrl: "https://api.example.test",
        environment: "production",
        allowInsecureInternalApi: undefined,
      }).href,
    ).toBe("https://api.example.test/");
    expect(
      resolveApiBaseUrl({
        configuredUrl: "http://127.0.0.2:8001",
        environment: "production",
        allowInsecureInternalApi: undefined,
      }).href,
    ).toBe("http://127.0.0.2:8001/");
  });

  it("rejects production cleartext except for an explicit private-network override", () => {
    const production = {
      configuredUrl: "http://api:8000",
      environment: "production",
      allowInsecureInternalApi: undefined,
    };
    expect(() => resolveApiBaseUrl(production)).toThrow(/cleartext production API/i);
    expect(
      resolveApiBaseUrl({ ...production, allowInsecureInternalApi: "true" }).href,
    ).toBe("http://api:8000/");
    expect(
      resolveApiBaseUrl({ ...production, environment: "development" }).href,
    ).toBe("http://api:8000/");
  });

  it("requires an explicit API origin in production", () => {
    expect(() =>
      resolveApiBaseUrl({
        configuredUrl: undefined,
        environment: "production",
        allowInsecureInternalApi: undefined,
      }),
    ).toThrow(/required in production/i);
  });

  it("rejects unsupported schemes and embedded credentials", () => {
    expect(() =>
      resolveApiBaseUrl({
        configuredUrl: "ftp://api.example.test",
        environment: "development",
        allowInsecureInternalApi: undefined,
      }),
    ).toThrow(/HTTP\(S\)/);
    expect(() =>
      resolveApiBaseUrl({
        configuredUrl: "https://user:password@api.example.test",
        environment: "production",
        allowInsecureInternalApi: undefined,
      }),
    ).toThrow(/without credentials/);
  });
});

describe("bounded response streaming", () => {
  it("reads a body whose byte length is within the limit", async () => {
    const response = new Response(new TextEncoder().encode("{\"ok\":true}"));
    await expect(readBoundedBody(response, 32)).resolves.toEqual({
      ok: true,
      text: "{\"ok\":true}",
    });
  });

  it("stops and cancels as soon as streamed chunks exceed the limit", async () => {
    let canceled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(6));
        controller.enqueue(new Uint8Array(6));
      },
      cancel() {
        canceled = true;
      },
    });

    await expect(readBoundedBody(new Response(stream), 10)).resolves.toEqual({
      ok: false,
      reason: "limit-exceeded",
    });
    expect(canceled).toBe(true);
  });

  it("rejects an oversized declared content length before consuming the body", async () => {
    const response = new Response("small", { headers: { "content-length": "1001" } });
    await expect(readBoundedBody(response, 1000)).resolves.toEqual({
      ok: false,
      reason: "limit-exceeded",
    });
  });
});
