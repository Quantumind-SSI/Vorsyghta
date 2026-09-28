import "server-only";

import { z } from "zod";

import {
  attackStatsSchema,
  billingOfferSchema,
  billingStatusSchema,
  currentUserSchema,
  findingListSchema,
  healthSchema,
  hostedUrlSchema,
  registrationResponseSchema,
  templateCatalogSchema,
  templateDetailSchema,
  threatActorSchema,
  threatCampaignSchema,
  threatIndicatorSchema,
  threatTtpSchema,
  tokenResponseSchema,
  toolUsageListSchema,
} from "@/lib/api/schemas";
import type { ThreatIntelLists } from "@/lib/api/schemas";
import {
  MAX_API_RESPONSE_BYTES,
  readBoundedBody,
  resolveApiBaseUrl,
} from "@/lib/api/http";
import type { RegistrationInput } from "@/lib/registration";

const REQUEST_TIMEOUT_MS = 6_000;
const BILLING_MUTATION_TIMEOUT_MS = 35_000;

export type ApiFailureKind =
  | "unauthorized"
  | "forbidden"
  | "not-found"
  | "conflict"
  | "unavailable"
  | "invalid-response"
  | "request-failed";

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; kind: ApiFailureKind; status: number | null };

type RequestOptions = {
  method?: "GET" | "POST";
  token?: string;
  body?: URLSearchParams;
  json?: unknown;
  timeoutMs?: number;
};

function resolveApiUrl(path: string): URL {
  const base = resolveApiBaseUrl({
    configuredUrl: process.env.VORSYGHTA_API_URL,
    environment: process.env.NODE_ENV,
    allowInsecureInternalApi: process.env.VORSYGHTA_ALLOW_INSECURE_INTERNAL_API,
  });
  return new URL(path.replace(/^\//, ""), base);
}

function failureForStatus(status: number): ApiFailureKind {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not-found";
  if (status === 409) return "conflict";
  if (status >= 500) return "unavailable";
  return "request-failed";
}

async function parseResponse<T>(response: Response, schema: z.ZodType<T>): Promise<ApiResult<T>> {
  const body = await readBoundedBody(response, MAX_API_RESPONSE_BYTES);
  if (!body.ok) {
    return { ok: false, kind: "invalid-response", status: response.status };
  }

  try {
    const parsed = schema.safeParse(JSON.parse(body.text));
    return parsed.success
      ? { ok: true, data: parsed.data }
      : { ok: false, kind: "invalid-response", status: response.status };
  } catch {
    return { ok: false, kind: "invalid-response", status: response.status };
  }
}

async function apiRequest<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const headers = new Headers({ Accept: "application/json" });
  if (options.token) headers.set("Authorization", `Bearer ${options.token}`);
  if (options.body) headers.set("Content-Type", "application/x-www-form-urlencoded");
  if (options.json !== undefined) headers.set("Content-Type", "application/json");

  try {
    const response = await fetch(resolveApiUrl(path), {
      method: options.method ?? "GET",
      headers,
      body: options.json === undefined ? options.body : JSON.stringify(options.json),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      if (response.body !== null) {
        await Promise.allSettled([response.body.cancel("Non-success API response")]);
      }
      return { ok: false, kind: failureForStatus(response.status), status: response.status };
    }
    return await parseResponse(response, schema);
  } catch {
    return { ok: false, kind: "unavailable", status: null };
  }
}

export function authenticate(username: string, password: string) {
  const body = new URLSearchParams({ username, password });
  return apiRequest("/api/auth/token", tokenResponseSchema, { method: "POST", body });
}

export function registerAccount(input: RegistrationInput) {
  return apiRequest("/api/auth/register", registrationResponseSchema, {
    method: "POST",
    json: input,
  });
}

export function fetchCurrentUser(token: string) {
  return apiRequest("/api/auth/me", currentUserSchema, { token });
}

export function fetchBillingOffer() {
  return apiRequest("/api/billing/offer", billingOfferSchema);
}

export function fetchBillingStatus(token: string) {
  return apiRequest("/api/billing/status", billingStatusSchema, { token });
}

export function createCheckoutSession(token: string) {
  return apiRequest("/api/billing/checkout-session", hostedUrlSchema, {
    method: "POST",
    token,
    timeoutMs: BILLING_MUTATION_TIMEOUT_MS,
  });
}

export function createPortalSession(token: string) {
  return apiRequest("/api/billing/portal-session", hostedUrlSchema, {
    method: "POST",
    token,
    timeoutMs: BILLING_MUTATION_TIMEOUT_MS,
  });
}

export function fetchHealth() {
  return apiRequest("/health", healthSchema);
}

export function fetchAttackStats(token: string) {
  return apiRequest("/api/attack-tracking/stats", attackStatsSchema, { token });
}

export function fetchRecentToolUsage(token: string) {
  return apiRequest("/api/attack-tracking/tool-usage?limit=8", toolUsageListSchema, { token });
}

export async function fetchThreatIntel(token: string): Promise<ApiResult<ThreatIntelLists>> {
  const limit = "50";
  const [actors, campaigns, indicators, ttps] = await Promise.all([
    apiRequest(`/api/threat-intel/actors?limit=${limit}`, z.array(threatActorSchema).max(200), { token }),
    apiRequest(`/api/threat-intel/campaigns?limit=${limit}`, z.array(threatCampaignSchema).max(200), { token }),
    apiRequest(`/api/threat-intel/indicators?limit=${limit}`, z.array(threatIndicatorSchema).max(200), { token }),
    apiRequest(`/api/threat-intel/ttps?limit=${limit}`, z.array(threatTtpSchema).max(200), { token }),
  ]);

  const parts = { actors, campaigns, indicators, ttps };
  for (const result of Object.values(parts)) {
    if (!result.ok) return result;
  }

  const data = {
    actors: "actors" in parts && parts.actors.ok ? parts.actors.data : [],
    campaigns: "campaigns" in parts && parts.campaigns.ok ? parts.campaigns.data : [],
    indicators: "indicators" in parts && parts.indicators.ok ? parts.indicators.data : [],
    ttps: "ttps" in parts && parts.ttps.ok ? parts.ttps.data : [],
  };
  return { ok: true, data };
}

export function fetchTemplateCatalog(token: string) {
  return apiRequest("/api/templates/", templateCatalogSchema, { token });
}

export function fetchTemplateDetail(token: string, category: string, name: string) {
  return apiRequest(
    `/api/templates/${encodeURIComponent(category)}/${encodeURIComponent(name)}`,
    templateDetailSchema,
    { token },
  );
}

export function fetchFindings(token: string, limit = 50) {
  return apiRequest(
    `/api/attack-tracking/sequences?limit=${encodeURIComponent(String(limit))}`,
    findingListSchema,
    { token },
  );
}

export function saveOnboardingStep(
  token: string,
  step: { title: string; content: string; category: string; tags: string[] },
) {
  return apiRequest(
    "/api/knowledge/entries",
    z.object({ entry_id: z.string().min(1).max(64), message: z.string().max(256).optional() }),
    { token, method: "POST", json: step },
  );
}
