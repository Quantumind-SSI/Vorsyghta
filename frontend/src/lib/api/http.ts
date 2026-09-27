export const DEFAULT_API_URL = "http://localhost:8001";
export const MAX_API_RESPONSE_BYTES = 1_000_000;

export type ApiTransportSettings = {
  configuredUrl: string | undefined;
  environment: string | undefined;
  allowInsecureInternalApi: string | undefined;
};

export type BoundedBodyResult =
  | { ok: true; text: string }
  | { ok: false; reason: "limit-exceeded" | "invalid-encoding" };

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "::1" || normalized === "localhost" || normalized.endsWith(".localhost")) {
    return true;
  }
  const octets = normalized.split(".").map(Number);
  return (
    octets.length === 4 &&
    octets[0] === 127 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
  );
}

export function resolveApiBaseUrl(settings: ApiTransportSettings): URL {
  if (settings.environment === "production" && !settings.configuredUrl?.trim()) {
    throw new Error("VORSYGHTA_API_URL is required in production");
  }
  const rawUrl = settings.configuredUrl?.trim() || DEFAULT_API_URL;
  const url = new URL(rawUrl.endsWith("/") ? rawUrl : `${rawUrl}/`);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("VORSYGHTA_API_URL must be an HTTP(S) URL without credentials");
  }
  const insecureProductionApi =
    settings.environment === "production" &&
    url.protocol === "http:" &&
    !isLoopbackHostname(url.hostname);
  if (insecureProductionApi && settings.allowInsecureInternalApi !== "true") {
    throw new Error("Cleartext production API URLs require an explicit private-network override");
  }
  return url;
}

async function cancelBody(body: ReadableStream<Uint8Array>): Promise<void> {
  await Promise.allSettled([body.cancel("Response body exceeded its configured bound")]);
}

function declaredBodyIsTooLarge(response: Response, maxBytes: number): boolean {
  const declaredLength = response.headers.get("content-length");
  return declaredLength !== null && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxBytes;
}

function combineChunks(chunks: Uint8Array[], size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readBodyBytes(body: ReadableStream<Uint8Array>, maxBytes: number): Promise<Uint8Array | null> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  const maxChunks = Math.min(maxBytes + 1, 16_384);
  let size = 0;
  try {
    for (let chunkCount = 0; chunkCount <= maxChunks; chunkCount += 1) {
      const { done, value } = await reader.read();
      if (done) return combineChunks(chunks, size);
      if (value === undefined) continue;
      size += value.byteLength;
      if (size > maxBytes || chunkCount === maxChunks) {
        await Promise.allSettled([reader.cancel("Response body exceeded its configured bound")]);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return null;
}

function decodeBody(bytes: Uint8Array): BoundedBodyResult {
  try {
    return { ok: true, text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return { ok: false, reason: "invalid-encoding" };
  }
}

export async function readBoundedBody(
  response: Response,
  maxBytes: number,
): Promise<BoundedBodyResult> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("maxBytes must be a positive safe integer");
  }
  if (declaredBodyIsTooLarge(response, maxBytes)) {
    if (response.body !== null) await cancelBody(response.body);
    return { ok: false, reason: "limit-exceeded" };
  }
  if (response.body === null) return { ok: true, text: "" };
  const bytes = await readBodyBytes(response.body, maxBytes);
  return bytes === null ? { ok: false, reason: "limit-exceeded" } : decodeBody(bytes);
}
