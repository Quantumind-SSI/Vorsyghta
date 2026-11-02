export function buildContentSecurityPolicy(nonce: string, environment: string | undefined): string {
  const development = environment === "development" || !environment;
  const apiUrl = process.env.VORSYGHTA_API_URL || "http://localhost:8001";
  const apiOrigin = new URL(apiUrl).origin;
  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    `connect-src 'self' ${apiOrigin}`,
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "img-src 'self' data:",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${development ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'unsafe-inline'${development ? "" : ` 'nonce-${nonce}'`}`,
  ];
  if (!development) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}
