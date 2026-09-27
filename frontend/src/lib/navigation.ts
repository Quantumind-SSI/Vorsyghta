export function safeReturnPath(value: FormDataEntryValue | string | null | undefined): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
    return "/app";
  }

  const path = value.split("?", 1)[0];
  if (path === "/start-trial" || path === "/app" || path?.startsWith("/app/")) {
    return value;
  }
  return "/app";
}

export function registrationPath(nextPath: string): string {
  return `/register?next=${encodeURIComponent(safeReturnPath(nextPath))}`;
}
