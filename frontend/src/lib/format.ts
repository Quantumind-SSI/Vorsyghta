import { normalizeApiTimestamp } from "@/lib/time";

const FALLBACK_LOCALE = "en-GB";

export function formatMoney(
  minorAmount: number,
  currency: string,
  locale = FALLBACK_LOCALE,
): string | null {
  if (!Number.isSafeInteger(minorAmount) || minorAmount < 0 || !/^[A-Z]{3}$/i.test(currency)) {
    return null;
  }

  try {
    const formatter = new Intl.NumberFormat(locale, {
      style: "currency",
      currency: currency.toUpperCase(),
    });
    const digits = formatter.resolvedOptions().maximumFractionDigits ?? 2;
    return formatter.format(minorAmount / 10 ** digits);
  } catch {
    return null;
  }
}

export function formatBillingInterval(interval: string, count: number): string {
  if (!Number.isSafeInteger(count) || count < 1) {
    return "billing period unavailable";
  }
  if (count === 1) {
    const singular: Record<string, string> = {
      day: "daily",
      week: "weekly",
      month: "monthly",
      year: "yearly",
    };
    return singular[interval] ?? `per ${interval}`;
  }
  return `every ${count} ${interval}s`;
}

export function formatDateTime(value: string | null, locale = FALLBACK_LOCALE): string {
  if (value === null) {
    return "Not reported";
  }
  const timestamp = normalizeApiTimestamp(value);
  if (timestamp === null) {
    return "Invalid date";
  }
  const date = new Date(timestamp);
  const formatted = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date);
  return `${formatted} UTC`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) {
    return "Not reported";
  }
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)} ms`;
  }
  return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
}
