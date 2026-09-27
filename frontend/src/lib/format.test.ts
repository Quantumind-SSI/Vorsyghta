import { describe, expect, it } from "vitest";

import { formatBillingInterval, formatDateTime, formatDuration, formatMoney } from "@/lib/format";
import { normalizeApiTimestamp } from "@/lib/time";

describe("display formatting", () => {
  it("formats Stripe minor units using the currency exponent", () => {
    expect(formatMoney(4900, "GBP", "en-GB")).toBe("£49.00");
    expect(formatMoney(5000, "JPY", "en-GB")).toContain("5,000");
    expect(formatMoney(-1, "GBP", "en-GB")).toBeNull();
    expect(formatMoney(100, "invalid", "en-GB")).toBeNull();
  });

  it("formats billing intervals without ambiguous shorthand", () => {
    expect(formatBillingInterval("month", 1)).toBe("monthly");
    expect(formatBillingInterval("week", 2)).toBe("every 2 weeks");
    expect(formatBillingInterval("month", 0)).toBe("billing period unavailable");
  });

  it("formats timestamps in UTC and reports missing values", () => {
    expect(formatDateTime("2026-09-14T12:30:00Z", "en-GB")).toContain("14 Sept 2026");
    expect(formatDateTime("2026-09-14T12:30:00Z", "en-GB")).toContain("UTC");
    expect(formatDateTime("2026-09-14T12:30:00", "en-GB")).toBe(
      formatDateTime("2026-09-14T12:30:00Z", "en-GB"),
    );
    expect(formatDateTime(null)).toBe("Not reported");
    expect(formatDateTime("not-a-date")).toBe("Invalid date");
  });

  it("normalizes API timestamps to UTC and rejects ambiguous formats", () => {
    expect(normalizeApiTimestamp("2026-09-14T12:30:00")).toBe("2026-09-14T12:30:00.000Z");
    expect(normalizeApiTimestamp("2026-09-14T12:30:00+02:00")).toBe(
      "2026-09-14T10:30:00.000Z",
    );
    expect(normalizeApiTimestamp("2026-02-30T12:30:00")).toBeNull();
    expect(normalizeApiTimestamp("2026-09-14")).toBeNull();
  });

  it("formats recorded durations without implying missing values are zero", () => {
    expect(formatDuration(0.25)).toBe("250 ms");
    expect(formatDuration(3.25)).toBe("3.3 s");
    expect(formatDuration(null)).toBe("Not reported");
  });
});
