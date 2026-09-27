const ISO_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/;

function hasValidCalendarParts(match: RegExpMatchArray): boolean {
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const calendarYear = year < 100 ? year + 400 : year;
  const daysInMonth = new Date(Date.UTC(calendarYear, month, 0)).getUTCDate();
  return day >= 1 && day <= daysInMonth;
}

export function normalizeApiTimestamp(value: string): string | null {
  if (value.trim() !== value) return null;
  const match = value.match(ISO_TIMESTAMP_PATTERN);
  if (match === null || !hasValidCalendarParts(match)) return null;

  const zone = match[8];
  const timestamp = zone === undefined ? `${value}Z` : value;
  const milliseconds = Date.parse(timestamp);
  if (Number.isNaN(milliseconds)) return null;
  return new Date(milliseconds).toISOString();
}
