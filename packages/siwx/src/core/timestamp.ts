//! Lexical RFC 3339 `date-time` + instant, mirroring Rust `Timestamp`.

/** Parsed RFC 3339 timestamp: original lexeme + epoch milliseconds. */
export type Timestamp = {
  /** Original RFC 3339 lexical form (formatter input). */
  readonly lexeme: string;
  /** Instant in whole milliseconds since the Unix epoch. */
  readonly epochMs: number;
};

const SHAPE = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

function daysInMonth(year: number, month: number): number {
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  return [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ?? 0;
}

/**
 * Parse an RFC 3339 `date-time`; `undefined` when invalid.
 *
 * Requires `T`/`t` and `Z`/`z`/`±HH:MM`; optional fraction; real calendar validity (Feb 30
 * rejected); leap second `:60` rejected like Rust `time`.
 */
export function parseTimestamp(s: string): Timestamp | undefined {
  const m = SHAPE.exec(s);
  if (m === null) {
    return undefined;
  }
  const [, ys, mos, ds, hs, mis, ss, frac, tz] = m;
  const year = Number(ys);
  const month = Number(mos);
  const day = Number(ds);
  const hour = Number(hs);
  const minute = Number(mis);
  const second = Number(ss);
  if (month < 1 || month > 12) {
    return undefined;
  }
  if (day < 1 || day > daysInMonth(year, month)) {
    return undefined;
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  let ms = Date.UTC(year, month - 1, day, hour, minute, second);
  if (frac !== undefined && frac.length > 1) {
    // Fraction of a second, truncated (not rounded) to milliseconds.
    ms += Math.floor(Number(`0${frac}`) * 1000);
  }
  if (tz !== undefined && tz !== "Z" && tz !== "z") {
    const oh = Number(tz.slice(1, 3));
    const om = Number(tz.slice(4, 6));
    if (oh > 23 || om > 59) {
      return undefined;
    }
    const off = (oh * 60 + om) * 60_000;
    ms += tz.startsWith("+") ? -off : off;
  }
  if (!Number.isFinite(ms)) {
    return undefined;
  }
  return { lexeme: s, epochMs: Math.trunc(ms) };
}

/**
 * `Date.prototype.toISOString()` semantics: UTC, millisecond precision, `YYYY-MM-DDTHH:MM:SS.sssZ`;
 * `undefined` for invalid dates and years outside `0000..=9999`.
 */
export function timestampFromDate(date: Date): string | undefined {
  const ms = date.getTime();
  if (!Number.isFinite(ms)) {
    return undefined;
  }
  const year = date.getUTCFullYear();
  if (year < 0 || year > 9999) {
    return undefined;
  }
  try {
    return date.toISOString();
  } catch {
    return undefined;
  }
}
