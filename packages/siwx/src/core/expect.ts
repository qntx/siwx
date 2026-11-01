//! Server-side binding + time policy, mirroring Rust `Expect`.

import { SiwxError, mismatchError } from "./error.ts";
import type { Message } from "./message.ts";
import { parseTimestamp } from "./timestamp.ts";

/** Expected bindings and clock policy for `checkExpect`. */
export type Expect = {
  readonly domain: string;
  readonly nonce: string;
  readonly scheme?: string | undefined;
  readonly uri?: string | undefined;
  readonly chainId?: string | undefined;
  readonly requestId?: string | undefined;
  /** Reference instant (defaults to `new Date()`). */
  readonly time?: Date | undefined;
  /** Clock-skew tolerance in seconds (default 60). */
  readonly skewSeconds?: number | undefined;
  /** Maximum age of `issued-at` in seconds. */
  readonly maxAgeSeconds?: number | undefined;
};

const DEFAULT_SKEW_SECONDS = 60;

/**
 * Check `message` against the bindings and time policy.
 *
 * @throws {RangeError} For invalid `time`, or non-finite/negative `skewSeconds`/`maxAgeSeconds`.
 *   Order: domain, nonce, scheme, uri, chainId, requestId (`Mismatch`), then `Expired`,
 *   `NotYetValid`, `IssuedAtTooOld`. All comparisons at millisecond precision; a future `issued-at`
 *   is not an error.
 * @throws {SiwxError} The first failing check.
 */
const assertNonNegativeFinite = (name: string, v: number | undefined): void => {
  if (v !== undefined && (!Number.isFinite(v) || v < 0)) {
    throw new RangeError(`${name} must be a non-negative finite number`);
  }
};

/** EpochMs of a timestamp already validated at `Message::new` time. */
const lexemeMs = (ts: string): number => {
  const parsed = parseTimestamp(ts);
  if (parsed === undefined) {
    // Unreachable in practice: messages are validated at construction.
    throw new RangeError("invalid stored timestamp");
  }
  return parsed.epochMs;
};

export function checkExpect(message: Message, expect: Expect): void {
  if (expect.time !== undefined && !Number.isFinite(expect.time.getTime())) {
    throw new RangeError("expect.time must be a valid Date");
  }
  assertNonNegativeFinite("skewSeconds", expect.skewSeconds);
  assertNonNegativeFinite("maxAgeSeconds", expect.maxAgeSeconds);
  if (message.domain !== expect.domain) {
    throw mismatchError("domain", expect.domain, message.domain);
  }
  if (message.nonce !== expect.nonce) {
    throw mismatchError("nonce", expect.nonce, message.nonce);
  }
  if (expect.scheme !== undefined && message.scheme !== expect.scheme) {
    throw mismatchError("scheme", expect.scheme, message.scheme);
  }
  if (expect.uri !== undefined && message.uri !== expect.uri) {
    throw mismatchError("uri", expect.uri, message.uri);
  }
  if (expect.chainId !== undefined && message.chainId !== expect.chainId) {
    throw mismatchError("chainId", expect.chainId, message.chainId);
  }
  if (expect.requestId !== undefined && message.requestId !== expect.requestId) {
    throw mismatchError("requestId", expect.requestId, message.requestId);
  }

  const now = Math.floor((expect.time ?? new Date()).getTime());
  const skew = Math.floor((expect.skewSeconds ?? DEFAULT_SKEW_SECONDS) * 1000);
  if (message.expirationTime !== undefined && now > lexemeMs(message.expirationTime) + skew) {
    throw new SiwxError({ code: "Expired" });
  }
  if (message.notBefore !== undefined && now + skew < lexemeMs(message.notBefore)) {
    throw new SiwxError({ code: "NotYetValid" });
  }
  if (expect.maxAgeSeconds !== undefined) {
    const maxAge = Math.floor(expect.maxAgeSeconds * 1000);
    if (now > lexemeMs(message.issuedAt) + maxAge + skew) {
      throw new SiwxError({ code: "IssuedAtTooOld" });
    }
  }
}
