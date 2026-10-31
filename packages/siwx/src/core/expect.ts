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
 * Order: domain, nonce, scheme, uri, chainId, requestId (`Mismatch`), then `Expired`,
 * `NotYetValid`, `IssuedAtTooOld`. All comparisons at millisecond precision; a future `issued-at`
 * is not an error.
 *
 * @throws {SiwxError} The first failing check.
 */
export function checkExpect(message: Message, expect: Expect): void {
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
  if (message.expirationTime !== undefined) {
    const exp = parseTimestamp(message.expirationTime);
    if (exp === undefined) {
      throw new SiwxError({
        code: "InvalidField",
        field: "expirationTime",
        reason: "not an RFC 3339 date-time",
      });
    }
    if (now > exp.epochMs + skew) {
      throw new SiwxError({ code: "Expired" });
    }
  }
  if (message.notBefore !== undefined) {
    const nbf = parseTimestamp(message.notBefore);
    if (nbf === undefined) {
      throw new SiwxError({
        code: "InvalidField",
        field: "notBefore",
        reason: "not an RFC 3339 date-time",
      });
    }
    if (now + skew < nbf.epochMs) {
      throw new SiwxError({ code: "NotYetValid" });
    }
  }
  if (expect.maxAgeSeconds !== undefined) {
    const issued = parseTimestamp(message.issuedAt);
    if (issued === undefined) {
      throw new SiwxError({
        code: "InvalidField",
        field: "issuedAt",
        reason: "not an RFC 3339 date-time",
      });
    }
    const maxAge = Math.floor(expect.maxAgeSeconds * 1000);
    if (issued.epochMs <= now + skew && now - issued.epochMs - skew > maxAge) {
      throw new SiwxError({ code: "IssuedAtTooOld" });
    }
  }
}
