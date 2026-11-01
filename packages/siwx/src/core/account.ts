//! CAIP-10 `account_id`: `namespace ":" reference ":" address`.

import { fieldError } from "./error.ts";

/** Every character matches — avoids spread-on-string for Hermes-safe lint. */
function everyChar(s: string, test: RegExp | ((c: string) => boolean)): boolean {
  const pred = typeof test === "function" ? test : (c: string) => test.test(c);
  for (const c of s) {
    if (!pred(c)) {
      return false;
    }
  }
  return true;
}

/** A validated CAIP-10 `account_id`. */
export type AccountId = {
  readonly namespace: string;
  readonly reference: string;
  readonly address: string;
  /** Canonical string form `namespace:reference:address`. */
  readonly id: string;
};

/**
 * Validate and build an `account_id`.
 *
 * `namespace` is CAIP-2 `[-a-z0-9]{3,8}`; `reference` is `[-_a-zA-Z0-9]{1,32}`; `address` is
 * `[-.%a-zA-Z0-9]{1,128}`.
 *
 * @throws {SiwxError} `InvalidField` `chainId` for bad namespace/reference, `address` for a bad
 *   address.
 */
export function createAccountId(namespace: string, reference: string, address: string): AccountId {
  if (namespace.length < 3 || namespace.length > 8 || !everyChar(namespace, /[a-z0-9-]/)) {
    throw fieldError("chainId", "bad CAIP-2 namespace");
  }
  if (reference.length === 0 || reference.length > 32 || !everyChar(reference, /[A-Za-z0-9_-]/)) {
    throw fieldError("chainId", "bad CAIP-2 reference");
  }
  if (
    address.length === 0 ||
    address.length > 128 ||
    !everyChar(address, (c) => /[A-Za-z0-9]/.test(c) || c === "-" || c === "." || c === "%")
  ) {
    throw fieldError("address", "bad CAIP-10 address");
  }
  return Object.freeze({
    namespace,
    reference,
    address,
    id: `${namespace}:${reference}:${address}`,
  });
}

/**
 * Parse `namespace:reference:address`.
 *
 * @throws {SiwxError} `InvalidField` `chainId` when the shape is wrong.
 */
export function parseAccountId(id: string): AccountId {
  const first = id.indexOf(":");
  const second = first === -1 ? -1 : id.indexOf(":", first + 1);
  if (first === -1 || second < 0) {
    throw fieldError("chainId", "expected namespace:reference:address");
  }
  return createAccountId(id.slice(0, first), id.slice(first + 1, second), id.slice(second + 1));
}
