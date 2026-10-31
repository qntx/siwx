/** Solana address rules: canonical on-curve Ed25519 key in base58. */

import { ed25519 } from "@noble/curves/ed25519.js";
import { equalBytes } from "@noble/curves/utils.js";
import { base58 } from "@scure/base";

import { fieldError } from "../core/error.ts";

/**
 * Decode `address` as a base58 (Bitcoin alphabet) string of 32–44 chars that decodes to exactly 32
 * bytes.
 *
 * @throws {SiwxError} `InvalidField` `address`.
 */
export function addressBytes(address: string): Uint8Array {
  if (address.length < 32 || address.length > 44) {
    throw fieldError("address", "expected 32–44 base58 chars");
  }
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(address);
  } catch {
    throw fieldError("address", "invalid base58");
  }
  if (bytes.length !== 32) {
    throw fieldError("address", "expected 32 bytes");
  }
  return bytes;
}

/**
 * The canonical, on-curve, non-small-order Ed25519 point for `bytes` (decompress → recompress byte
 * equality proves canonicity).
 *
 * @throws {SiwxError} `InvalidField` `address`.
 */
export function canonicalPoint(bytes: Uint8Array): void {
  let point: InstanceType<typeof ed25519.Point>;
  try {
    point = ed25519.Point.fromBytes(bytes);
  } catch {
    throw fieldError("address", "invalid Ed25519 pubkey");
  }
  if (point.equals(ed25519.Point.ZERO)) {
    throw fieldError("address", "identity pubkey");
  }
  if (!point.isTorsionFree()) {
    throw fieldError("address", "not in the prime-order subgroup");
  }
  if (!equalBytes(point.toBytes(), bytes)) {
    throw fieldError("address", "non-canonical pubkey");
  }
}

/**
 * Validate that `address` is a canonical, on-curve, non-small-order Ed25519 verifying key in base58
 * form.
 *
 * @throws {SiwxError} `InvalidField` `address`.
 */
export function validateAddress(address: string): void {
  canonicalPoint(addressBytes(address));
}

/** Base58-encode `bytes` (error messages). */
export function b58(bytes: Uint8Array): string {
  return base58.encode(bytes);
}
