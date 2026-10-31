/** Ed25519 signature verification for Solana (internal). */

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, equalBytes } from "@noble/curves/utils.js";

import { SiwxError } from "../core/error.ts";
import type { Message } from "../core/message.ts";
import { addressBytes, canonicalPoint } from "./address.ts";

const L = ed25519.Point.CURVE().n;
const P = ed25519.Point;

/**
 * RFC 8032 verification over the exact `signed` bytes.
 *
 * `A` (the address key) and `R` must be canonical encodings of prime-order-subgroup points
 * (torsion-free — excluding identity, small-order and mixed points) and `S < L`; for torsion-free
 * `A`/`R` the cofactored and cofactorless equations coincide, so library verifiers agree.
 *
 * @throws {SiwxError} `InvalidSignature` (wrong length or `S >= L`) or `VerificationFailed` (bad
 *   `R`, or the equation fails).
 */
export function verifyEddsa(message: Message, signed: Uint8Array, signature: Uint8Array): void {
  if (signature.length !== 64) {
    throw new SiwxError({
      code: "InvalidSignature",
      reason: "Ed25519 signature must be 64 bytes",
    });
  }
  if (bytesToNumberLE(signature.subarray(32, 64)) >= L) {
    throw new SiwxError({
      code: "InvalidSignature",
      reason: "S must be a canonical scalar (S < L)",
    });
  }
  const key = addressBytes(message.address);
  canonicalPoint(key);
  const rBytes = signature.subarray(0, 32);
  let r: InstanceType<typeof P>;
  try {
    r = P.fromBytes(rBytes);
  } catch {
    throw new SiwxError({ code: "VerificationFailed" });
  }
  if (!equalBytes(r.toBytes(), rBytes) || !r.isTorsionFree() || r.equals(P.ZERO)) {
    throw new SiwxError({ code: "VerificationFailed" });
  }
  let ok: boolean;
  try {
    ok = ed25519.verify(signature, signed, key, { zip215: false });
  } catch {
    throw new SiwxError({ code: "VerificationFailed" });
  }
  if (!ok) {
    throw new SiwxError({ code: "VerificationFailed" });
  }
}
