//! EIP-191 `personal_sign` verification.
//!
//! Decode order (cross-language contract, mirrored with Rust): length ≠
//! 65 → `v ∉ {0,1,27,28}` → `r`/`s` equal to 0 or ≥ n → `s > n/2` (all
//! `InvalidSignature`) → recovery failure or address mismatch →
//! `VerificationFailed`.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { SiwxError, fieldError } from "../core/error.ts";
import type { Message } from "../core/message.ts";
import { utf8Encode } from "../core/utf8.ts";
import { parseEip55 } from "./address.ts";

const N =
  0xff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_fe_ba_ae_dc_e6_af_48_a0_3b_bf_d2_5e_8c_d0_36_41_41n;
const N_HALF = N / 2n;

const MAGIC = (() => {
  const m = new Uint8Array(32);
  for (let i = 0; i < m.length; i++) {
    m[i] = i % 2 === 0 ? 0x64 : 0x92;
  }
  return m;
})();

/** True when `signature` ends with the ERC-6492 detection suffix. */
export function has6492MagicSuffix(signature: Uint8Array): boolean {
  if (signature.length < MAGIC.length) {
    return false;
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (signature[signature.length - MAGIC.length + i] !== MAGIC[i]) {
      return false;
    }
  }
  return true;
}

/** `keccak256("\x19Ethereum Signed Message:\n" + len + message)`. */
export function eip191Hash(message: Uint8Array): Uint8Array {
  const prefix = utf8Encode(`\u0019Ethereum Signed Message:\n${message.length}`);
  const joined = new Uint8Array(prefix.length + message.length);
  joined.set(prefix);
  joined.set(message, prefix.length);
  return keccak_256(joined);
}

/** Verify a 65-byte `r‖s‖v` EIP-191 signature over `signed`. */
export function verifyEip191(message: Message, signed: Uint8Array, signature: Uint8Array): void {
  if (signature.length !== 65) {
    throw new SiwxError({ code: "InvalidSignature", reason: "EIP-191 signature must be 65 bytes" });
  }
  const v = signature[64] ?? 0;
  if (v !== 0 && v !== 1 && v !== 27 && v !== 28) {
    throw new SiwxError({ code: "InvalidSignature", reason: "v must be 0, 1, 27 or 28" });
  }
  const r = bytesToNumberBE(signature.subarray(0, 32));
  const s = bytesToNumberBE(signature.subarray(32, 64));
  if (r === 0n || r >= N || s === 0n || s >= N) {
    throw new SiwxError({ code: "InvalidSignature", reason: "r/s out of range" });
  }
  if (s > N_HALF) {
    throw new SiwxError({ code: "InvalidSignature", reason: "high-s (EIP-2)" });
  }

  const hash = eip191Hash(signed);
  let recovered: Uint8Array;
  try {
    const sig = secp256k1.Signature.fromBytes(signature.subarray(0, 64), "compact").addRecoveryBit(
      v % 27,
    );
    const point = sig.recoverPublicKey(hash);
    const uncompressed = point.toBytes(false);
    const addr = keccak_256(uncompressed.subarray(1)).subarray(12);
    recovered = addr;
  } catch {
    throw new SiwxError({ code: "VerificationFailed" });
  }

  let expected: Uint8Array;
  try {
    expected = parseEip55(message.address);
  } catch (error) {
    if (error instanceof SiwxError) {
      throw error;
    }
    throw fieldError("address", "expected 0x + 40 hex");
  }

  if (!equalBytes(recovered, expected)) {
    throw new SiwxError({ code: "VerificationFailed" });
  }
}
