//! Cryptographically secure nonce generation (17 unbiased ASCII
//! alphanumerics via rejection sampling over `randomBytes`).

import { randomBytes } from "@noble/hashes/utils.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const LEN = 17;

/** Generate a random nonce: 17 unbiased ASCII alphanumerics (≥ 8 required). */
export function generateNonce(): string {
  // 62 values; accept bytes < 248 (4*62) for uniformity.
  let out = "";
  while (out.length < LEN) {
    const bytes = randomBytes(LEN * 2);
    for (const b of bytes) {
      if (b < 248) {
        out += ALPHABET[b % 62];
        if (out.length === LEN) {
          break;
        }
      }
    }
  }
  return out;
}
