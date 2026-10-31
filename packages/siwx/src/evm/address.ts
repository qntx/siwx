//! EIP-55 / EVM address + chain-id rules, matching `siwx::evm`.

import { keccak_256 } from "@noble/hashes/sha3.js";

import { fieldError } from "../core/error.ts";
import { utf8Encode } from "../core/utf8.ts";

const HEX40 = /^[0-9a-fA-F]{40}$/;

/** EIP-55 checksum spelling of a `0x`-prefixed 40-hex address. */
export function toChecksumAddress(address: string): string {
  const body = address.startsWith("0x") ? address.slice(2) : address;
  if (!HEX40.test(body)) {
    throw fieldError("address", "expected 0x + 40 hex");
  }
  const lower = body.toLowerCase();
  const hash = keccak_256(utf8Encode(lower));
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    const c = lower.charAt(i);
    const nibble = ((hash[Math.floor(i / 2)] ?? 0) >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    out += /[a-f]/.test(c) && nibble >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

/**
 * Validate `0x` + 40 hex: all-lowercase/all-uppercase or valid EIP-55.
 *
 * @throws {SiwxError} `InvalidField` `address`.
 */
export function validateAddress(address: string): void {
  parseEip55(address);
}

const badAddress = (): Error => fieldError("address", "expected 0x + 40 hex");

/** Parse an EVM address to its 20 bytes under the canonical rule. */
export function parseEip55(address: string): Uint8Array {
  const bad = badAddress;
  if (!address.startsWith("0x")) {
    throw bad();
  }
  const hex = address.slice(2);
  if (hex.length !== 40 || !HEX40.test(hex)) {
    throw bad();
  }
  const hasLower = /[a-f]/.test(hex);
  const hasUpper = /[A-F]/.test(hex);
  if (hasLower && hasUpper && address !== toChecksumAddress(address)) {
    throw fieldError("address", "bad EIP-55 checksum");
  }
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * EVM `chain-id`: `[0-9]+`, no leading zero unless `"0"`, fits in `u64`.
 *
 * @throws {SiwxError} `InvalidField` `chainId`.
 */
export function parseEvmChainId(chainId: string): bigint {
  if (chainId.length === 0) {
    throw fieldError("chainId", "empty");
  }
  if (!/^[0-9]+$/.test(chainId)) {
    throw fieldError("chainId", "not decimal");
  }
  if (chainId.length > 1 && chainId.startsWith("0")) {
    throw fieldError("chainId", "leading zero");
  }
  const value = BigInt(chainId);
  if (value > 0xff_ff_ff_ff_ff_ff_ff_ffn) {
    throw fieldError("chainId", "overflow");
  }
  return value;
}
