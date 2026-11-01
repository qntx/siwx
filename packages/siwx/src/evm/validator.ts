//! On-chain smart-account verification: the ERC-6492 universal validator via a
//! deployless `eth_call`. Covers deployed ERC-1271 accounts, counterfactual
//! ERC-6492 accounts and EOAs. Providers are injected; the library builds no
//! transports and applies no timeouts — transport policy belongs to the
//! provider owner.

import { bytesToHex, hexToBytes, numberToBytesBE } from "@noble/curves/utils.js";

import { SiwxError } from "../core/error.ts";
import type { Message } from "../core/message.ts";
import { parseEip55 } from "./address.ts";
import { UNIVERSAL_VALIDATOR_BYTECODE } from "./bytecode.ts";
import { eip191Hash } from "./eip191.ts";

/** Minimal EIP-1193 provider surface used by the on-chain path. */
export type Eip1193Provider = {
  request: (args: {
    readonly method: string;
    readonly params?: ReadonlyArray<unknown>;
  }) => Promise<unknown>;
};

const BYTECODE: Uint8Array = hexToBytes(UNIVERSAL_VALIDATOR_BYTECODE);

/** Abi.encode(address signer, bytes32 hash, bytes signature). */
export function deploylessCalldata(
  signer: string,
  hash: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  const addr = hexToBytes(signer.slice(2));
  const word = 32;
  const out = new Uint8Array(
    BYTECODE.length + 3 * word + word + Math.ceil(signature.length / word) * word,
  );
  const bc = BYTECODE;
  out.set(bc, 0);
  let o = bc.length;
  out.set(addr, o + (word - addr.length));
  o += word;
  out.set(hash, o);
  o += word;
  out.set(numberToBytesBE(BigInt(96), word), o);
  o += word;
  out.set(numberToBytesBE(BigInt(signature.length), word), o);
  out.set(signature, o + word);
  return out;
}

const malformed = (): SiwxError =>
  new SiwxError({ code: "Backend", reason: "malformed eth_call result" });

/**
 * Interpret a deployless validator `eth_call` result: `0x01` or a 32-byte word of zeros ending `01`
 * is valid; the same shapes ending `00` are `false`; anything else is malformed.
 */
export function decodeResult(hex: string): boolean {
  const data = hex === "" || hex === "0x" ? new Uint8Array(0) : hexToBytes(hex.slice(2));
  if (data.length === 1) {
    if (data[0] === 1) {
      return true;
    }
    if (data[0] === 0) {
      return false;
    }
    throw malformed();
  }
  if (data.length === 32) {
    for (let i = 0; i < 31; i++) {
      if (data[i] !== 0) {
        throw malformed();
      }
    }
    if (data[31] === 1) {
      return true;
    }
    if (data[31] === 0) {
      return false;
    }
  }
  throw malformed();
}

/** JSON-RPC code 3 (EIP-1474 execution reverted) ⇒ signature rejected. */
const codeOf = (error: unknown): unknown =>
  typeof error === "object" && error !== null && "code" in error
    ? (error as Record<"code", unknown>).code
    : undefined;

function isRevert(error: unknown): boolean {
  const code = codeOf(error);
  return typeof code === "number" && code === 3;
}

function backend(): SiwxError {
  return new SiwxError({ code: "Backend", reason: "RPC request failed" });
}

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

/** `eth_chainId` as a decimal number; malformed → `Backend`. */
export async function providerChainId(provider: Eip1193Provider): Promise<bigint> {
  let result: unknown;
  try {
    result = await provider.request({ method: "eth_chainId" });
  } catch {
    throw backend();
  }
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]+$/.test(result)) {
    throw backend();
  }
  return BigInt(result);
}

/**
 * Deployless `eth_call` against the vendored universal validator. `provider`'s chain id must
 * already equal the message chain id (the caller caches the binding).
 */
export async function verifyOnChain(
  provider: Eip1193Provider,
  message: Message,
  signed: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  parseEip55(message.address);
  const hash = eip191Hash(signed);
  const data = `0x${bytesToHex(deploylessCalldata(message.address, hash, signature))}`;
  let result: unknown;
  try {
    result = await provider.request({
      method: "eth_call",
      params: [{ data, input: data }, "latest"],
    });
  } catch (error) {
    throw isRevert(error) ? new SiwxError({ code: "VerificationFailed" }) : backend();
  }
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]*$/.test(result)) {
    throw backend();
  }
  if (!decodeResult(result)) {
    throw new SiwxError({ code: "VerificationFailed" });
  }
}
