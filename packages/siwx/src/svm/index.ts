/**
 * `siwx` Solana (`solana`) namespace profile — SIWS layout plus the off-chain message v1 envelope
 * (sRFC 38).
 */

import { equalBytes } from "@noble/curves/utils.js";

import type { AccountId } from "../core/account.ts";
import { createAccountId } from "../core/account.ts";
import { SiwxError, fieldError, syntaxError } from "../core/error.ts";
import { MAX_MESSAGE_BYTES } from "../core/limits.ts";
import type { Message } from "../core/message.ts";
import type { Namespace } from "../core/namespace.ts";
import { settle } from "../core/namespace.ts";
import { utf8Encode } from "../core/utf8.ts";
import { addressBytes, b58, canonicalPoint, validateAddress } from "./address.ts";
import { verifyEddsa } from "./ed25519.ts";
import { format as formatSiws, parseBytes as parseSiws } from "./siws.ts";

export { validateAddress } from "./address.ts";
export * as siws from "./siws.ts";

const NAMESPACE = "solana";
const CHAIN_NAME = "Solana";
const OFFCHAIN_DOMAIN = new Uint8Array([0xff, ...utf8Encode("solana offchain")]);

/** CAIP-2 reference for a Solana `chainId` alias. */
function chainReference(chainId: string): string {
  const base = chainId.startsWith("solana:") ? chainId.slice(7) : chainId;
  switch (base) {
    case "mainnet":
      return "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    case "testnet":
      return "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z";
    case "devnet":
      return "EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    case "localnet":
      return "localnet";
    default:
      throw fieldError("chainId", "unknown Solana cluster");
  }
}

type Envelope = {
  signer: Uint8Array;
  content: Uint8Array;
};

function invalidEnvelope(): SiwxError {
  return syntaxError("InvalidEnvelope");
}

/** Decode the v1 envelope at the start of `signed`. */
function decodeEnvelope(signed: Uint8Array): Envelope {
  if (signed.length < 18) {
    throw invalidEnvelope();
  }
  const version = signed[16] ?? 0;
  if (version !== 1) {
    throw new SiwxError({ code: "Unsupported", reason: "off-chain message version" });
  }
  const count = signed[17] ?? 0;
  // SIWS 1.1 requires exactly one signer.
  if (count !== 1) {
    throw invalidEnvelope();
  }
  const n = 32 * count;
  const signers = signed.subarray(18, 18 + n);
  if (signers.length !== n) {
    throw invalidEnvelope();
  }
  for (let i = 0; i < n; i += 32) {
    const s = signers.subarray(i, i + 32);
    if (i > 0 && bytesLe(s, signers.subarray(i - 32, i)) <= 0) {
      throw invalidEnvelope();
    }
  }
  const content = signed.subarray(18 + n);
  if (content.length === 0) {
    throw invalidEnvelope();
  }
  return { signer: signers.subarray(0, 32), content };
}

/** -1, 0 or 1 comparing `a` and `b` lexicographically. */
function bytesLe(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return (a[i] ?? 0) < (b[i] ?? 0) ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Wrap `text` in the off-chain message v1 envelope for `signer` (validated as an SIWS address).
 *
 * @throws {SiwxError} `InvalidField` `address`.
 */
export function offchainMessage(text: string, signer: string): Uint8Array {
  const signerBytes = addressBytes(signer);
  canonicalPoint(signerBytes);
  const textBytes = utf8Encode(text);
  const out = new Uint8Array(18 + 32 + textBytes.length);
  out.set(OFFCHAIN_DOMAIN, 0);
  out[16] = 1;
  out[17] = 1;
  out.set(signerBytes, 18);
  out.set(textBytes, 50);
  return out;
}

/** `Svm` namespace profile. `SvmOptions` is reserved for Phase 5+ extras. */
export type SvmOptions = Record<string, never>;

function svmAccount(message: Message): AccountId {
  validateAddress(message.address);
  return createAccountId(NAMESPACE, chainReference(message.chainId), message.address);
}

/** Create the Solana namespace profile. */
export function svm(_options?: SvmOptions): Namespace {
  return {
    namespace: NAMESPACE,
    label: CHAIN_NAME,
    account: svmAccount,
    format(message: Message): string {
      svmAccount(message);
      return formatSiws(message);
    },
    parse(signed: Uint8Array): Message {
      if (signed.length > MAX_MESSAGE_BYTES) {
        throw new SiwxError({
          code: "MessageTooLarge",
          length: signed.length,
          max: MAX_MESSAGE_BYTES,
        });
      }
      if (
        signed.length >= OFFCHAIN_DOMAIN.length &&
        equalBytes(signed.subarray(0, OFFCHAIN_DOMAIN.length), OFFCHAIN_DOMAIN)
      ) {
        const env = decodeEnvelope(signed);
        const message = parseSiws(env.content);
        const expected = addressBytes(message.address);
        if (!equalBytes(env.signer, expected)) {
          throw new SiwxError({
            code: "Mismatch",
            field: "address",
            expected: message.address,
            actual: b58(env.signer),
          });
        }
        return message;
      }
      return parseSiws(signed);
    },
    verify: async (message: Message, signed: Uint8Array, signature: Uint8Array) =>
      settle(() => verifyEddsa(message, signed, signature)),
  };
}
