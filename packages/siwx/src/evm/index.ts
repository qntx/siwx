//! `@qntx/siwx/evm` — EIP-155 (`eip155`) namespace profile.
//!
//! `account()` emits the canonical EIP-55 checksum spelling, so
//! lowercase / uppercase / checksummed spellings of the same address map
//! to the same `AccountId`.

import type { AccountId } from "../core/account.ts";
import { createAccountId } from "../core/account.ts";
import { format as formatEip4361, parseLabeled } from "../core/eip4361.ts";
import { SiwxError } from "../core/error.ts";
import type { Message } from "../core/message.ts";
import type { Namespace } from "../core/namespace.ts";
import { settle } from "../core/namespace.ts";
import { parseEip55, parseEvmChainId, toChecksumAddress } from "./address.ts";
import { has6492MagicSuffix, verifyEip191 } from "./eip191.ts";

export { parseEvmChainId, toChecksumAddress, validateAddress } from "./address.ts";

const CHAIN_NAME = "Ethereum";
const NAMESPACE = "eip155";

/** Options for `evm()`; `rpc` arrives in Phase 5. */
export type EvmOptions = Record<string, never>;

/**
 * Ethereum (`eip155`) namespace: offline EIP-191 verification; the ERC-6492 magic suffix fails with
 * `Unsupported` until RPC support lands.
 */
function evmAccount(message: Message): AccountId {
  parseEip55(message.address);
  parseEvmChainId(message.chainId);
  return createAccountId(NAMESPACE, message.chainId, toChecksumAddress(message.address));
}

export function evm(_options?: EvmOptions): Namespace {
  return {
    namespace: NAMESPACE,
    label: CHAIN_NAME,
    account: evmAccount,
    format(message: Message): string {
      evmAccount(message);
      return formatEip4361(CHAIN_NAME, message);
    },
    parse(signed: Uint8Array): Message {
      return parseLabeled(CHAIN_NAME, signed);
    },
    verify: async (message: Message, signed: Uint8Array, signature: Uint8Array) =>
      settle(() => {
        if (has6492MagicSuffix(signature)) {
          throw new SiwxError({ code: "Unsupported", reason: "EIP-6492 requires RPC" });
        }
        verifyEip191(message, signed, signature);
      }),
  };
}
