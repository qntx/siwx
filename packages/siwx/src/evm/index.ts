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
import { parseEip55, parseEvmChainId, toChecksumAddress } from "./address.ts";
import { verifyEip191 } from "./eip191.ts";
import type { Eip1193Provider } from "./validator.ts";
import { has6492MagicSuffix, providerChainId, verifyOnChain } from "./validator.ts";

export { parseEvmChainId, toChecksumAddress, validateAddress } from "./address.ts";
export type { Eip1193Provider } from "./validator.ts";

const CHAIN_NAME = "Ethereum";
const NAMESPACE = "eip155";

function evmAccount(message: Message): AccountId {
  parseEip55(message.address);
  parseEvmChainId(message.chainId);
  return createAccountId(NAMESPACE, message.chainId, toChecksumAddress(message.address));
}

/** Options for `evm()`: injected EIP-1193 providers by decimal chain id. */
export type EvmOptions = {
  readonly rpc?: Readonly<Record<string, Eip1193Provider>>;
};

/**
 * Ethereum (`eip155`) namespace. EIP-191 runs fully offline; a signature carrying the ERC-6492
 * magic suffix, or an EIP-191 failure on a chain with a configured provider, takes the on-chain
 * universal-validator path. Providers own all transport policy — the library applies no timeouts —
 * and `eth_chainId` is bound to the message chain id (cached per provider on success only) before
 * any `eth_call`.
 */
export function evm(options?: EvmOptions): Namespace {
  const rpc = options?.rpc ?? {};
  // Chain-id binding is cached per chain-id key — one provider object may
  // serve several entries and each must be checked (matches the Rust
  // per-entry cache).
  const verifiedChains = new Set<string>();
  const providerFor = (chainId: string): Eip1193Provider | undefined => {
    const key = parseEvmChainId(chainId).toString(10);
    return rpc[key];
  };
  const onChain = async (
    message: Message,
    signed: Uint8Array,
    signature: Uint8Array,
    eip191Err: SiwxError | undefined,
  ): Promise<void> => {
    const key = parseEvmChainId(message.chainId).toString(10);
    const provider = providerFor(message.chainId);
    if (provider === undefined) {
      throw eip191Err ?? new SiwxError({ code: "Unsupported", reason: "EIP-6492 requires RPC" });
    }
    if (!verifiedChains.has(key)) {
      const rpcChain = await providerChainId(provider);
      if (rpcChain !== parseEvmChainId(message.chainId)) {
        throw new SiwxError({
          code: "Mismatch",
          field: "chainId",
          expected: key,
          actual: rpcChain.toString(),
        });
      }
      verifiedChains.add(key);
    }
    await verifyOnChain(provider, message, signed, signature);
  };
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
    verify: async (message: Message, signed: Uint8Array, signature: Uint8Array) => {
      if (has6492MagicSuffix(signature)) {
        await onChain(message, signed, signature, undefined);
        return;
      }
      try {
        verifyEip191(message, signed, signature);
      } catch (error) {
        if (error instanceof SiwxError && providerFor(message.chainId) !== undefined) {
          await onChain(message, signed, signature, error);
          return;
        }
        throw error;
      }
    },
  };
}
