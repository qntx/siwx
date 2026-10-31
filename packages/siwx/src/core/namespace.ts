//! Chain namespace abstraction: parsing, formatting, and signature
//! verification for one CAIP-2 namespace.

import type { AccountId } from "./account.ts";
import type { Expect } from "./expect.ts";
import { checkExpect } from "./expect.ts";
import type { Message } from "./message.ts";
import { utf8Encode } from "./utf8.ts";

/**
 * Run a synchronous verification body as a promise; throws reject. Shared idiom for namespace
 * `verify` implementations.
 */
export async function settle<T>(run: () => T): Promise<T> {
  return new Promise((resolve) => {
    resolve(run());
  });
}

/** A chain namespace profile. */
export type Namespace = {
  /** CAIP-2 namespace, e.g. `"eip155"` / `"solana"`. */
  readonly namespace: string;
  /** Preamble label, e.g. `"Ethereum"` / `"Solana"`. */
  readonly label: string;
  /** Map `message` to an `AccountId` under this namespace's rules. */
  account: (message: Message) => AccountId;
  /** Render `message` to this namespace's signing text. */
  format: (message: Message) => string;
  /** Parse `signed` bytes, requiring label === `this.label`. */
  parse: (signed: Uint8Array) => Message;
  /** Verify `signature` over the exact `signed` bytes. */
  verify: (message: Message, signed: Uint8Array, signature: Uint8Array) => Promise<void>;
};

/** Successful `authenticate`: parsed message plus CAIP-10 identity. */
export type Authenticated = {
  readonly message: Message;
  readonly account: AccountId;
};

/** Full backend login flow: parse → checkExpect → account → verify. */
export async function authenticate(
  namespace: Namespace,
  input: {
    readonly message: string | Uint8Array;
    readonly signature: Uint8Array;
    readonly expect: Expect;
  },
): Promise<Authenticated> {
  const signed = typeof input.message === "string" ? utf8Encode(input.message) : input.message;
  const message = namespace.parse(signed);
  checkExpect(message, input.expect);
  const account = namespace.account(message);
  await namespace.verify(message, signed, input.signature);
  return { message, account };
}
