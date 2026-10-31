//! `@qntx/siwx` — Sign-In with X (CAIP-122) for TypeScript.
//!
//! Mirrors the `siwx` Rust crate 1:1: same error codes, field names,
//! validation order, layout, and `Expect` semantics; both languages run
//! the same vector files in `vectors/`.
//!
//! The Ethereum namespace lives at `@qntx/siwx/evm`.

export type { AccountId } from "./core/account.ts";
export { createAccountId, parseAccountId } from "./core/account.ts";
export * as eip4361 from "./core/eip4361.ts";
export type { Parsed } from "./core/eip4361.ts";
export { SiwxError } from "./core/error.ts";
export type { Field, SiwxErrorCode, SiwxErrorInfo, SyntaxKind } from "./core/error.ts";
export {
  MAX_MESSAGE_BYTES,
  MAX_REQUEST_ID_BYTES,
  MAX_RESOURCES,
  MAX_STATEMENT_BYTES,
  MAX_URI_BYTES,
  MIN_NONCE_LEN,
} from "./core/limits.ts";
export type { Message, MessageFields } from "./core/message.ts";
export { createMessage } from "./core/message.ts";
export type { Authenticated, Namespace } from "./core/namespace.ts";
export { authenticate } from "./core/namespace.ts";
export type { Expect } from "./core/expect.ts";
export { checkExpect } from "./core/expect.ts";
export { generateNonce } from "./core/nonce.ts";
export type { Timestamp } from "./core/timestamp.ts";
export { parseTimestamp, timestampFromDate } from "./core/timestamp.ts";
