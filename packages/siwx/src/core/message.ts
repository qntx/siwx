//! CAIP-122 abstract data model: lexical `MessageFields` and the
//! validated `Message` produced by `createMessage` (single validation
//! path, same check order as Rust `Message::new`).

import { fieldError } from "./error.ts";
import {
  MAX_REQUEST_ID_BYTES,
  MAX_RESOURCES,
  MAX_STATEMENT_BYTES,
  MAX_URI_BYTES,
  MIN_NONCE_LEN,
} from "./limits.ts";
import { isAuthority, isPcharString, isScheme, isUri } from "./rfc3986.ts";
import { parseTimestamp } from "./timestamp.ts";
import { utf8ByteLength } from "./utf8.ts";

/** Plain lexical form of a CAIP-122 message (all strings, absent = `undefined`). */
export type MessageFields = {
  readonly scheme?: string | undefined;
  readonly domain: string;
  readonly address: string;
  readonly statement?: string | undefined;
  readonly uri: string;
  readonly version: string;
  readonly chainId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expirationTime?: string | undefined;
  readonly notBefore?: string | undefined;
  readonly requestId?: string | undefined;
  readonly resources?: ReadonlyArray<string> | undefined;
};

declare const brand: unique symbol;

/** Validated CAIP-122 message; construct only via `createMessage`. */
export type Message = {
  readonly [brand]: "Message";
} & MessageFields;

const STATEMENT_CHARS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;= ",
);

function isCaip10Address(s: string): boolean {
  if (s.length === 0 || s.length > 128) {
    return false;
  }
  for (const c of s) {
    if (!/[A-Za-z0-9]/.test(c) && c !== "-" && c !== "." && c !== "%") {
      return false;
    }
  }
  return true;
}

/**
 * Validate `fields` and return a frozen [`Message`].
 *
 * Check order (as Rust `Message::new`): scheme, domain, address, statement, uri, version, chainId,
 * nonce, issuedAt, expirationTime, notBefore, requestId, resources.
 *
 * @throws {SiwxError} `InvalidField` naming the first invalid field.
 */
export function createMessage(fields: MessageFields): Message {
  if (fields.scheme !== undefined && !isScheme(fields.scheme)) {
    throw fieldError("scheme", "not an RFC 3986 scheme");
  }
  if (fields.domain.length === 0) {
    throw fieldError("domain", "empty");
  }
  if (fields.domain.includes("@")) {
    // ERC-4361 erratum signinwithethereum/ERCs#1: userinfo rejected.
    throw fieldError("domain", "userinfo not allowed");
  }
  if (fields.domain.startsWith(":")) {
    throw fieldError("domain", "empty host");
  }
  if (!isAuthority(fields.domain)) {
    throw fieldError("domain", "not an RFC 3986 authority");
  }
  if (!isCaip10Address(fields.address)) {
    throw fieldError(
      "address",
      fields.address.length === 0 || fields.address.length > 128
        ? "expected 1..=128 characters"
        : "bad CAIP-10 charset",
    );
  }
  if (fields.statement !== undefined) {
    if (utf8ByteLength(fields.statement) > MAX_STATEMENT_BYTES) {
      throw fieldError("statement", "exceeds maximum size");
    }
    for (const c of fields.statement) {
      if (!STATEMENT_CHARS.has(c)) {
        throw fieldError("statement", "must be RFC 3986 reserved / unreserved / SP");
      }
    }
  }
  checkUri(fields.uri, "uri");
  if (fields.version !== "1") {
    throw fieldError("version", 'must be "1"');
  }
  if (fields.chainId.length === 0) {
    throw fieldError("chainId", "empty");
  }
  if (fields.chainId.length > 64) {
    throw fieldError("chainId", "exceeds 64 characters");
  }
  for (const c of fields.chainId) {
    if (!/[A-Za-z0-9]/.test(c) && c !== "-" && c !== "_" && c !== ":") {
      throw fieldError("chainId", "bad charset");
    }
  }
  if (fields.nonce.length < MIN_NONCE_LEN) {
    throw fieldError("nonce", "too short");
  }
  for (const c of fields.nonce) {
    if (!/[A-Za-z0-9]/.test(c)) {
      throw fieldError("nonce", "not ASCII alphanumeric");
    }
  }
  if (parseTimestamp(fields.issuedAt) === undefined) {
    throw fieldError("issuedAt", "not an RFC 3339 date-time");
  }
  if (fields.expirationTime !== undefined && parseTimestamp(fields.expirationTime) === undefined) {
    throw fieldError("expirationTime", "not an RFC 3339 date-time");
  }
  if (fields.notBefore !== undefined && parseTimestamp(fields.notBefore) === undefined) {
    throw fieldError("notBefore", "not an RFC 3339 date-time");
  }
  if (fields.requestId !== undefined) {
    if (utf8ByteLength(fields.requestId) > MAX_REQUEST_ID_BYTES) {
      throw fieldError("requestId", "exceeds maximum size");
    }
    if (!isPcharString(fields.requestId)) {
      throw fieldError("requestId", "must be RFC 3986 *pchar");
    }
  }
  if (fields.resources !== undefined) {
    if (fields.resources.length > MAX_RESOURCES) {
      throw fieldError("resources", "too many");
    }
    for (const uri of fields.resources) {
      checkUri(uri, "resources");
    }
  }
  const out = {
    domain: fields.domain,
    address: fields.address,
    uri: fields.uri,
    version: fields.version,
    chainId: fields.chainId,
    nonce: fields.nonce,
    issuedAt: fields.issuedAt,
    ...(fields.scheme === undefined ? {} : { scheme: fields.scheme }),
    ...(fields.statement === undefined ? {} : { statement: fields.statement }),
    ...(fields.expirationTime === undefined ? {} : { expirationTime: fields.expirationTime }),
    ...(fields.notBefore === undefined ? {} : { notBefore: fields.notBefore }),
    ...(fields.requestId === undefined ? {} : { requestId: fields.requestId }),
    ...(fields.resources === undefined ? {} : { resources: fields.resources }),
  };
  // oxlint-disable-next-line no-unsafe-type-assertion -- brand is type-level only
  return Object.freeze(out) as Message;
}

function checkUri(uri: string, field: "uri" | "resources"): void {
  if (uri.length === 0) {
    throw fieldError(field, "empty");
  }
  if (utf8ByteLength(uri) > MAX_URI_BYTES) {
    throw fieldError(field, "exceeds maximum size");
  }
  if (!isUri(uri)) {
    throw fieldError(field, "not an RFC 3986 URI");
  }
}
