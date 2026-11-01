/** SIWS (Sign-In-With-Solana) text layout — Phantom ABNF, LF only. */

import { SiwxError, syntaxError } from "../core/error.ts";
import type { Field } from "../core/error.ts";
import { MID, SUFFIX, optionalTags } from "../core/layout.ts";
import { MAX_MESSAGE_BYTES } from "../core/limits.ts";
import type { Message } from "../core/message.ts";
import { createMessage } from "../core/message.ts";
import { utf8Decode, utf8ByteLength } from "../core/utf8.ts";

const LABEL = "Solana";

/**
 * Format `message` as a SIWS signing text.
 *
 * @throws {SiwxError} `InvalidField` `scheme` (SIWS has none) or `statement` (empty).
 */
export function format(message: Message): string {
  if (message.scheme !== undefined) {
    throw new SiwxError({ code: "InvalidField", field: "scheme", reason: "not supported by SIWS" });
  }
  if (message.statement !== undefined) {
    if (message.statement === "") {
      throw new SiwxError({ code: "InvalidField", field: "statement", reason: "empty" });
    }
    if (message.statement.startsWith("URI: ")) {
      throw new SiwxError({
        code: "InvalidField",
        field: "statement",
        reason: "ambiguous with the URI: tag",
      });
    }
  }
  let out = `${message.domain}${MID}${LABEL}${SUFFIX}\n${message.address}`;
  if (message.statement !== undefined) {
    out += `\n\n${message.statement}`;
  }
  out += `\n\nURI: ${message.uri}`;
  out += `\nVersion: ${message.version}`;
  out += `\nChain ID: ${message.chainId}`;
  out += `\nNonce: ${message.nonce}`;
  out += `\nIssued At: ${message.issuedAt}`;
  if (message.expirationTime !== undefined) {
    out += `\nExpiration Time: ${message.expirationTime}`;
  }
  if (message.notBefore !== undefined) {
    out += `\nNot Before: ${message.notBefore}`;
  }
  if (message.requestId !== undefined) {
    out += `\nRequest ID: ${message.requestId}`;
  }
  if (message.resources !== undefined) {
    out += "\nResources:";
    for (const r of message.resources) {
      out += `\n- ${r}`;
    }
  }
  return out;
}

const missingUri = (): SiwxError => syntaxError("MissingField", "uri");

/** The optional statement and the gap up to the required `URI: ` line. */
function statementThenFields(lines: string[], i: { v: number }): string | undefined {
  if (i.v >= lines.length) {
    throw missingUri();
  }
  if (lines[i.v] !== "") {
    throw syntaxError("ExpectedBlankLine");
  }
  i.v++;
  const l = lines[i.v];
  if (l === undefined) {
    throw missingUri();
  }
  if (l === "") {
    throw syntaxError("ExpectedBlankLine");
  }
  if (l.startsWith("URI: ")) {
    return undefined;
  }
  // Single-line statement, then one blank line before fields.
  i.v++;
  const after = lines[i.v];
  if (after === undefined) {
    throw missingUri();
  }
  if (after !== "") {
    throw syntaxError("ExpectedBlankLine");
  }
  i.v++;
  return l;
}

/**
 * Parse `text` into a validated message; the preamble label must be exactly `"Solana"`.
 *
 * @throws {SiwxError} `Syntax`, `Mismatch` `label`, or `InvalidField`.
 */
export function parse(text: string): Message {
  const byteLength = utf8ByteLength(text);
  if (byteLength > MAX_MESSAGE_BYTES) {
    throw new SiwxError({
      code: "MessageTooLarge",
      length: byteLength,
      max: MAX_MESSAGE_BYTES,
    });
  }
  if (text.includes("\r")) {
    throw syntaxError("CarriageReturn");
  }
  if (text.endsWith("\n")) {
    throw syntaxError("UnexpectedTrailing");
  }
  const lines = text.split("\n");
  const idx = { v: 0 };
  const preamble = lines[idx.v++];
  if (preamble === undefined) {
    throw syntaxError("UnexpectedEof");
  }
  const mid = preamble.indexOf(MID);
  if (mid === -1) {
    throw syntaxError("MissingPreamble");
  }
  const domain = preamble.slice(0, mid);
  const tail = preamble.slice(mid + MID.length);
  if (!tail.endsWith(SUFFIX)) {
    throw syntaxError("MissingAccountSuffix");
  }
  const label = tail.slice(0, tail.length - SUFFIX.length);
  if (label !== LABEL) {
    throw new SiwxError({
      code: "Mismatch",
      field: "label",
      expected: LABEL,
      actual: label,
    });
  }
  const address = lines[idx.v++];
  if (address === undefined) {
    throw syntaxError("UnexpectedEof");
  }
  const statement = statementThenFields(lines, idx);
  const take = (tag: string, field: Field): string => {
    const line = lines[idx.v];
    if (line === undefined || !line.startsWith(tag)) {
      throw syntaxError("MissingField", field);
    }
    idx.v++;
    return line.slice(tag.length);
  };
  const uri = take("URI: ", "uri");
  const version = take("Version: ", "version");
  const chainId = take("Chain ID: ", "chainId");
  const nonce = take("Nonce: ", "nonce");
  const issuedAt = take("Issued At: ", "issuedAt");
  const tail4 = optionalTags(lines, idx.v);
  return createMessage({
    domain,
    address,
    ...(statement === undefined ? {} : { statement }),
    uri,
    version,
    chainId,
    nonce,
    issuedAt,
    ...tail4,
  });
}

/**
 * {@link parse} over raw bytes: size check, strict UTF-8 (`InvalidUtf8`), then parse.
 *
 * @throws {SiwxError}
 */
export function parseBytes(bytes: Uint8Array): Message {
  if (bytes.length > MAX_MESSAGE_BYTES) {
    throw new SiwxError({
      code: "MessageTooLarge",
      length: bytes.length,
      max: MAX_MESSAGE_BYTES,
    });
  }
  const text = utf8Decode(bytes);
  if (text === undefined) {
    throw syntaxError("InvalidUtf8");
  }
  return parse(text);
}
