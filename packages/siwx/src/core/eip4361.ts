//! ERC-4361 signing-text layout: `format` and its strict inverse `parse`.
//! For every accepted text `t`, `format(label, parse(t).message) === t`
//! byte-for-byte.

import { SiwxError, fieldError, mismatchError, syntaxError } from "./error.ts";
import type { Field } from "./error.ts";
import { MAX_MESSAGE_BYTES } from "./limits.ts";
import { createMessage } from "./message.ts";
import type { Message, MessageFields } from "./message.ts";
import { utf8ByteLength, utf8Decode } from "./utf8.ts";

const MID = " wants you to sign in with your ";
const SUFFIX = " account:";

function takeTag(line: string, tag: string, field: Field): string {
  if (!line.startsWith(tag)) {
    throw syntaxError("MissingField", field);
  }
  return line.slice(tag.length);
}

/** Result of [`parse`]: preamble label plus the validated message. */
export type Parsed = {
  readonly label: string;
  readonly message: Message;
};

/** Render `message` as an ERC-4361 signing text under `label`. */
export function format(label: string, message: Message): string {
  let out = "";
  if (message.scheme !== undefined) {
    out += `${message.scheme}://`;
  }
  out += `${message.domain + MID + label + SUFFIX}\n`;
  out += `${message.address}\n\n`;
  if (message.statement !== undefined) {
    out += `${message.statement}\n`;
  }
  out += "\n";
  out += `URI: ${message.uri}\n`;
  out += `Version: ${message.version}\n`;
  out += `Chain ID: ${message.chainId}\n`;
  out += `Nonce: ${message.nonce}\n`;
  out += `Issued At: ${message.issuedAt}`;
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
    for (const uri of message.resources) {
      out += `\n- ${uri}`;
    }
  }
  return out;
}

/** Parse `text` into a label + validated message. */
export function parse(text: string): Parsed {
  if (utf8ByteLength(text) > MAX_MESSAGE_BYTES) {
    throw new SiwxError({
      code: "MessageTooLarge",
      length: utf8ByteLength(text),
      max: MAX_MESSAGE_BYTES,
    });
  }
  if (text.includes("\r")) {
    throw syntaxError("CarriageReturn");
  }
  const lines = text.split("\n");
  let i = 0;
  const next = (): string => {
    const l = lines[i++];
    if (l === undefined) {
      throw syntaxError("UnexpectedEof");
    }
    return l;
  };

  const preamble = next();
  const mid = preamble.indexOf(MID);
  if (mid === -1) {
    throw syntaxError("MissingPreamble");
  }
  const head = preamble.slice(0, mid);
  const tail = preamble.slice(mid + MID.length);
  if (!tail.endsWith(SUFFIX)) {
    throw syntaxError("MissingAccountSuffix");
  }
  const label = tail.slice(0, -SUFFIX.length);
  if (label.length === 0) {
    throw fieldError("label", "empty");
  }
  let scheme: string | undefined;
  let domain: string;
  const proto = head.indexOf("://");
  if (proto === -1) {
    domain = head;
  } else {
    scheme = head.slice(0, proto);
    domain = head.slice(proto + 3);
  }

  const address = next();

  let blanks = 0;
  while (lines[i + blanks] === "") {
    blanks++;
  }
  let statement: string | undefined;
  if (blanks === 1) {
    i += 1;
    statement = next();
    if (next() !== "") {
      throw syntaxError("ExpectedBlankLine");
    }
  } else if (blanks === 2) {
    i += 2;
  } else if (blanks === 3) {
    i += 3;
    statement = "";
  } else {
    throw syntaxError("ExpectedBlankLine");
  }

  const uri = takeTag(next(), "URI: ", "uri");
  const version = takeTag(next(), "Version: ", "version");
  const chainId = takeTag(next(), "Chain ID: ", "chainId");
  const nonce = takeTag(next(), "Nonce: ", "nonce");
  const issuedAt = takeTag(next(), "Issued At: ", "issuedAt");

  let expirationTime: string | undefined;
  let notBefore: string | undefined;
  let requestId: string | undefined;
  let resources: string[] | undefined;

  const line = lines[i];
  if (line !== undefined && line.startsWith("Expiration Time: ")) {
    expirationTime = line.slice("Expiration Time: ".length);
    i++;
  }
  const line2 = lines[i];
  if (line2 !== undefined && line2.startsWith("Not Before: ")) {
    notBefore = line2.slice("Not Before: ".length);
    i++;
  }
  const line3 = lines[i];
  if (line3 !== undefined && line3.startsWith("Request ID: ")) {
    requestId = line3.slice("Request ID: ".length);
    i++;
  }
  if (lines[i] === "Resources:") {
    i++;
    resources = [];
    let r: string | undefined;
    while ((r = lines[i]) !== undefined) {
      if (r.startsWith("- ")) {
        resources.push(r.slice(2));
        i++;
      } else if (r.startsWith("-")) {
        throw syntaxError("ResourceSyntax");
      } else {
        throw syntaxError("UnexpectedTrailing");
      }
    }
  }
  if (i !== lines.length) {
    throw syntaxError("UnexpectedTrailing");
  }

  const fields: MessageFields = {
    scheme,
    domain,
    address,
    statement,
    uri,
    version,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
    notBefore,
    requestId,
    resources,
  };
  return { label, message: createMessage(fields) };
}

/** [`parseBytes`]: UTF-8 strictness then [`parse`]. */
export function parseBytes(bytes: Uint8Array): Parsed {
  if (bytes.length > MAX_MESSAGE_BYTES) {
    throw new SiwxError({ code: "MessageTooLarge", length: bytes.length, max: MAX_MESSAGE_BYTES });
  }
  const text = utf8Decode(bytes);
  if (text === undefined) {
    throw syntaxError("InvalidUtf8");
  }
  return parse(text);
}

/** [`parseBytes`] plus a required preamble `label`. */
export function parseLabeled(label: string, signed: Uint8Array): Message {
  const parsed = parseBytes(signed);
  if (parsed.label !== label) {
    throw mismatchError("label", label, parsed.label);
  }
  return parsed.message;
}
