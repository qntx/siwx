/** CAIP-122 message field or preamble component, camelCase-named. */
export type Field =
  | "label"
  | "scheme"
  | "domain"
  | "address"
  | "statement"
  | "uri"
  | "version"
  | "chainId"
  | "nonce"
  | "issuedAt"
  | "expirationTime"
  | "notBefore"
  | "requestId"
  | "resources";

/** Layout-level (ABNF) syntax failure kinds. */
export type SyntaxKind =
  | "InvalidUtf8"
  | "CarriageReturn"
  | "MissingPreamble"
  | "MissingAccountSuffix"
  | "UnexpectedEof"
  | "ExpectedBlankLine"
  | "MissingField"
  | "UnexpectedTrailing"
  | "ResourceSyntax"
  | "InvalidEnvelope";

/** Per-code error detail; `switch (info.code)` narrows the payload. */
export type SiwxErrorInfo =
  | Readonly<{ code: "MessageTooLarge"; length: number; max: number }>
  | Readonly<{ code: "Syntax"; syntax: "MissingField"; field: Field }>
  | Readonly<{ code: "Syntax"; syntax: Exclude<SyntaxKind, "MissingField"> }>
  | Readonly<{ code: "InvalidField"; field: Field; reason: string }>
  | Readonly<{ code: "Mismatch"; field: Field; expected: string; actual: string | undefined }>
  | Readonly<{ code: "InvalidOrigin" }>
  | Readonly<{ code: "Expired" }>
  | Readonly<{ code: "NotYetValid" }>
  | Readonly<{ code: "IssuedAtTooOld" }>
  | Readonly<{ code: "InvalidSignature"; reason: string }>
  | Readonly<{ code: "VerificationFailed" }>
  | Readonly<{ code: "Unsupported"; reason: string }>
  | Readonly<{ code: "Backend"; reason: string }>;

/** Stable error code set shared with the Rust implementation. */
export type SiwxErrorCode = SiwxErrorInfo["code"];

const SYNTAX_MESSAGES: Record<Exclude<SyntaxKind, "MissingField">, string> = {
  InvalidUtf8: "invalid UTF-8",
  CarriageReturn: "CR not allowed",
  MissingPreamble: "missing preamble marker",
  MissingAccountSuffix: "missing account suffix",
  UnexpectedEof: "unexpected end of input",
  ExpectedBlankLine: "expected blank line",
  UnexpectedTrailing: "unexpected trailing content",
  ResourceSyntax: "resource line must start with '- '",
  InvalidEnvelope: "invalid off-chain message envelope",
};

function describe(info: SiwxErrorInfo): string {
  if (info.code === "MessageTooLarge") {
    return `message exceeds maximum size of ${info.max} bytes, got ${info.length}`;
  }
  if (info.code === "Syntax") {
    return info.syntax === "MissingField"
      ? `invalid message syntax: missing ${info.field}`
      : `invalid message syntax: ${SYNTAX_MESSAGES[info.syntax]}`;
  }
  if (info.code === "InvalidField") {
    return `invalid ${info.field}: ${info.reason}`;
  }
  if (info.code === "Mismatch") {
    return `${info.field} mismatch: expected ${info.expected}, got ${JSON.stringify(info.actual)}`;
  }
  if (info.code === "InvalidOrigin") {
    return "invalid origin: not a serialized web origin";
  }
  if (info.code === "Expired") {
    return "message expired";
  }
  if (info.code === "NotYetValid") {
    return "message not yet valid";
  }
  if (info.code === "IssuedAtTooOld") {
    return "issued-at exceeds max age";
  }
  if (info.code === "InvalidSignature") {
    return `invalid signature: ${info.reason}`;
  }
  if (info.code === "VerificationFailed") {
    return "verification failed";
  }
  if (info.code === "Unsupported") {
    return `unsupported: ${info.reason}`;
  }
  return `backend error: ${info.reason}`;
}

/** The single error type thrown by every library failure. */
export class SiwxError extends Error {
  /** Structured payload; `code` matches the Rust `Error::code()`. */
  readonly info: SiwxErrorInfo;

  constructor(info: SiwxErrorInfo) {
    super(describe(info));
    this.name = "SiwxError";
    this.info = info;
  }

  /** Stable variant name for cross-language contract tests. */
  get code(): SiwxErrorCode {
    return this.info.code;
  }
}

/** `SiwxError` constructor shorthand for layout failures. */
export function syntaxError(syntax: SyntaxKind, field?: Field): SiwxError {
  if (syntax === "MissingField") {
    if (field === undefined) {
      throw new RangeError("MissingField requires a field");
    }
    return new SiwxError({ code: "Syntax", syntax, field });
  }
  return new SiwxError({ code: "Syntax", syntax });
}

/** `SiwxError` constructor shorthand for a malformed field value. */
export function fieldError(field: Field, reason: string): SiwxError {
  return new SiwxError({ code: "InvalidField", field, reason });
}

/** `SiwxError` constructor shorthand for a binding mismatch. */
export function mismatchError(
  field: Field,
  expected: string,
  actual: string | undefined,
): SiwxError {
  return new SiwxError({ code: "Mismatch", field, expected, actual });
}
