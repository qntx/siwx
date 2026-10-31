/**
 * Maximum byte length of a signing text accepted by the parser.
 *
 * Shared with the Rust crate via `vectors/limits/defaults.json`.
 */
export const MAX_MESSAGE_BYTES = 16_384;

/** Maximum number of `Resources:` entries a message may carry. */
export const MAX_RESOURCES = 32;

/** Maximum byte length of the optional statement line. */
export const MAX_STATEMENT_BYTES = 4096;

/** Maximum byte length of the `Request ID` field. */
export const MAX_REQUEST_ID_BYTES = 128;

/** Maximum byte length of the `URI` field. */
export const MAX_URI_BYTES = 2048;

/** Minimum character length of the `Nonce` field. */
export const MIN_NONCE_LENGTH = 8;
