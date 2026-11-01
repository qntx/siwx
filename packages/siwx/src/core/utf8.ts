//! Strict UTF-8 helpers.
//!
//! `TextEncoder`/`TextDecoder` exist on every supported platform (Node,
//! browsers, Hermes). Decoding must reject exactly what Rust
//! `str::from_utf8` rejects — overlongs, surrogates, > U+10FFFF,
//! truncated sequences — so `fatal: true` is used (which follows the
//! WHATWG fatal algorithm and rejects all of those).

const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder("utf-8", { fatal: true });

/** Encode `text` as UTF-8 bytes. */
export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Decode `bytes` as strict UTF-8; `undefined` on any invalid sequence. */
export function utf8Decode(bytes: Uint8Array): string | undefined {
  try {
    return fatalDecoder.decode(bytes);
  } catch {
    return undefined;
  }
}

/** UTF-8 byte length of `text` (JS string length counts UTF-16 code units). */
export function utf8ByteLength(text: string): number {
  return encoder.encode(text).length;
}
