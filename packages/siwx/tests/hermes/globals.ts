/**
 * Test-only globals installed before the library modules evaluate, for the raw Hermes CLI
 * (`hermes`, no RN host). Each shim mirrors what an Expo / React Native runtime provides in
 * production — the library documents these as runtime requirements and ships no fallbacks.
 */

const has = (name: string): boolean => Reflect.get(globalThis, name) !== undefined;

/**
 * Referenced by entry.ts so bundlers keep this module (and its ordering): package.json sets
 * `sideEffects: false`, so bun/esbuild would tree-shake a pure side-effect module and skip
 * installation entirely.
 */
export const hermesGlobalsInstalled = true;

// TextDecoder — production: Expo ships a UTF-8 TextDecoder on native (Hermes
// itself ships TextEncoder only). @blockchaincommons/dcbor constructs one with
// `{ fatal: true }` at module load and uses it for CBOR text strings. Minimal
// UTF-8 decoder: fatal mode throws TypeError on ill-formed input per the
// encoding spec; otherwise invalid, truncated, overlong, surrogate, and
// out-of-range sequences each decode to U+FFFD, consuming the longest
// well-formed prefix of the ill-formed subpart.
if (!has("TextDecoder")) {
  class HermesTextDecoder {
    readonly encoding = "utf8";
    readonly fatal: boolean;
    readonly ignoreBOM: boolean;

    constructor(label = "utf8", options?: { fatal?: boolean; ignoreBOM?: boolean }) {
      if (label.toLowerCase().replaceAll("-", "") !== "utf8") {
        throw new RangeError(`The encoding label provided ('${label}') is invalid.`);
      }
      this.fatal = options?.fatal === true;
      this.ignoreBOM = options?.ignoreBOM === true;
    }

    // oxlint-disable-next-line no-restricted-types -- decode(null) is part of the WebIDL signature
    decode(input?: ArrayBuffer | ArrayBufferView | null): string {
      if (input === undefined || input === null) {
        return "";
      }
      const bytes =
        input instanceof ArrayBuffer
          ? new Uint8Array(input)
          : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      const replacement = (): string => {
        if (this.fatal) {
          throw new TypeError("The encoded data was not valid for encoding utf-8");
        }
        return String.fromCodePoint(0xfffd);
      };
      let out = "";
      let i = 0;
      // UTF-8 BOM is stripped by default (ignoreBOM: false).
      if (!this.ignoreBOM && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
        i = 3;
      }
      while (i < bytes.length) {
        const b0 = bytes[i];
        if (b0 === undefined) {
          break;
        }
        if (b0 < 0x80) {
          out += String.fromCodePoint(b0);
          i += 1;
          continue;
        }
        // Sequence length and valid range for the second byte (the range also
        // encodes the overlong / surrogate / >U+10FFFF restrictions).
        let len: number;
        let lo = 0x80;
        let hi = 0xbf;
        if (b0 >= 0xc2 && b0 <= 0xdf) {
          len = 2;
        } else if (b0 === 0xe0) {
          len = 3;
          lo = 0xa0;
        } else if (b0 === 0xed) {
          len = 3;
          hi = 0x9f;
        } else if (b0 >= 0xe1 && b0 <= 0xef) {
          len = 3;
        } else if (b0 === 0xf0) {
          len = 4;
          lo = 0x90;
        } else if (b0 === 0xf4) {
          len = 4;
          hi = 0x8f;
        } else if (b0 >= 0xf1 && b0 <= 0xf3) {
          len = 4;
        } else {
          // C0/C1, F5..FF, or a stray continuation byte.
          out += replacement();
          i += 1;
          continue;
        }
        const b1 = bytes[i + 1];
        if (b1 === undefined || b1 < lo || b1 > hi) {
          out += replacement();
          i += 1;
          continue;
        }
        let cp: number;
        if (len === 2) {
          cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
        } else {
          const b2 = bytes[i + 2];
          if (b2 === undefined || b2 < 0x80 || b2 > 0xbf) {
            out += replacement();
            i += 2;
            continue;
          }
          if (len === 3) {
            cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
          } else {
            const b3 = bytes[i + 3];
            if (b3 === undefined || b3 < 0x80 || b3 > 0xbf) {
              out += replacement();
              i += 3;
              continue;
            }
            cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
          }
        }
        out += String.fromCodePoint(cp);
        i += len;
      }
      return out;
    }
  }
  Reflect.set(globalThis, "TextDecoder", HermesTextDecoder);
}
