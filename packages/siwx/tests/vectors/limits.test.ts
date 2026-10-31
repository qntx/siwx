import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import {
  MAX_MESSAGE_BYTES,
  MAX_REQUEST_ID_BYTES,
  MAX_RESOURCES,
  MAX_STATEMENT_BYTES,
  MAX_URI_BYTES,
  MIN_NONCE_LENGTH,
} from "../../src/index.ts";

// Shared golden file; the Rust suite reads the same file in
// crates/siwx/tests/limits.rs (see vectors/README.md).
const DEFAULTS = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/limits/defaults.json"), "utf8"),
) as Record<string, number>;

describe("core limits", () => {
  test("constants match vectors/limits/defaults.json", () => {
    expect(MAX_MESSAGE_BYTES).toBe(DEFAULTS["maxMessageBytes"]);
    expect(MAX_RESOURCES).toBe(DEFAULTS["maxResources"]);
    expect(MAX_STATEMENT_BYTES).toBe(DEFAULTS["maxStatementBytes"]);
    expect(MAX_REQUEST_ID_BYTES).toBe(DEFAULTS["maxRequestIdBytes"]);
    expect(MAX_URI_BYTES).toBe(DEFAULTS["maxUriBytes"]);
    expect(MIN_NONCE_LENGTH).toBe(DEFAULTS["minNonceLength"]);
  });
});
