import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import {
  MAX_MESSAGE_BYTES,
  MAX_REQUEST_ID_BYTES,
  MAX_RESOURCES,
  MAX_STATEMENT_BYTES,
  MAX_URI_BYTES,
  MIN_NONCE_LEN,
  parseTimestamp,
  timestampFromDate,
  generateNonce,
} from "../../src/index.ts";

const json = (p: string) =>
  JSON.parse(readFileSync(new URL(`../../../../vectors/${p}`, import.meta.url), "utf8"));

it("limits match shared vector", () => {
  const d = json("limits/defaults.json");
  expect(MAX_MESSAGE_BYTES).toBe(d.maxMessageBytes);
  expect(MAX_RESOURCES).toBe(d.maxResources);
  expect(MAX_STATEMENT_BYTES).toBe(d.maxStatementBytes);
  expect(MAX_REQUEST_ID_BYTES).toBe(d.maxRequestIdBytes);
  expect(MAX_URI_BYTES).toBe(d.maxUriBytes);
  expect(MIN_NONCE_LEN).toBe(d.minNonceLength);
});

const tsCases = json("timestamp/from-instant.json") as {
  cases: Array<{ input: string; out: string }>;
};

describe("timestampFromDate vectors", () => {
  it.each(tsCases.cases)("$input", (c) => {
    const t = parseTimestamp(c.input);
    expect(t).toBeDefined();
    expect(timestampFromDate(new Date(t!.epochMs))).toBe(c.out);
  });
});

describe("parseTimestamp edges", () => {
  const good = [
    "2022-03-17T12:45:13Z",
    "2022-03-17T12:45:13.610Z",
    "2022-03-17t12:45:13z",
    "2022-03-17T12:45:13.61Z",
    "2022-03-17T12:45:13+05:30",
    "2022-03-17T12:45:13-05:30",
    "2020-02-29T00:00:00Z",
  ];

  it.each(good)("accepts %s", (s) => expect(parseTimestamp(s)).toBeDefined());
  const bad = [
    "2022-03-17 12:45:13Z",
    "2022-03-17T12:45:13",
    "2022-02-30T00:00:00Z",
    "2022-03-17T25:00:00Z",
    "2022-03-17T12:60:00Z",
    "2022-03-17T12:45:60Z",
    "2022-13-01T00:00:00Z",
    "2022-00-01T00:00:00Z",
    "2022-03-17T12:45:13+24:00",
    "2022-03-17T12:45:13+05:60",
    "2022-3-17T12:45:13Z",
  ];

  it.each(bad)("rejects %s", (s) => expect(parseTimestamp(s)).toBeUndefined());
});

describe("generateNonce", () => {
  it("17 ASCII alphanumerics", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 64; i++) {
      const n = generateNonce();
      expect(n).toMatch(/^[A-Za-z0-9]{17}$/);
      seen.add(n);
    }
    expect(seen.size).toBe(64);
  });
});
