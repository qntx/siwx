import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { SiwxError, createMessage } from "../../src/index.ts";
import type { MessageFields } from "../../src/index.ts";
import { svm, siws, offchainMessage } from "../../src/svm/index.ts";

const json = (p: string) =>
  JSON.parse(readFileSync(new URL(`../../../../vectors/${p}`, import.meta.url), "utf8"));

const hexToBytes = (s: string) => {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return b;
};

const fieldsFromJson = (v: Record<string, unknown>): MessageFields => ({
  scheme: (v["scheme"] as string | null) ?? undefined,
  domain: (v["domain"] as string | undefined) ?? "",
  address: (v["address"] as string | undefined) ?? "",
  statement: (v["statement"] as string | null) ?? undefined,
  uri: (v["uri"] as string | undefined) ?? "",
  version: (v["version"] as string | undefined) ?? "",
  chainId: String(v["chainId"] ?? ""),
  nonce: (v["nonce"] as string | undefined) ?? "",
  issuedAt: (v["issuedAt"] as string | undefined) ?? "",
  expirationTime: (v["expirationTime"] as string | null) ?? undefined,
  notBefore: (v["notBefore"] as string | null) ?? undefined,
  requestId: (v["requestId"] as string | null) ?? undefined,
  resources: (v["resources"] as string[] | null) ?? undefined,
});

const checkErr = (e: SiwxError, want: { code: string; syntax?: string; field?: string }) => {
  expect(e.code).toBe(want.code);
  const { info } = e;
  if (want.syntax !== undefined && info.code === "Syntax") {
    expect(info.syntax).toBe(want.syntax);
    if (want.field !== undefined && info.syntax === "MissingField") {
      expect(info.field).toBe(want.field);
    }
    return;
  }
  if (want.field !== undefined && "field" in info) {
    expect(info.field).toBe(want.field);
  }
};

describe("siws contract vectors", () => {
  const contract = json("siws/contract.json") as {
    accept: Array<{ name: string; text: string; fields: Record<string, unknown> }>;
    reject: Array<{
      name: string;
      text: string;
      error: { code: string; syntax?: string; field?: string };
    }>;
    formatReject: Array<{
      name: string;
      fields: Record<string, unknown>;
      error: { code: string; syntax?: string; field?: string };
    }>;
  };
  const ns = svm();

  it.each(contract.accept)("$name", (c) => {
    const parsed = ns.parse(new TextEncoder().encode(c.text));
    const want = createMessage(fieldsFromJson(c.fields));
    expect({ ...parsed }).toStrictEqual({ ...want });
    expect(ns.format(parsed)).toBe(c.text);
  });

  it.each(contract.formatReject ?? [])("$name", (c) => {
    let thrown: unknown;
    try {
      ns.format(createMessage(fieldsFromJson(c.fields)));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    if (thrown instanceof SiwxError) {
      checkErr(thrown, c.error);
    }
  });

  it.each(contract.reject)("$name", (c) => {
    let thrown: unknown;
    try {
      ns.parse(new TextEncoder().encode(c.text));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    if (thrown instanceof SiwxError) {
      checkErr(thrown, c.error);
    }
  });
});

describe("siws offchain vectors", () => {
  const off = json("siws/offchain.json") as {
    cases: Array<{
      name: string;
      signedHex: string;
      error: { code: string; syntax?: string; field?: string } | null;
      fields?: Record<string, unknown>;
    }>;
  };
  const ns = svm();

  it.each(off.cases)("$name", (c) => {
    const signed = hexToBytes(c.signedHex);
    if (c.error === null) {
      const m = ns.parse(signed);
      expect({ ...m }).toStrictEqual({ ...createMessage(fieldsFromJson(c.fields ?? {})) });
      return;
    }
    let thrown: unknown;
    try {
      ns.parse(signed);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    if (thrown instanceof SiwxError) {
      checkErr(thrown, c.error);
    }
  });
});

describe("svm account vectors", () => {
  const acct = json("svm/account.json") as {
    cases: Array<{
      name: string;
      address: string;
      chainId: string;
      accountId?: string;
      error?: { code: string; field?: string };
    }>;
  };
  const ns = svm();

  it.each(acct.cases)("$name", (c) => {
    const run = () =>
      ns.account(
        createMessage(
          fieldsFromJson({
            domain: "service.org",
            address: c.address,
            uri: "https://service.org/login",
            version: "1",
            chainId: c.chainId,
            nonce: "12341234",
            issuedAt: "2022-03-17T12:45:13.610Z",
          }),
        ),
      );
    if (c.error === undefined) {
      expect(run().id).toBe(c.accountId);
      return;
    }
    let thrown: unknown;
    try {
      run();
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    if (thrown instanceof SiwxError) {
      checkErr(thrown, c.error);
    }
  });
});

describe("svm ed25519 vectors", () => {
  const ed = json("svm/ed25519.json") as {
    cases: Array<{
      name: string;
      text?: string;
      signedHex?: string;
      signatureHex: string;
      error: { code: string } | null;
    }>;
  };
  const ns = svm();

  it.each(ed.cases)("$name", async (c) => {
    const signed =
      c.text === undefined ? hexToBytes(c.signedHex ?? "") : new TextEncoder().encode(c.text);
    const msg = ns.parse(signed);
    const sig = hexToBytes(c.signatureHex);
    const error = await ns.verify(msg, signed, sig).then(
      () => null,
      (error: unknown) => error,
    );
    if (c.error === null) {
      expect(error).toBeNull();
    } else {
      expect(error).toBeInstanceOf(SiwxError);
      if (error instanceof SiwxError) {
        checkErr(error, c.error);
      }
    }
  });
});

describe("ed25519-speccheck vectors", () => {
  const cases = json("svm/speccheck/cases.json") as Array<{
    message: string;
    pub_key: string;
    signature: string;
  }>;
  const expected = json("svm/speccheck-expected.json") as {
    cases: Array<{ index: number; accept: boolean }>;
  };
  const ns = svm();

  it.each(cases.map((c, index) => ({ ...c, index })))("case $index", async (c) => {
    const msgBytes = hexToBytes(c.message);
    // speccheck pub_key is hex — encode as base58 for our address path.
    const { base58 } = await import("@scure/base");
    const address = base58.encode(hexToBytes(c.pub_key));
    const msg = createMessage(
      fieldsFromJson({
        domain: "service.org",
        address,
        uri: "https://service.org/login",
        version: "1",
        chainId: "mainnet",
        nonce: "12341234",
        issuedAt: "2022-03-17T12:45:13.610Z",
      }),
    );
    const sig = hexToBytes(c.signature);
    const error = await ns.verify(msg, msgBytes, sig).then(
      () => null,
      (error: unknown) => error,
    );
    const want = expected.cases[c.index]!.accept;
    if (want) {
      expect(error).toBeNull();
    } else {
      expect(error).not.toBeNull();
    }
  });
});

describe("siws format/parse + envelope", () => {
  it("offchainMessage produces a parseable envelope", () => {
    const ns = svm();
    const msg = createMessage(
      fieldsFromJson({
        domain: "service.org",
        address: "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
        uri: "https://service.org/login",
        version: "1",
        chainId: "mainnet",
        nonce: "12341234",
        issuedAt: "2022-03-17T12:45:13.610Z",
      }),
    );
    const text = siws.format(msg);
    const env = offchainMessage(text, "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj");
    expect({ ...ns.parse(env) }).toStrictEqual({ ...msg });
  });
});

describe("siws round-trip property", () => {
  // Hand-rolled seeded generator — no new devDeps.
  let state = 0x51ab5e;
  const rand = () => {
    // Plain float multiply stays exact below 2^53 — no bitwise ops.
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state / 4294967296;
  };
  const pick = <T>(xs: T[]): T => xs[Math.floor(rand() * xs.length)]!;

  it("100 seeded messages round-trip", () => {
    const ns = svm();
    const words = ["alpha", "beta", "gamma", "service", "login", "claim", "a1", "x.y"];
    for (let n = 0; n < 100; n++) {
      const stmt = rand() < 0.6 ? pick(words) : undefined;
      const res =
        rand() < 0.4
          ? Array.from({ length: Math.floor(rand() * 3) }, () => `https://a.example/${pick(words)}`)
          : undefined;
      const req = rand() < 0.3 ? "req" : undefined;
      const msg = createMessage(
        fieldsFromJson({
          domain: "service.org",
          address: "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
          statement: stmt,
          uri: "https://service.org/login",
          version: "1",
          chainId: pick(["mainnet", "testnet", "devnet", "localnet"]),
          nonce: "12341234",
          issuedAt: "2022-03-17T12:45:13.610Z",
          requestId: req,
          resources: res,
        }),
      );
      const text = ns.format(msg);
      const back = ns.parse(new TextEncoder().encode(text));
      expect({ ...back }).toStrictEqual({ ...msg });
      expect(ns.format(back)).toBe(text);
    }
  });
});
