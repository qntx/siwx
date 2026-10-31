import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { SiwxError, checkExpect, createMessage, eip4361 } from "../../src/index.ts";
import type { Expect, MessageFields } from "../../src/index.ts";

const json = (p: string) =>
  JSON.parse(readFileSync(new URL(`../../../../vectors/${p}`, import.meta.url), "utf8"));

function fieldsFromJson(v: Record<string, unknown>): MessageFields {
  return {
    scheme: (v["scheme"] as string | null) ?? undefined,
    domain: v["domain"] as string,
    address: v["address"] as string,
    statement: (v["statement"] as string | null) ?? undefined,
    uri: v["uri"] as string,
    version: v["version"] as string,
    chainId: String(v["chainId"]),
    nonce: v["nonce"] as string,
    issuedAt: v["issuedAt"] as string,
    expirationTime: (v["expirationTime"] as string | null) ?? undefined,
    notBefore: (v["notBefore"] as string | null) ?? undefined,
    requestId: (v["requestId"] as string | null) ?? undefined,
    resources: (v["resources"] as string[] | null) ?? undefined,
  };
}

const contract = json("eip4361/contract.json") as {
  accept: Array<{ name: string; text: string; label: string; fields: Record<string, unknown> }>;
  reject: Array<{
    name: string;
    text: string;
    note?: string;
    error: { code: string; syntax?: string; field?: string };
  }>;
};

describe("contract accept", () => {
  it.each(contract.accept)("$name", (c) => {
    const parsed = eip4361.parse(c.text);
    expect(parsed.label).toBe(c.label);
    expect({ ...parsed.message }).toStrictEqual({ ...createMessage(fieldsFromJson(c.fields)) });
    expect(eip4361.format(c.label, parsed.message)).toBe(c.text);
  });
});

describe("contract reject", () => {
  it.each(contract.reject)("$name", (c) => {
    let thrown: SiwxError | undefined;
    try {
      if (c.note !== undefined && c.note.includes("synthesizes")) {
        eip4361.parseBytes(new Uint8Array([0xff]));
      } else {
        eip4361.parse(c.text);
      }
    } catch (error) {
      thrown = error as SiwxError;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    expect(thrown!.code).toBe(c.error.code);
    const { info } = thrown!;
    if (c.error.syntax !== undefined && info.code === "Syntax") {
      expect(info.syntax).toBe(c.error.syntax);
    }
    if (c.error.field !== undefined && "field" in info) {
      expect(info.field).toBe(c.error.field);
    }
  });
});

const expects = json("eip4361/expect.json") as {
  cases: Array<{
    name: string;
    fields: Record<string, unknown>;
    expect: Record<string, unknown>;
    error: { code: string; field?: string } | null;
  }>;
};

describe("expect vectors", () => {
  it.each(expects.cases)("$name", (c) => {
    const { expect: e } = c;
    const exp: Expect = {
      domain: e["domain"] as string,
      nonce: e["nonce"] as string,
      scheme: (e["scheme"] as string | undefined) ?? undefined,
      uri: (e["uri"] as string | undefined) ?? undefined,
      chainId: (e["chainId"] as string | undefined) ?? undefined,
      requestId: (e["requestId"] as string | undefined) ?? undefined,
      time: e["time"] === undefined ? undefined : new Date(e["time"] as string),
      skewSeconds: (e["skewSeconds"] as number | undefined) ?? undefined,
      maxAgeSeconds: (e["maxAgeSeconds"] as number | undefined) ?? undefined,
    };
    const msg = createMessage(fieldsFromJson(c.fields));
    if (c.error === null) {
      expect(() => checkExpect(msg, exp)).not.toThrow();
    } else {
      let thrown: SiwxError | undefined;
      try {
        checkExpect(msg, exp);
      } catch (error) {
        thrown = error as SiwxError;
      }
      expect(thrown).toBeInstanceOf(SiwxError);
      expect(thrown!.code).toBe(c.error.code);
      const { info } = thrown!;
      if (c.error.field !== undefined && "field" in info) {
        expect(info.field).toBe(c.error.field);
      }
    }
  });
});
