import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import {
  SiwxError,
  checkExpect,
  createAccountId,
  createMessage,
  eip4361,
  parseAccountId,
} from "../src/index.ts";
import type { Expect, MessageFields } from "../src/index.ts";

const base: MessageFields = {
  domain: "service.org",
  address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
  uri: "https://service.org/login",
  version: "1",
  chainId: "1",
  nonce: "12341234",
  issuedAt: "2022-03-17T12:45:13.610Z",
};

describe("SiwxError", () => {
  it("carries info payload and code", () => {
    const e = new SiwxError({ code: "Mismatch", field: "domain", expected: "a", actual: "b" });
    expect(e.name).toBe("SiwxError");
    expect(e.code).toBe("Mismatch");
    if (e.info.code === "Mismatch") {
      expect(e.info.field).toBe("domain");
    }
    expect(e.message).toContain("a");
    expect(e).toBeInstanceOf(Error);
  });
});

describe("createMessage", () => {
  it("freezes output and omits undefined props", () => {
    const m = createMessage(base);
    expect(Object.isFrozen(m)).toBe(true);
    expect("statement" in m).toBe(false);
    expect("resources" in m).toBe(false);
    expect(() => {
      (m as { domain: string }).domain = "mutated";
    }).toThrow(TypeError);
  });

  it("domain empty host rejected", () => {
    expect(() => createMessage({ ...base, domain: ":8080" })).toThrow(SiwxError);
  });

  it("accepts empty statement/requestId/resources", () => {
    const m = createMessage({ ...base, statement: "", requestId: "", resources: [] });
    expect(m.statement).toBe("");
    expect(m.requestId).toBe("");
    expect(m.resources).toStrictEqual([]);
  });
});

describe("round-trip", () => {
  const variants: MessageFields[] = [
    base,
    { ...base, scheme: "https", statement: "hi there", resources: ["https://a/b", "ipfs://x"] },
    { ...base, statement: "", requestId: "", resources: [] },
    {
      ...base,
      expirationTime: "2022-03-18T12:45:13.610Z",
      notBefore: "2022-03-17T00:00:00Z",
      requestId: "abc",
    },
  ];

  it.each(variants)("variant %#", (f) => {
    const m = createMessage(f);
    const text = eip4361.format("Ethereum", m);
    const parsed = eip4361.parse(text);
    expect(parsed.label).toBe("Ethereum");
    expect({ ...parsed.message }).toStrictEqual({ ...m });
    expect(eip4361.format("Ethereum", parsed.message)).toBe(text);
  });
});

describe("checkExpect", () => {
  const msg = () => createMessage(base);
  const exp = (over: Partial<Expect> = {}): Expect => ({
    domain: "service.org",
    nonce: "12341234",
    time: new Date("2022-03-17T12:45:20Z"),
    skewSeconds: 60,
    ...over,
  });

  it("passes a good binding", () => {
    expect(() => checkExpect(msg(), exp())).not.toThrow(SiwxError);
  });

  it("domain mismatch names actual", () => {
    try {
      checkExpect(msg(), exp({ domain: "other.org" }));
      expect.unreachable();
    } catch (error) {
      const err = error as SiwxError;
      expect(err.code).toBe("Mismatch");
      if (err.info.code === "Mismatch") {
        expect(err.info.actual).toBe("service.org");
      }
    }
  });

  it.each([
    ["NaN time", { time: new Date(Number.NaN) }],
    ["NaN skew", { skewSeconds: Number.NaN }],
    ["Infinity skew", { skewSeconds: Number.POSITIVE_INFINITY }],
    ["negative skew", { skewSeconds: -1 }],
    ["NaN maxAge", { maxAgeSeconds: Number.NaN }],
    ["Infinity maxAge", { maxAgeSeconds: Number.POSITIVE_INFINITY }],
    ["negative maxAge", { maxAgeSeconds: -1 }],
  ])("throws RangeError for %s", (_n, over) => {
    expect(() => checkExpect(msg(), exp(over))).toThrow(RangeError);
  });

  it("absent optional field mismatch uses undefined actual", () => {
    try {
      checkExpect(msg(), exp({ requestId: "r" }));
      expect.unreachable();
    } catch (error) {
      const err = error as SiwxError;
      if (err.info.code === "Mismatch") {
        expect(err.info.actual).toBeUndefined();
      } else {
        expect.unreachable();
      }
    }
  });
});

describe("AccountId vectors (account/caip10.json)", () => {
  const v = JSON.parse(
    readFileSync(new URL("../../../vectors/account/caip10.json", import.meta.url), "utf8"),
  ) as {
    create: Array<{
      name: string;
      namespace: string;
      reference: string;
      address: string;
      id: string | null;
      error: { code: string; field?: string } | null;
    }>;
    parse: Array<{ name: string; id: string; error: { code: string; field?: string } | null }>;
  };

  it.each(v.create)("create $name", (c) => {
    const run = () => createAccountId(c.namespace, c.reference, c.address);
    if (c.error === null) {
      expect(run().id).toBe(c.id);
    } else {
      expect(run).toThrow(SiwxError);
      try {
        run();
      } catch (error) {
        const err = error as SiwxError;
        expect(err.code).toBe(c.error.code);
        const { info } = err;
        if (c.error.field !== undefined && "field" in info) {
          expect(info.field).toBe(c.error.field);
        }
      }
    }
  });

  it.each(v.parse)("parse $name", (c) => {
    const run = () => parseAccountId(c.id);
    if (c.error === null) {
      expect(run().id).toBe(c.id);
    } else {
      expect(run).toThrow(SiwxError);
      try {
        run();
      } catch (error) {
        expect((error as SiwxError).code).toBe(c.error.code);
      }
    }
  });
});
