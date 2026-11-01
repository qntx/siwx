import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { evm, validateAddress, toChecksumAddress, parseEvmChainId } from "../../src/evm/index.ts";
import { SiwxError, createMessage } from "../../src/index.ts";
import type { MessageFields } from "../../src/index.ts";

const json = (p: string) =>
  JSON.parse(readFileSync(new URL(`../../../../vectors/${p}`, import.meta.url), "utf8"));

const base: MessageFields = {
  domain: "service.org",
  address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
  uri: "https://x",
  version: "1",
  chainId: "1",
  nonce: "12341234",
  issuedAt: "2022-03-17T12:45:13.610Z",
};

const hexToBytes = (s: string) => {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return b;
};

const account = json("evm/account.json") as {
  cases: Array<{
    name: string;
    address: string;
    chainId: string;
    accountId: string | null;
    error: { code: string; field?: string } | null;
  }>;
};

describe("evm account vectors", () => {
  it.each(account.cases)("$name", (c) => {
    const ns = evm();
    const fields = { ...base, address: c.address, chainId: c.chainId };
    const run = () => ns.account(createMessage(fields));
    if (c.error === null) {
      expect(run()).toStrictEqual(expect.objectContaining({ id: c.accountId }));
    } else {
      let thrown: SiwxError | undefined;
      try {
        run();
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

const eip191 = json("evm/eip191.json") as {
  cases: Array<{
    name: string;
    text: string;
    signatureHex: string;
    error: { code: string } | null;
  }>;
};

describe("evm eip191 vectors", () => {
  const ns = evm();

  it.each(eip191.cases)("$name", async (c) => {
    const signed = new TextEncoder().encode(c.text);
    const signature = hexToBytes(c.signatureHex);
    const p = (async () => {
      const msg = ns.parse(signed);
      await ns.verify(msg, signed, signature);
    })();
    if (c.error === null) {
      await expect(p).resolves.toBeUndefined();
    } else {
      let thrown: SiwxError | undefined;
      try {
        await p;
      } catch (error) {
        thrown = error as SiwxError;
      }
      expect(thrown).toBeInstanceOf(SiwxError);
      expect(thrown!.code).toBe(c.error.code);
    }
  });
});

describe("evm address helpers", () => {
  it("checksums a lowercase input", () => {
    expect(toChecksumAddress("0xe5a12547fe4e872d192e3ececb76f2ce1aea4946")).toBe(
      "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
    );
  });

  it("validateAddress rejects bad checksum", () => {
    expect(() => validateAddress("0xe5a12547fe4E872D192E3eCecb76F2Ce1aeA4946")).toThrow(SiwxError);
  });

  it("parseEvmChainId boundaries", () => {
    expect(parseEvmChainId("0")).toBe(0n);
    expect(parseEvmChainId("18446744073709551615")).toBe(0xffffffffffffffffn);
    expect(() => parseEvmChainId("01")).toThrow(SiwxError);
    expect(() => parseEvmChainId("18446744073709551616")).toThrow(SiwxError);
  });
});
