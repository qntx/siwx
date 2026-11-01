import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { UNIVERSAL_VALIDATOR_BYTECODE } from "../../src/evm/bytecode.ts";
import { evm } from "../../src/evm/index.ts";
import type { Eip1193Provider } from "../../src/evm/index.ts";
import { decodeResult, deploylessCalldata } from "../../src/evm/validator.ts";
import { SiwxError, createMessage } from "../../src/index.ts";

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

const bytesToHex = (b: Uint8Array) =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;

const fields = (chainId: string) =>
  createMessage({
    domain: "service.org",
    address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
    uri: "https://service.org/login",
    version: "1",
    chainId,
    nonce: "12341234",
    issuedAt: "2022-03-17T12:45:13.610Z",
  });

const MAGIC = hexToBytes("6492".repeat(16));

/** Fake provider: fixed responses per call, counts invocations. */
function fakeProvider(
  responses: ReadonlyArray<unknown>,
): Eip1193Provider & { calls: Array<{ method: string }> } {
  const calls: Array<{ method: string }> = [];
  let i = 0;
  return {
    calls,
    async request(args: { method: string }) {
      calls.push({ method: args.method });
      const r = responses[i++];
      if (r === undefined) {
        return Promise.reject(new Error("queue empty"));
      }
      if (typeof r === "function") {
        const err = r();
        return Promise.reject(err instanceof Error ? err : new Error(String(err)));
      }
      return Promise.resolve(r);
    },
  };
}

describe("universal-validator bytecode", () => {
  it("matches the vendored crate .hex byte-for-byte", () => {
    const crateHex = readFileSync(
      new URL(
        "../../../../crates/siwx/src/evm/bytecode/universalSignatureValidatorBytecode.hex",
        import.meta.url,
      ),
      "utf8",
    ).trim();
    expect(UNIVERSAL_VALIDATOR_BYTECODE).toBe(crateHex);
  });
});

describe("universal-validator calldata vectors", () => {
  const v = json("evm/universal-validator.json") as {
    cases: Array<{
      name: string;
      signer: string;
      hashHex: string;
      signatureHex: string;
      calldataHex: string;
    }>;
  };

  it.each(v.cases)("$name", (c) => {
    const got = deploylessCalldata(c.signer, hexToBytes(c.hashHex), hexToBytes(c.signatureHex));
    expect(bytesToHex(got)).toBe(c.calldataHex.toLowerCase());
    expect(bytesToHex(got).startsWith(`0x${UNIVERSAL_VALIDATOR_BYTECODE}`)).toBe(true);
  });
});

describe("universal-validator decode table", () => {
  const v = json("evm/universal-validator.json") as {
    decode: Array<{ resultHex: string; verdict: string }>;
  };

  it.each(v.decode)("$resultHex → $verdict", (c) => {
    if (c.verdict === "backend") {
      expect(() => decodeResult(c.resultHex)).toThrow(SiwxError);
      return;
    }
    expect(decodeResult(c.resultHex)).toBe(c.verdict === "valid");
  });
});

describe("evm rpc path", () => {
  const magicSig = new Uint8Array([...new Uint8Array(65).fill(1), ...MAGIC]);

  it("offline success makes zero RPC calls", async () => {
    const v = json("evm/eip191.json") as { cases: Array<{ text: string; signatureHex: string }> };
    const text = new TextEncoder().encode(v.cases[0]!.text);
    const sig = hexToBytes(v.cases[0]!.signatureHex);
    const provider = fakeProvider([]);
    const ns = evm({ rpc: { "1": provider } });
    const msg = ns.parse(text);
    await ns.verify(msg, text, sig);
    expect(provider.calls).toHaveLength(0);
  });

  it("6492 magic without provider → Unsupported", async () => {
    const ns = evm();
    const msg = fields("1");
    await expect(ns.verify(msg, new Uint8Array([1]), magicSig)).rejects.toMatchObject({
      code: "Unsupported",
    });
  });

  it("191 failure without provider → original 191 error", async () => {
    const ns = evm();
    const msg = fields("1");
    const e = await ns.verify(msg, new Uint8Array([1]), new Uint8Array(65)).then(
      () => null,
      (error: unknown) => error,
    );
    expect(e).toBeInstanceOf(SiwxError);
    if (e instanceof SiwxError) {
      expect(e.code).toBe("InvalidSignature");
    }
  });

  it("chain id mismatch → Mismatch, no eth_call", async () => {
    const provider = fakeProvider(["0x7a69"]);
    const ns = evm({ rpc: { "1": provider } });
    const msg = fields("1");
    const e = await ns.verify(msg, new Uint8Array([1]), magicSig).then(
      () => null,
      (error: unknown) => error,
    );
    expect(e).toBeInstanceOf(SiwxError);
    if (e instanceof SiwxError) {
      expect(e.code).toBe("Mismatch");
    }
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]!.method).toBe("eth_chainId");
  });

  it("chain id cached across verifies", async () => {
    const provider = fakeProvider(["0x1", "0x01", "0x01"]);
    const ns = evm({ rpc: { "1": provider } });
    const msg = fields("1");
    await ns.verify(msg, new Uint8Array([1]), magicSig);
    await ns.verify(msg, new Uint8Array([1]), magicSig);
    const chainCalls = provider.calls.filter((c) => c.method === "eth_chainId");
    expect(chainCalls).toHaveLength(1);
    expect(provider.calls).toHaveLength(3);
  });

  it("code-3 revert → VerificationFailed", async () => {
    const provider = fakeProvider([
      "0x1",
      () => {
        const e = new Error("execution reverted") as Error & { code: number };
        e.code = 3;
        return e;
      },
    ]);
    const ns = evm({ rpc: { "1": provider } });
    const e = await ns.verify(fields("1"), new Uint8Array([1]), magicSig).then(
      () => null,
      (error: unknown) => error,
    );
    expect((e as SiwxError).code).toBe("VerificationFailed");
  });

  it.each([
    { code: -32000, tag: "other code" },
    { code: null, tag: "no code" },
  ])("$tag → Backend", async ({ code }) => {
    const provider = fakeProvider([
      "0x1",
      () => {
        const e = new Error("boom") as Error & { code?: number };
        if (code !== null) {
          e.code = code;
        }
        return e;
      },
    ]);
    const ns = evm({ rpc: { "1": provider } });
    const e = await ns.verify(fields("1"), new Uint8Array([1]), magicSig).then(
      () => null,
      (error: unknown) => error,
    );
    expect(e).toBeInstanceOf(SiwxError);
    if (e instanceof SiwxError) {
      expect(e.code).toBe("Backend");
    }
  });

  it("error text never contains the provider URL", async () => {
    const secret = "https://secret-node.example/KEY";
    const provider = fakeProvider(["0x1", () => new Error(`cannot reach ${secret}`)]);
    const ns = evm({ rpc: { "1": provider } });
    const e = await ns.verify(fields("1"), new Uint8Array([1]), magicSig).then(
      () => null,
      (error: unknown) => error,
    );
    expect(e).toBeInstanceOf(SiwxError);
    if (e instanceof SiwxError) {
      expect(e.code).toBe("Backend");
      expect(e.message).not.toContain("secret-node");
      expect(e.message).not.toContain(secret);
    }
  });
});

describe.skipIf(process.env["SIWX_MAINNET_RPC"] === undefined)("eip1271 mainnet vectors", () => {
  const vec = json("siwe/verification/eip1271.json") as Record<
    string,
    { message: string; signature: string }
  >;
  const mainnetProvider: Eip1193Provider = {
    request: async (args) => {
      const res = await fetch(process.env["SIWX_MAINNET_RPC"]!, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...args }),
      });
      const body = (await res.json()) as { result?: unknown; error?: { code: number } };
      if (body.error !== undefined) {
        const e = new Error("rpc error") as Error & { code: number };
        e.code = body.error.code;
        throw e;
      }
      return body.result;
    },
  };

  it.each(Object.keys(vec))("%s", async (name) => {
    const ns = evm({ rpc: { "1": mainnetProvider } });
    const c = vec[name] ?? { message: "", signature: "" };
    const text = new TextEncoder().encode(c.message);
    const msg = ns.parse(text);
    const err = await ns.verify(msg, text, hexToBytes(c.signature)).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(err).toBeUndefined();
  });
});
