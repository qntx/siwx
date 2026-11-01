import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";

import { describe, expect, it, beforeAll, afterAll } from "vite-plus/test";

import { evm } from "../../src/evm/index.ts";
import type { Eip1193Provider } from "../../src/evm/index.ts";
import { authenticate, createMessage } from "../../src/index.ts";

const ENABLED = process.env["SIWX_E2E_ANVIL"] === "1";
const OWNER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const CHAIN = "31337";

type ContractsFile = {
  contracts: Record<string, { creationBytecode: string }>;
};
const isContractsFile = (v: unknown): v is ContractsFile =>
  typeof v === "object" && v !== null && "contracts" in v;
const parsedContracts: unknown = JSON.parse(
  readFileSync(new URL("../../../../vectors/evm/e2e/contracts.json", import.meta.url), "utf8"),
);
// Fixtures: vectors/evm/e2e/Owner1271.sol + vectors/evm/e2e/Factory.sol.
const contracts: ContractsFile = isContractsFile(parsedContracts)
  ? parsedContracts
  : { contracts: {} };

let anvil: ChildProcess;
let url: string;

type JsonRpcBody = {
  result?: unknown;
  error?: { code: number; message: string };
};

const asBody = (v: unknown): JsonRpcBody => (typeof v === "object" && v !== null ? v : {});

const asString = (v: unknown): string => (typeof v === "string" ? v : "");

const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const rpcCall = async (method: string, params?: ReadonlyArray<unknown>): Promise<unknown> => {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? [] }),
  });
  const body = asBody(await res.json());
  if (body.error !== undefined) {
    const e = new Error(body.error.message);
    throw Object.assign(e, { code: body.error.code });
  }
  return body.result;
};

const provider: Eip1193Provider = {
  request: async (args) => rpcCall(args.method, args.params),
};

const asReceipt = (v: unknown): { contractAddress: string } | undefined => {
  if (typeof v !== "object" || v === null) {
    return undefined;
  }
  const addr = (v as { contractAddress?: unknown }).contractAddress;
  return typeof addr === "string" ? { contractAddress: addr } : undefined;
};

const waitReceipt = async (tx: string, tries: number): Promise<string> => {
  const r = asReceipt(await rpcCall("eth_getTransactionReceipt", [tx]));
  if (r !== undefined) {
    return r.contractAddress;
  }
  if (tries <= 0) {
    throw new Error("receipt timeout");
  }
  await sleep(50);
  return waitReceipt(tx, tries - 1);
};

const send = async (data: string): Promise<string> => {
  const tx = asString(await rpcCall("eth_sendTransaction", [{ from: OWNER, data }]));
  return waitReceipt(tx, 50);
};

const waitUp = async (tries: number): Promise<void> => {
  try {
    await rpcCall("eth_chainId");
  } catch {
    if (tries <= 0) {
      throw new Error("anvil did not start");
    }
    await sleep(50);
    await waitUp(tries - 1);
  }
};

const personalSign = async (text: string, signer: string): Promise<string> =>
  asString(await rpcCall("personal_sign", [`0x${Buffer.from(text).toString("hex")}`, signer]));

const hexToBytes = (s: string): Uint8Array => {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return b;
};

const concat = (...xs: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of xs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};

const keccak256 = async (b: Uint8Array): Promise<Uint8Array> => {
  const { keccak_256 } = await import("@noble/hashes/sha3.js");
  return keccak_256(b);
};

/** Creation code + abi.encode(owner) constructor args. */
const creationCode = (name: string): string => {
  const c = contracts.contracts[name];
  return c?.creationBytecode ?? "";
};

/** Creation code + abi.encode(owner) constructor args. */
const owner1271Init = (owner: string): string =>
  `${creationCode("Owner1271")}${owner.slice(2).padStart(64, "0")}`;

/** Abi.encodeWithSelector("deploy(address,bytes32)", owner, salt). */
const deployCalldata = async (owner: string, salt: Uint8Array): Promise<Uint8Array> => {
  const selHash = await keccak256(new TextEncoder().encode("deploy(address,bytes32)"));
  const sel = selHash.slice(0, 4);
  const args = new Uint8Array(64);
  args.set(hexToBytes(owner.slice(2)), 12);
  args.set(salt, 32);
  return concat(sel, args);
};

/** Abi.encode(address factory, bytes calldata, bytes signature) + magic. */
const wrap6492 = (factory: string, call: Uint8Array, sig: Uint8Array): Uint8Array => {
  const w = 32;
  const callPad = Math.ceil(call.length / w) * w;
  const sigPad = Math.ceil(sig.length / w) * w;
  const out = new Uint8Array(3 * w + w + callPad + w + sigPad + 32);
  out.set(hexToBytes(factory.slice(2)), 12);
  const callOff = 3 * w;
  const sigOff = callOff + w + callPad;
  out[w + w - 1] = callOff;
  out[2 * w + w - 1] = sigOff;
  const num = (v: number, at: number) => out.set(new Uint8Array([v]), at + w - 1);
  num(call.length, callOff);
  out.set(call, callOff + w);
  num(sig.length, sigOff);
  out.set(sig, sigOff + w);
  out.set(hexToBytes("6492".repeat(16)), sigOff + w + sigPad);
  return out;
};

/** Keccak(0xff ‖ factory ‖ salt ‖ keccak(init))[12..] */
const create2 = async (factory: string, salt: Uint8Array, init: string): Promise<string> => {
  const h = await keccak256(
    concat(new Uint8Array([0xff]), hexToBytes(factory), salt, await keccak256(hexToBytes(init))),
  );
  return `0x${Array.from(h.slice(12), (x) => x.toString(16).padStart(2, "0")).join("")}`;
};

const message = (address: string) =>
  createMessage({
    domain: "service.org",
    address,
    uri: "https://service.org/login",
    version: "1",
    chainId: CHAIN,
    nonce: "12341234",
    issuedAt: "2022-03-17T12:45:13.610Z",
  });

describe.skipIf(!ENABLED)("anvil e2e", () => {
  beforeAll(async () => {
    const port = 10000 + Math.floor(Math.random() * 50000);
    url = `http://127.0.0.1:${port}`;
    anvil = spawn("anvil", ["--port", String(port)], { stdio: "ignore" });
    await waitUp(100);
  });

  afterAll(() => {
    anvil.kill();
  });

  it("deployed 1271 verifies through authenticate", async () => {
    const contract = await send(owner1271Init(OWNER));
    const msg = message(contract);
    const ns = evm({ rpc: { [CHAIN]: provider } });
    const text = ns.format(msg);
    const sig = hexToBytes(await personalSign(text, OWNER));
    await authenticate(ns, {
      message: text,
      signature: sig,
      expect: {
        domain: "service.org",
        nonce: "12341234",
        time: new Date("2022-03-17T12:45:14.610Z"),
        skewSeconds: 60,
      },
    });
    expect.assertions(0);
  });

  it("wrong-owner signature fails", async () => {
    const contract = await send(owner1271Init(OWNER));
    const ns = evm({ rpc: { [CHAIN]: provider } });
    const msg = message(contract);
    const text = ns.format(msg);
    const sig = hexToBytes(await personalSign(text.replace("12341234", "87654321"), OWNER));
    await expect(ns.verify(msg, new TextEncoder().encode(text), sig)).rejects.toMatchObject({
      code: "VerificationFailed",
    });
  });

  it("counterfactual 6492 verifies", async () => {
    const factory = await send(creationCode("Factory"));
    const salt = new Uint8Array(32);
    salt[31] = 42;
    const init = owner1271Init(OWNER);
    const cf = await create2(factory, salt, init);
    const call = await deployCalldata(OWNER, salt);
    const ns = evm({ rpc: { [CHAIN]: provider } });
    const msg = message(cf);
    const text = ns.format(msg);
    const sig = hexToBytes(await personalSign(text, OWNER));
    const wrapped = wrap6492(factory, call, sig);
    await ns.verify(msg, new TextEncoder().encode(text), wrapped);
    expect.assertions(0);
  });

  it("provider on wrong chain id → Mismatch", async () => {
    const contract = await send(owner1271Init(OWNER));
    const ns = evm({ rpc: { "1": provider } });
    const msg = message(contract);
    const text = ns.format(msg).replace(`Chain ID: ${CHAIN}`, "Chain ID: 1");
    const msgOn1 = ns.parse(new TextEncoder().encode(text));
    const sig = hexToBytes(await personalSign(text, OWNER));
    await expect(ns.verify(msgOn1, new TextEncoder().encode(text), sig)).rejects.toMatchObject({
      code: "Mismatch",
    });
  });

  it("EOA verifies offline", async () => {
    const ns = evm({ rpc: { [CHAIN]: provider } });
    const msg = message(OWNER);
    const text = ns.format(msg);
    const sig = hexToBytes(await personalSign(text, OWNER));
    await ns.verify(msg, new TextEncoder().encode(text), sig);
    expect.assertions(0);
  });
});
