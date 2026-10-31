/// <reference types="node" />
/**
 * Seeded cross-language differential harness. TypeScript generates records: random valid
 * MessageFields → createMessage/format outcomes; mutated texts → parse outcomes; account()
 * outcomes. The Rust replay test (`crates/siwx/tests/differential.rs`, driven by `bun run
 * test:parity`) asserts identical outcomes for every record.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { Namespace } from "../../packages/siwx/src/core/namespace.ts";
import { evm } from "../../packages/siwx/src/evm/index.ts";
import { createMessage } from "../../packages/siwx/src/index.ts";
import type { MessageFields } from "../../packages/siwx/src/index.ts";
import { svm } from "../../packages/siwx/src/svm/index.ts";

const DEFAULT_SEED = 42;
const DEFAULT_COUNT = 2000;
const DEFAULT_OUT = "target/parity/differential.json";

/** Lehmer (MINSTD) PRNG — identical constants to the ur.js harness. */
export type Rng = {
  float: () => number;
  int: (min: number, max: number) => number;
  chance: (p: number) => boolean;
  pick: <T>(items: ReadonlyArray<T>) => T;
};

export function makeRng(seed: number): Rng {
  let state = Math.floor(Math.abs(seed)) % 2147483647;
  if (state === 0) {
    state = 1;
  }
  const float = (): number => {
    state = (state * 48271) % 2147483647;
    return state / 2147483647;
  };
  return {
    float,
    int: (min: number, max: number) => min + Math.floor(float() * (max - min + 1)),
    chance: (p: number) => float() < p,
    pick: <T>(items: ReadonlyArray<T>): T => {
      const i = items[Math.floor(float() * items.length)];
      if (i === undefined) {
        throw new RangeError("empty list");
      }
      return i;
    },
  };
}

export type Outcome = { ok: string } | { error: { code: string; field?: string; syntax?: string } };

export type DiffRecord = {
  seq: number;
  op:
    | "create"
    | "format_eip4361"
    | "format_siws"
    | "parse_eip4361"
    | "parse_siws"
    | "account_evm"
    | "account_svm";
  fields?: MessageFields;
  text?: string;
  outcome: Outcome;
};

type ErrorInfo = {
  code?: string;
  field?: string;
  syntax?: string;
};

const isErrorInfo = (v: unknown): v is ErrorInfo => typeof v === "object" && v !== null;

const infoOf = (error: unknown): ErrorInfo => {
  if (typeof error === "object" && error !== null && "info" in error) {
    const { info } = error;
    if (isErrorInfo(info)) {
      return info;
    }
  }
  return {};
};

const out = (run: () => string): Outcome => {
  try {
    return { ok: run() };
  } catch (error) {
    const info = infoOf(error);
    const eo: { code: string; field?: string; syntax?: string } = {
      code: info.code ?? String(error instanceof Error ? error.message : error),
    };
    if (info.field !== undefined) {
      eo.field = info.field;
    }
    if (info.syntax !== undefined) {
      eo.syntax = info.syntax;
    }
    return { error: eo };
  }
};

const DOMAINS = ["service.org", "example.com", "sub.example.co.uk", "x.io", "dom_ain"];
const SCHEMES = ["https", "http", "myapp"];
const EV_CHAINS = ["1", "137", "31337", "0x1", "eip155:5"];
const SV_CHAINS = ["mainnet", "devnet", "solana:testnet", "1", "unknown-cluster"];
const RESOURCES = ["https://docs.example.com/x", "mailto:a@b.c", "ftp://r.example/f", "ipfs://Qma"];

function randomFields(rng: Rng, ns: "evm" | "svm"): MessageFields {
  const address =
    ns === "evm"
      ? `0x${rng.pick(["f39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "AE9aA90F1a627c7a20783AF9e8747fCFEDEFAd03", "00401b0f059b5af9f71a43263f2fc17422b6b8f8"])}`
      : rng.pick([
          "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
          "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
          "So11111111111111111111111111111111111111112",
        ]);
  const ts = `20${rng.int(20, 26)}-${String(rng.int(1, 12)).padStart(2, "0")}-${String(rng.int(1, 28)).padStart(2, "0")}T${String(rng.int(0, 23)).padStart(2, "0")}:${String(rng.int(0, 59)).padStart(2, "0")}:${String(rng.int(0, 59)).padStart(2, "0")}.${String(rng.int(0, 999)).padStart(3, "0")}Z`;
  const fields: MessageFields = {
    domain: rng.pick(DOMAINS),
    address,
    uri: `https://${rng.pick(DOMAINS)}/login/${rng.int(1, 99)}`,
    version: "1",
    chainId: ns === "evm" ? rng.pick(EV_CHAINS) : rng.pick(SV_CHAINS),
    nonce: `${rng.int(10000000, 99999999)}x`,
    issuedAt: ts,
    ...(rng.chance(0.4) ? { statement: `stmt-${rng.int(1, 999)} multi word` } : {}),
    ...(ns === "evm" && rng.chance(0.3) ? { scheme: rng.pick(SCHEMES) } : {}),
    ...(rng.chance(0.2) ? { requestId: `req-${rng.int(1, 999)}` } : {}),
    ...(rng.chance(0.25)
      ? { resources: [rng.pick(RESOURCES), ...(rng.chance(0.5) ? [rng.pick(RESOURCES)] : [])] }
      : {}),
    ...(rng.chance(0.15) ? { expirationTime: `2100-01-0${rng.int(1, 9)}T00:00:00Z` } : {}),
    ...(rng.chance(0.1) ? { notBefore: ts } : {}),
  };
  return fields;
}

type MutKind = "byte" | "drop" | "dup" | "swap" | "cr" | "unicode" | "truncate";
const MUT: ReadonlyArray<MutKind> = ["byte", "drop", "dup", "swap", "cr", "unicode", "truncate"];
const MUTATORS: Record<MutKind, (rng: Rng, text: string) => string> = {
  byte: (rng, text) => {
    const i = rng.int(0, text.length - 1);
    return text.slice(0, i) + String.fromCodePoint(rng.int(33, 126)) + text.slice(i + 1);
  },
  drop: (rng, text) => {
    const lines = text.split("\n");
    return lines.filter((_, i) => i !== rng.int(0, lines.length - 1)).join("\n");
  },
  dup: (rng, text) => {
    const lines = text.split("\n");
    const i = rng.int(0, lines.length - 1);
    return [...lines.slice(0, i), lines[i] ?? "", ...lines.slice(i)].join("\n");
  },
  swap: (_rng, text) => text.split("\n").toReversed().join("\n"),
  cr: (_rng, text) => text.replace("\n", "\r\n"),
  unicode: (_rng, text) => `${text}\nURI: https://exämple.com/💥`,
  truncate: (_rng, text) => text.slice(0, Math.max(1, Math.floor(text.length / 2))),
};
function mutate(rng: Rng, text: string): string {
  const kind = rng.pick(MUT);
  return MUTATORS[kind](rng, text);
}

function randomBadFields(rng: Rng): MessageFields {
  const base = randomFields(rng, "evm");
  const which = rng.pick(["domain", "uri", "chainId", "address", "nonce", "issuedAt"] as const);
  const bad: Record<string, string> = {
    domain: "!!bad domain..",
    uri: "not a uri:::\\",
    chainId: rng.pick(["abc", "0", "-1", "1.5", ""]),
    address: rng.pick(["0xzz", "not-an-address", ""]),
    nonce: rng.pick(["a b", "", "x".repeat(40)]),
    issuedAt: rng.pick(["not-a-date", "2020-13-40T99:99:99Z", ""]),
  };
  return { ...base, [which]: bad[which] };
}

export function generate(seed: number, count: number): DiffRecord[] {
  const rng = makeRng(seed);
  const records: DiffRecord[] = [];
  let seq = 0;
  const push = (r: Omit<DiffRecord, "seq">) => {
    records.push({ seq: seq++, ...r });
  };
  const em = evm();
  const sm = svm();

  while (records.length < count) {
    const ns = rng.chance(0.5) ? "evm" : "svm";
    const fields = randomFields(rng, ns);
    push({
      op: "create",
      fields,
      outcome: out(() => {
        createMessage(fields);
        return "ok";
      }),
    });
    if (rng.chance(0.15)) {
      const bf = randomBadFields(rng);
      push({
        op: "create",
        fields: bf,
        outcome: out(() => {
          createMessage(bf);
          return "ok";
        }),
      });
    }

    const namespace: Namespace = ns === "evm" ? em : sm;
    const formatOp = ns === "evm" ? "format_eip4361" : "format_siws";
    const parseOp = ns === "evm" ? "parse_eip4361" : "parse_siws";

    let text: string | undefined;
    push({
      op: formatOp,
      fields,
      outcome: out(() => {
        const m = createMessage(fields);
        text = namespace.format(m);
        return text;
      }),
    });
    push({
      op: `account_${ns}` as const,
      fields,
      outcome: out(() => namespace.account(createMessage(fields)).id),
    });

    if (text !== undefined && rng.chance(0.8)) {
      const t = text;
      push({
        op: parseOp,
        text: t,
        outcome: out(() => {
          const m = namespace.parse(new TextEncoder().encode(t));
          return namespace.format(m);
        }),
      });
      // mutate and parse again
      const mutated = mutate(rng, t);
      push({
        op: parseOp,
        text: mutated,
        outcome: out(() => {
          const m = namespace.parse(new TextEncoder().encode(mutated));
          return namespace.format(m);
        }),
      });
    }
  }
  return records.slice(0, count);
}

export function parseArgs(argv: ReadonlyArray<string>): {
  seed: number;
  count: number;
  outPath: string;
} {
  let seed = DEFAULT_SEED;
  let count = DEFAULT_COUNT;
  let outPath = DEFAULT_OUT;
  for (let i = 0; i < argv.length; i += 2) {
    const arg = argv[i];
    const value = argv[i + 1];
    if (value === undefined) {
      throw new Error(`${String(arg)} requires a value`);
    }
    if (arg === "--seed") {
      seed = Number(value);
    } else if (arg === "--count") {
      count = Number(value);
    } else if (arg === "--out") {
      outPath = value;
    } else {
      throw new Error(`unknown argument: ${String(arg)}`);
    }
  }
  return { seed, count, outPath };
}

if (import.meta.main) {
  const { seed, count, outPath } = parseArgs(process.argv.slice(2));
  const records = generate(seed, count);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify({ seed, records }, null, 1));
  console.log(`wrote ${records.length} records (seed ${seed}) → ${outPath}`);
}
