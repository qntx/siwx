/// <reference types="node" />
/**
 * Seeded cross-language differential harness. TypeScript generates records: random valid
 * MessageFields → createMessage/format outcomes; mutated texts → parse outcomes; account()
 * outcomes. The Rust replay test (`crates/siwx/tests/differential.rs`, driven by `bun run
 * test:parity`) asserts identical outcomes for every record.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { parseAccountId } from "../../packages/siwx/src/core/account.ts";
import { checkExpect } from "../../packages/siwx/src/core/expect.ts";
import type { Namespace } from "../../packages/siwx/src/core/namespace.ts";
import { parseTimestamp } from "../../packages/siwx/src/core/timestamp.ts";
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
    | "timestamp"
    | "account_id"
    | "expect"
    | "format_eip4361"
    | "format_siws"
    | "parse_eip4361"
    | "parse_siws"
    | "account_evm"
    | "account_svm";
  fields?: MessageFields;
  text?: string;
  lexeme?: string;
  id?: string;
  expect?: {
    domain: string;
    nonce: string;
    scheme?: string;
    uri?: string;
    chainId?: string;
    requestId?: string;
    timeMs?: number;
    skewSeconds?: number;
    maxAgeSeconds?: number;
  };
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

const ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@%";
const UNICODE = "é中💥́😀";
const IPV6 = [
  "[::1]",
  "[2001:db8::ff00:42:8329]",
  "[::ffff:192.0.2.1]",
  "[v7.aB-c]",
  "[fe80::a:b:c:d:e:f%eth0]",
];

function randChars(rng: Rng, alphabet: string, min: number, max: number): string {
  // Iterate code points so surrogate pairs stay intact (serde rejects lone surrogates).
  const chars: string[] = [];
  for (const c of alphabet) {
    chars.push(c);
  }
  const n = rng.int(min, max);
  let out = "";
  for (let i = 0; i < n; i += 1) {
    out += chars[rng.int(0, chars.length - 1)];
  }
  return out;
}

function randomAuthority(rng: Rng): string {
  const kind = rng.int(0, 9);
  switch (kind) {
    case 0:
      return `0${rng.int(0, 9)}${rng.int(0, 9)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(0, 255)}`;
    case 1:
      return `${rng.int(0, 999)}.${rng.int(0, 999)}.${rng.int(0, 999)}.${rng.int(0, 999)}`;
    case 2:
      return rng.pick(IPV6);
    case 3:
      return `${randChars(rng, PCHAR, 0, 8)}%${rng.chance(0.5) ? "zz" : "20"}${randChars(rng, ASCII, 0, 4)}`;
    case 4:
      return `${randChars(rng, ASCII, 1, 8)}:${randChars(rng, ASCII, 0, 8)}@${rng.pick(DOMAINS)}`;
    case 5:
      return `${rng.pick(DOMAINS)}:${rng.pick(["0", "80", "443", "65535", "99999", "abc", ""])}`;
    case 6:
      return "";
    case 7:
      return randChars(rng, "abcdefghijklmnopqrstuvwxyz-._~", 0, 16);
    default:
      return rng.pick(DOMAINS);
  }
}

function randomUri(rng: Rng): string {
  const scheme = rng.pick([
    "https",
    "http",
    "ftp",
    "mailto",
    "ipfs",
    "did:pkh",
    "urn",
    "x",
    "1bad",
    "",
  ]);
  const auth = rng.chance(0.7) ? `//${randomAuthority(rng)}` : "";
  const path = rng.chance(0.8) ? `/${randChars(rng, `${PCHAR}/?&=#`, 0, 24)}` : "";
  const q = rng.chance(0.25) ? `?${randChars(rng, `${PCHAR}/?=&%`, 0, 16)}` : "";
  const f = rng.chance(0.2) ? `#${randChars(rng, PCHAR, 0, 10)}` : "";
  return `${scheme}${scheme === "" || scheme === "urn" ? ":" : ":"}${auth}${path}${q}${f}`;
}

function randomTimestampLexeme(rng: Rng): string {
  const y = rng.pick([
    "0000",
    "0001",
    "0050",
    "0099",
    "0100",
    "1900",
    "1969",
    "1970",
    "2000",
    "2024",
    "2100",
    "9999",
  ]);
  const mo = String(rng.int(0, 13)).padStart(2, "0");
  const day = String(rng.int(0, 32)).padStart(2, "0");
  const hh = String(rng.int(0, 24)).padStart(2, "0");
  const mm = String(rng.int(0, 60)).padStart(2, "0");
  const ss = rng.chance(0.06) ? "60" : String(rng.int(0, 60)).padStart(2, "0");
  const fracLen = rng.int(0, 12);
  const frac = fracLen === 0 ? "" : `.${randChars(rng, "0123456789", fracLen, fracLen)}`;
  const tz = rng.pick([
    "Z",
    "z",
    "Z",
    "+00:00",
    "-00:00",
    "+23:59",
    "-23:59",
    "+24:00",
    "+99:99",
    "-05:30",
    "+14:00",
    `+0${rng.int(0, 9)}:15`,
  ]);
  return `${y}-${mo}-${day}${rng.chance(0.08) ? "t" : "T"}${hh}:${mm}:${ss}${frac}${tz}`;
}

function randomEvmAddress(rng: Rng): string {
  if (rng.chance(0.15)) {
    return rng.chance(0.5)
      ? randChars(rng, "0123456789abcdef", 0, 41)
      : `0x${randChars(rng, "0123456789abcdefg", 38, 42)}`;
  }
  let hex = randChars(rng, "0123456789abcdef", 40, 40);
  if (rng.chance(0.6)) {
    hex = hex
      .split("")
      .map((c) => (rng.chance(0.5) ? c.toUpperCase() : c))
      .join("");
  }
  return `0x${hex}`;
}

function randomSolAddress(rng: Rng): string {
  if (rng.chance(0.25)) {
    return rng.pick([
      "4uQeVj5tqViY8sVz9WmVqA2JtZ7fYbA3pT9kJcWv3kE2t",
      "11111111111111111111111111111111",
      "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
      "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    ]);
  }
  return randChars(rng, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 30, 45);
}

function randomStatement(rng: Rng): string {
  if (rng.chance(0.15)) {
    return `URI: ${rng.pick(["https://x.example", "urn:x", ""])}`;
  }
  return randChars(rng, `${ASCII} ${UNICODE}`, 0, 48);
}

function randomNonce(rng: Rng): string {
  return randChars(rng, ASCII, rng.pick([0, 1, 7, 8, 12, 32, 64]), rng.pick([8, 16, 24, 48, 96]));
}

function randomChainId(rng: Rng, ns: "evm" | "svm"): string {
  return ns === "evm"
    ? rng.pick([
        "1",
        "137",
        "31337",
        "0",
        "-1",
        "abc",
        "0x1",
        "eip155:5",
        "99999999999999999999",
        "",
      ])
    : rng.pick([
        "mainnet",
        "devnet",
        "testnet",
        "solana:testnet",
        "1",
        "unknown-cluster",
        "MAINNET",
        "",
      ]);
}
const SCHEMES = ["https", "http", "myapp"];
const EV_CHAINS = ["1", "137", "31337", "0x1", "eip155:5"];
const SV_CHAINS = ["mainnet", "devnet", "solana:testnet", "1", "unknown-cluster"];
const RESOURCES = ["https://docs.example.com/x", "mailto:a@b.c", "ftp://r.example/f", "ipfs://Qma"];

const GOOD_EVM = [
  "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "AE9aA90F1a627c7a20783AF9e8747fCFEDEFAd03",
  "00401b0f059b5af9f71a43263f2fc17422b6b8f8",
];
const GOOD_SVM = [
  "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
  "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
  "So11111111111111111111111111111111111111112",
];

function randomFields(rng: Rng, ns: "evm" | "svm"): MessageFields {
  const wild = rng.chance(0.35);
  const address =
    ns === "evm"
      ? wild
        ? randomEvmAddress(rng)
        : `0x${rng.pick(GOOD_EVM)}`
      : wild
        ? randomSolAddress(rng)
        : rng.pick(GOOD_SVM);
  const ts = wild
    ? randomTimestampLexeme(rng)
    : `20${rng.int(20, 26)}-${String(rng.int(1, 12)).padStart(2, "0")}-${String(rng.int(1, 28)).padStart(2, "0")}T${String(rng.int(0, 23)).padStart(2, "0")}:${String(rng.int(0, 59)).padStart(2, "0")}:${String(rng.int(0, 59)).padStart(2, "0")}.${String(rng.int(0, 999)).padStart(3, "0")}Z`;
  const fields: MessageFields = {
    domain: wild ? randomAuthority(rng) : rng.pick(DOMAINS),
    address,
    uri: wild ? randomUri(rng) : `https://${rng.pick(DOMAINS)}/login/${rng.int(1, 99)}`,
    version: "1",
    chainId: wild
      ? randomChainId(rng, ns)
      : ns === "evm"
        ? rng.pick(EV_CHAINS)
        : rng.pick(SV_CHAINS),
    nonce: wild ? randomNonce(rng) : `${rng.int(10000000, 99999999)}x`,
    issuedAt: ts,
    ...(rng.chance(0.4)
      ? { statement: wild ? randomStatement(rng) : `stmt-${rng.int(1, 999)} multi word` }
      : {}),
    ...(ns === "evm" && rng.chance(0.3) ? { scheme: rng.pick(SCHEMES) } : {}),
    ...(rng.chance(0.2)
      ? {
          requestId: wild ? randChars(rng, `${ASCII} ${UNICODE}`, 0, 32) : `req-${rng.int(1, 999)}`,
        }
      : {}),
    ...(rng.chance(0.25)
      ? { resources: [rng.pick(RESOURCES), ...(rng.chance(0.5) ? [randomUri(rng)] : [])] }
      : {}),
    ...(rng.chance(0.15)
      ? {
          expirationTime: wild ? randomTimestampLexeme(rng) : `2100-01-0${rng.int(1, 9)}T00:00:00Z`,
        }
      : {}),
    ...(rng.chance(0.1) ? { notBefore: ts } : {}),
  };
  return fields;
}

type MutKind = "byte" | "drop" | "dup" | "swap" | "cr" | "unicode" | "truncate";
const MUT: ReadonlyArray<MutKind> = ["byte", "drop", "dup", "swap", "cr", "unicode", "truncate"];
const MUTATORS: Record<MutKind, (rng: Rng, text: string) => string> = {
  byte: (rng, text) => {
    const chars: string[] = [];
    for (const c of text) {
      chars.push(c);
    }
    const i = rng.int(0, chars.length - 1);
    chars[i] = String.fromCodePoint(rng.int(33, 126));
    return chars.join("");
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
  truncate: (_rng, text) => {
    const chars: string[] = [];
    for (const c of text) {
      chars.push(c);
    }
    return chars.slice(0, Math.max(1, Math.floor(chars.length / 2))).join("");
  },
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
    if (rng.chance(0.12)) {
      const lexeme = randomTimestampLexeme(rng);
      push({
        op: "timestamp",
        lexeme,
        outcome: out(() => {
          const t = parseTimestamp(lexeme);
          return t === undefined ? "invalid" : `${t.epochMs}`;
        }),
      });
      continue;
    }
    if (rng.chance(0.12)) {
      const id = `${rng.pick(["eip155", "solana", "bip122", "cosmos", "bad ns", ""])}:${randChars(rng, `${ASCII}-._~`, 0, 8)}:${rng.chance(0.5) ? randomEvmAddress(rng) : randomSolAddress(rng)}${rng.chance(0.1) ? ":extra" : ""}`;
      push({
        op: "account_id",
        id,
        outcome: out(() => parseAccountId(id).id),
      });
      continue;
    }
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

    if (rng.chance(0.25)) {
      const e = {
        domain: rng.chance(0.7) ? fields.domain : `other-${rng.int(1, 9)}.example`,
        nonce: rng.chance(0.7) ? fields.nonce : `nonce-${rng.int(1, 9)}`,
        ...(rng.chance(0.3) ? { uri: rng.chance(0.7) ? fields.uri : "https://other.example" } : {}),
        ...(rng.chance(0.3) ? { chainId: rng.chance(0.7) ? fields.chainId : "999" } : {}),
        ...(rng.chance(0.2)
          ? { requestId: rng.chance(0.7) ? (fields.requestId ?? "none") : "other" }
          : {}),
        ...(rng.chance(0.6)
          ? { timeMs: new Date(`20${rng.int(20, 26)}-0${rng.int(1, 9)}-15T12:00:00Z`).getTime() }
          : {}),
        ...(rng.chance(0.5) ? { skewSeconds: rng.int(0, 600) } : {}),
        ...(rng.chance(0.4) ? { maxAgeSeconds: rng.int(0, 86400) } : {}),
      };
      push({
        op: "expect",
        fields,
        expect: e,
        outcome: out(() => {
          const m = createMessage(fields);
          checkExpect(m, {
            domain: e.domain,
            nonce: e.nonce,
            ...(e.uri === undefined ? {} : { uri: e.uri }),
            ...(e.chainId === undefined ? {} : { chainId: e.chainId }),
            ...(e.requestId === undefined ? {} : { requestId: e.requestId }),
            ...(e.timeMs === undefined ? {} : { time: new Date(e.timeMs) }),
            ...(e.skewSeconds === undefined ? {} : { skewSeconds: e.skewSeconds }),
            ...(e.maxAgeSeconds === undefined ? {} : { maxAgeSeconds: e.maxAgeSeconds }),
          });
          return "ok";
        }),
      });
    }

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
