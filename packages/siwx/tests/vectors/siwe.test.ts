import { readFileSync } from "node:fs";

import { expect, it } from "vite-plus/test";

import { evm } from "../../src/evm/index.ts";
import { SiwxError, checkExpect, createMessage, eip4361 } from "../../src/index.ts";
import type { MessageFields } from "../../src/index.ts";

const json = (p: string) =>
  JSON.parse(readFileSync(new URL(`../../../../vectors/${p}`, import.meta.url), "utf8"));

function fieldsFromJson(v: Record<string, unknown>): MessageFields {
  return {
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
  };
}

const overrides = json("siwe-overrides.json") as Record<
  string,
  { error: { code: string; field?: string } }
>;
const overridesHit = new Set<string>();

// Parsing vectors: positives and warnings must parse, format round-trip,
// and validate under Evm; negatives must fail; overrides assert our pinned
// answers and may never be skipped.
const parsingCases = ["parsing_positive", "parsing_negative", "parsing_warnings"].flatMap((file) =>
  Object.entries(
    json(`siwe/parsing/${file}.json`) as Record<
      string,
      { message: string; fields: Record<string, unknown> }
    >,
  ).map(([name, c]) => ({ file, name, ...c })),
);

it.each(parsingCases)("$file.json#$name", ({ file, name, message, fields }) => {
  const ns = evm();
  const key = `${file}.json#${name}`;
  const override = overrides[key];
  if (override !== undefined) {
    overridesHit.add(key);
    let thrown: unknown;
    try {
      const msg = ns.parse(new TextEncoder().encode(message));
      ns.account(msg);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SiwxError);
    if (thrown instanceof SiwxError) {
      expect(thrown.code).toBe(override.error.code);
      const { info } = thrown;
      if (override.error.field !== undefined && "field" in info) {
        expect(info.field).toBe(override.error.field);
      }
    }
    return;
  }
  if (file === "parsing_negative") {
    expect(() => {
      const msg = ns.parse(new TextEncoder().encode(message));
      ns.account(msg);
    }).toThrow(SiwxError);
    return;
  }
  const msg = ns.parse(new TextEncoder().encode(message));
  const want = createMessage(fieldsFromJson(fields));
  expect({ ...msg }).toStrictEqual({ ...want });
  expect(eip4361.format("Ethereum", msg)).toBe(message);
  ns.account(msg);
});

// Objects vectors: {msg, error} — "none" means valid.
const objectCases = Object.entries(
  json("siwe/objects/message_objects.json") as Record<
    string,
    { msg: Record<string, unknown>; error: string }
  >,
).map(([name, c]) => ({ name, ...c }));

it.each(objectCases)("objects/message_objects.json#$name", ({ msg, error }) => {
  const ns = evm();
  const build = () => {
    const m = createMessage(fieldsFromJson(msg));
    ns.format(m); // exercises account() too
    return m;
  };
  if (error === "none") {
    const m = build();
    const text = ns.format(m);
    const parsed = ns.parse(new TextEncoder().encode(text));
    expect({ ...parsed }).toStrictEqual({ ...m });
  } else {
    expect(build).toThrow(SiwxError);
  }
});

const negativeObjects = Object.entries(
  json("siwe/objects/parsing_negative_objects.json") as Record<string, Record<string, unknown>>,
).map(([name, msg]) => ({ name, msg }));

it.each(negativeObjects)("objects/parsing_negative_objects.json#$name", ({ msg }) => {
  const build = () => {
    const m = createMessage(fieldsFromJson(msg));
    evm().account(m); // chain-specific rules live here
  };
  expect(build).toThrow(SiwxError);
});

// Grammar vectors — mirrors the Rust runner: the raw rule charset verdict
// AND the embedded message verdict must match the canonical `answer`.
const UNRESERVED = /[A-Za-z0-9._~-]/;
const SUB_DELIM = /[!$&'()*+,;=]/;
const HEXC = /[0-9A-Fa-f]/;
const pcharC = (c: string) => UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":" || c === "@";

function charsetOk(input: string, allowPct: boolean, allowed: (c: string) => boolean): boolean {
  for (let i = 0; i < input.length; i++) {
    const c = input.charAt(i);
    if (c === "%" && allowPct) {
      if (
        i + 2 >= input.length ||
        !HEXC.test(input.charAt(i + 1)) ||
        !HEXC.test(input.charAt(i + 2))
      ) {
        return false;
      }
      i += 2;
      continue;
    }
    if (!allowed(c)) {
      return false;
    }
  }
  return true;
}

const STATEMENT_CHARS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;= ",
);

function ruleOk(rule: string, input: string): boolean {
  switch (rule) {
    case "scheme":
      return /^[A-Za-z][A-Za-z0-9+.-]*$/.test(input);
    case "statement":
      return input.split("").every((c) => STATEMENT_CHARS.has(c));
    case "pct-encoded":
      return (
        input.length === 3 &&
        input.startsWith("%") &&
        HEXC.test(input[1] ?? "") &&
        HEXC.test(input[2] ?? "")
      );
    case "userinfo":
      return charsetOk(input, true, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":");
    case "IPvFuture": {
      if (!input.startsWith("v") && !input.startsWith("V")) {
        return false;
      }
      const dot = input.indexOf(".");
      if (dot === -1) {
        return false;
      }
      const hex = input.slice(1, dot);
      const tail = input.slice(dot + 1);
      return (
        hex.length > 0 &&
        charsetOk(hex, false, (c) => HEXC.test(c)) &&
        tail.length > 0 &&
        charsetOk(tail, false, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":")
      );
    }
    case "reg-name":
      return charsetOk(input, true, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c));
    case "IPv6address":
    case "IPv4address":
      return true; // structure covered by the URI embed
    case "segment-nz":
    case "segment":
    case "pchar":
      return input.length > 0 && charsetOk(input, true, pcharC);
    case "fragment":
    case "query":
      return charsetOk(input, true, (c) => pcharC(c) || c === "/" || c === "?");
    default:
      throw new Error(`unmapped grammar rule ${rule}`);
  }
}

const base = {
  domain: "service.org",
  address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
  uri: "uri:",
  version: "1",
  chainId: "1",
  nonce: "12341234",
  issuedAt: "2021-09-30T16:25:24.000Z",
};

function embed(rule: string, input: string): MessageFields | undefined {
  switch (rule) {
    case "scheme":
      return { ...base, scheme: input };
    case "statement":
      return { ...base, statement: input };
    case "userinfo":
      return { ...base, uri: `uri://${input}@h` };
    case "IPvFuture":
    case "IPv6address":
      return { ...base, uri: `uri://[${input}]` };
    case "reg-name":
    case "IPv4address":
      return { ...base, uri: `uri://${input}` };
    case "pct-encoded":
    case "segment-nz":
    case "segment":
    case "pchar":
      return { ...base, uri: `uri:${input}` };
    case "fragment":
      return { ...base, uri: `uri:#${input}` };
    case "query":
      return { ...base, uri: `uri:?${input}` };
    default:
      return undefined;
  }
}

function acceptsRule(rule: string, input: string): boolean {
  if (!ruleOk(rule, input)) {
    return false;
  }
  const f = embed(rule, input);
  if (f === undefined) {
    return true;
  }
  try {
    createMessage(f);
    return true;
  } catch {
    return false;
  }
}

const charCases = ["valid_chars", "invalid_chars"].flatMap((file) =>
  Object.entries(
    json(`siwe/grammar/${file}.json`) as Record<
      string,
      { rule: string; input: string; answer: boolean }
    >,
  ).map(([name, c]) => ({ file, name, ...c })),
);

it.each(charCases)("grammar $file.json#$name", ({ rule, input, answer }) => {
  expect(acceptsRule(rule, input)).toBe(answer);
});

// Message-level grammar files: {msg} object or bare message string.
const messageCases = (
  [
    ["valid_uris", true],
    ["invalid_uris", false],
    ["valid_resources", true],
    ["invalid_resources", false],
    ["valid_specification", true],
  ] as const
).flatMap(([file, expectOk]) =>
  Object.entries(
    json(`siwe/grammar/${file}.json`) as Record<string, { msg?: string } | string>,
  ).map(([name, c]) => ({ file, name, expectOk, msg: typeof c === "string" ? c : c.msg })),
);

it.each(messageCases)("grammar $file.json#$name", ({ file, name, expectOk, msg }) => {
  expect(msg).toBeDefined();
  const key = `${file}.json#${name}`;
  const override = overrides[key];
  if (override !== undefined) {
    overridesHit.add(key);
    expect(() => eip4361.parse(msg!)).toThrow(SiwxError);
    return;
  }
  if (expectOk) {
    const parsed = eip4361.parse(msg!);
    expect(eip4361.format(parsed.label, parsed.message)).toBe(msg);
  } else {
    expect(() => eip4361.parse(msg!)).toThrow(SiwxError);
  }
});

// Verification vectors: format fields, parse, checkExpect with vector time
// and skew 0, verify. eip1271.json requires RPC — not run (Phase 5).
const hexToBytes = (s: string) => {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return b;
};

const verifyCases = ["verification_positive", "verification_negative"].flatMap((file) =>
  Object.entries(
    json(`siwe/verification/${file}.json`) as Record<
      string,
      Record<string, unknown> & { signature: string; time?: string }
    >,
  ).map(([name, c]) => ({ file, name, valid: file === "verification_positive", ...c })),
);

it.each(verifyCases)("verify $file#$name", async ({ valid, signature, time, ...fieldsJson }) => {
  const ns = evm();
  const fields = fieldsFromJson(fieldsJson);
  const expect_ = {
    domain: fields.domain,
    nonce: fields.nonce,
    time: new Date(time ?? fields.issuedAt),
    skewSeconds: 0,
  };
  let text: string;
  try {
    text = ns.format(createMessage(fields));
  } catch (error) {
    if (valid) {
      throw error;
    }
    return; // construction failure counts as expected negative
  }
  const signed = new TextEncoder().encode(text);
  const p = (async () => {
    const msg = ns.parse(signed);
    checkExpect(msg, expect_);
    await ns.verify(msg, signed, hexToBytes(signature));
  })();
  const error = await p.then(
    () => null,
    (error: unknown) => error,
  );
  expect(error instanceof SiwxError).toBe(!valid);
});

it("every override was exercised", () => {
  for (const k of Object.keys(overrides)) {
    expect(overridesHit.has(k)).toBe(true);
  }
});
