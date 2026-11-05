import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { SiwxError, checkOrigin, createMessage } from "../../src/index.ts";
import type { OriginFinding, OriginPolicy } from "../../src/index.ts";

type Case = {
  name: string;
  scheme: string | null;
  domain: string;
  origin: string;
  policy: OriginPolicy;
  findings: OriginFinding[] | null;
  error: string | null;
};

const { cases } = JSON.parse(
  readFileSync(new URL("../../../../vectors/origin/check.json", import.meta.url), "utf8"),
) as { cases: Case[] };

const message = (c: Case) =>
  createMessage({
    scheme: c.scheme ?? undefined,
    domain: c.domain,
    address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
    uri: "https://service.org/login",
    version: "1",
    chainId: "1",
    nonce: "12341234",
    issuedAt: "2022-03-17T12:45:13.610Z",
  });

describe("checkOrigin vectors", () => {
  it.each(cases)("$name", (c) => {
    if (c.error !== null) {
      expect(() => checkOrigin(message(c), c.origin, c.policy)).toThrow(SiwxError);
      expect(() => checkOrigin(message(c), c.origin, c.policy)).toThrow(
        expect.objectContaining({ code: c.error }),
      );
      return;
    }
    expect(checkOrigin(message(c), c.origin, c.policy)).toStrictEqual(c.findings);
  });
});
