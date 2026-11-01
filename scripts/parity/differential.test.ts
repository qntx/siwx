import { describe, expect, it } from "vite-plus/test";

import { generate, makeRng } from "./differential.ts";

describe("differential harness", () => {
  it("is deterministic per seed", () => {
    const a = generate(42, 50);
    const b = generate(42, 50);
    expect(a).toStrictEqual(b);
  });

  it("produces both ok and error outcomes", () => {
    const recs = generate(42, 200);
    expect(recs.some((r) => "ok" in r.outcome)).toBe(true);
    expect(recs.some((r) => "error" in r.outcome)).toBe(true);
    expect(new Set(recs.map((r) => r.op)).size).toBeGreaterThan(3);
  });

  it("rng is stable", () => {
    const r1 = makeRng(1);
    const r2 = makeRng(1);
    for (let i = 0; i < 10; i++) {
      expect(r1.float()).toBe(r2.float());
    }
  });
});
