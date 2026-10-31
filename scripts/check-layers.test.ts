import { describe, expect, test } from "vite-plus/test";

import { checkLayers, crateFromManifest } from "./check-layers.ts";
import type { CrateInfo } from "./check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers", () => {
  test("accepts the allowed edges", () => {
    const crates = [crate("siwx", []), crate("siwx-cli", ["siwx"])];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("siwx", ["siwx-cli"]), crate("siwx-cli", ["siwx"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["siwx: must not depend on siwx-cli"]);
  });

  test("rejects a siwx edge hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "siwx" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { "siwx-cli": { path: "../siwx-cli" } } } },
      },
      "siwx",
    );
    expect(checkLayers([info])).toStrictEqual(["siwx: must not depend on siwx-cli"]);
  });

  test("rejects a published crate depending on an unpublished crate", () => {
    const crates = [crate("siwx", [], false), crate("siwx-cli", ["siwx"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["siwx-cli: published crate must not depend on siwx"]);
  });

  test("rejects an unknown siwx* crate", () => {
    const errors = checkLayers([crate("siwx-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "siwx-mystery"']);
  });

  test("ignores third-party dependencies", () => {
    const crates = [
      crate("siwx", ["crc", "thiserror"]),
      crate("siwx-cli", ["siwx", "clap", "minicbor"]),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });
});
