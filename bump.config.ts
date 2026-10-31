import { execFileSync } from "node:child_process";

import { defineConfig } from "bumpp";

// npm package and Cargo workspace versions are lockstep; bumpp rewrites every
// `0.x.y` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and the `siwx = "=x.y.z"` dep.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["packages/siwx/package.json", "Cargo.toml"],
  // The fuzz crate is its own workspace with a path dependency on siwx, so
  // its lockfile records the siwx version too. A string `execute` is not run
  // through a shell, so the two updates run as separate processes.
  execute: () => {
    for (const manifest of ["Cargo.toml", "fuzz/Cargo.toml"]) {
      execFileSync("cargo", ["update", "--workspace", "--manifest-path", manifest], {
        stdio: "inherit",
      });
    }
  },
  // execute rewrites both lockfiles; commit them too.
  all: true,
  commit: true,
  // main is protected: release through a `release/v<version>` pull request
  // opened via `gh`. No tag is created; after the release PR merges, tag the
  // merge commit by hand (GITHUB_TOKEN tags do not trigger publish workflows).
  pr: true,
  push: true,
});

export default config;
