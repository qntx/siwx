import { builtinModules } from "node:module";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintPreset, merge } from "@qntx/oxlint";

// The library runs on Node, browsers, and Hermes: Node builtins must not be
// imported from src.
const platformNeutralImports = {
  paths: builtinModules.map((name) => ({
    name,
    message: "Node builtin — the library must stay platform-neutral",
  })),
  patterns: [
    {
      group: ["node:*"],
      message: "Node builtin — the library must stay platform-neutral",
    },
  ],
};

const config: UserConfig = defineConfig({
  defaultPackage: {
    pack: "./packages/siwx",
  },
  staged: { "*": "vp check --fix" },
  fmt: {
    ...fmt,
    ignorePatterns: [
      ...fmt.ignorePatterns,
      "target/**",
      "bun.lock",
      // TOML is owned by taplo (.taplo.toml, align_entries); shared vectors
      // stay byte-frozen.
      "**/*.toml",
      "vectors/**",
      "fuzz/**",
    ],
  },
  lint: merge(lintPreset, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    ignorePatterns: ["target/**"],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
      // oxfmt canonicalizes hex digits to lowercase; this rule demands uppercase, so fmt always wins.
      "unicorn/number-literal-case": "off",
    },
    overrides: [
      {
        files: ["scripts/**"],
        rules: {
          // Maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        // Data-driven vector runners: conditionals express the vector's own
        // verdict; expect-inside-conditional and it.each-less loops are the
        // natural shape for per-case assertions.
        files: ["packages/siwx/tests/**"],
        rules: {
          // Verdict branching and conditional assertions mirror the vector shape.
          "vitest/no-conditional-in-test": "off",
          "vitest/no-conditional-expect": "off",
        },
      },
      {
        // Bitwise ops are confined to the crypto byte twiddling in evm/.
        files: ["packages/siwx/src/evm/**"],
        rules: { "eslint/no-bitwise": "off" },
      },
      {
        files: ["packages/*/src/**"],
        rules: {
          // Hermes V1 (what React Native ships) has no ES2023 immutable array
          // methods, so the library must sort/reverse copies in place.
          "unicorn/no-array-sort": "off",
          "unicorn/no-array-reverse": "off",
          // @types/node is in the program via tests and scripts, so Node-only
          // globals would typecheck silently; browser-only globals are equally
          // absent on Hermes. Both sets are banned — library code must use
          // globalThis lookups instead.
          "eslint/no-restricted-globals": [
            "error",
            { name: "Buffer", message: "Node-only global — use Uint8Array" },
            { name: "process", message: "Node-only global — not available in browsers or Hermes" },
            { name: "global", message: "Node-only global — use globalThis" },
            { name: "require", message: "CJS-only — use import" },
            { name: "module", message: "CJS-only global" },
            { name: "__dirname", message: "CJS-only global" },
            { name: "__filename", message: "CJS-only global" },
            { name: "setImmediate", message: "Node-only global — use setTimeout" },
            { name: "clearImmediate", message: "Node-only global — use clearTimeout" },
            { name: "window", message: "browser-only global — use globalThis" },
            { name: "document", message: "browser-only global — use globalThis" },
            { name: "navigator", message: "browser-only global — use globalThis" },
            { name: "location", message: "browser-only global — use globalThis" },
            { name: "localStorage", message: "browser-only global — inject a store" },
            { name: "sessionStorage", message: "browser-only global — inject a store" },
          ],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      {
        // Overrides replace a rule per override — this must come after the
        // generic packages/*/src/** block so core cannot import chain modules.
        files: ["packages/siwx/src/core/**"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: [
                ...platformNeutralImports.paths,
                { name: "../evm/index.ts", message: "core must not import chain modules" },
              ],
              patterns: [
                ...platformNeutralImports.patterns,
                { group: ["../evm/**"], message: "core must not import chain modules" },
              ],
            },
          ],
        },
      },
    ],
  }),
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
});

export default config;
