import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
  pack: {
    dts: {},
    // ESM-only sugar flattens to a string; keep types/import/default for pack entries.
    exports: {
      customExports(exports) {
        for (const [key, value] of Object.entries(exports)) {
          if (typeof value === "string" && value.endsWith(".mjs")) {
            exports[key] = {
              types: value.replace(/\.mjs$/, ".d.mts"),
              import: value,
              default: value,
            };
          }
        }
        return exports;
      },
    },
    entry: {
      index: "src/index.ts",
    },
  },
});

export default config;
