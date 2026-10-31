/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

export type CrateInfo = {
  name: string;
  publish: boolean;
  deps: string[];
};

type JsonObject = Record<string, unknown>;

// Allowed internal dependency edges. `siwx` is the leaf library crate; the CLI
// sits on top of it.
const ALLOWED: Record<string, string[]> = {
  siwx: [],
  "siwx-cli": ["siwx"],
};

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function depNames(section: unknown): string[] {
  const names: string[] = [];
  for (const [key, spec] of Object.entries(asRecord(section))) {
    const renamed = asRecord(spec)["package"];
    names.push(typeof renamed === "string" ? renamed : key);
  }
  return names;
}

/**
 * Builds a CrateInfo from a parsed Cargo.toml. Normal deps include `[dependencies]` plus every
 * `[target.<cfg>.dependencies]` table so a leaf crate cannot smuggle a dependency in through a
 * target section.
 */
export function crateFromManifest(manifest: unknown, fallbackName: string): CrateInfo {
  const root = asRecord(manifest);
  const pkg = asRecord(root["package"]);
  const deps = depNames(root["dependencies"]);
  for (const target of Object.values(asRecord(root["target"]))) {
    deps.push(...depNames(asRecord(target)["dependencies"]));
  }
  return {
    name: typeof pkg["name"] === "string" ? pkg["name"] : fallbackName,
    publish: pkg["publish"] !== false,
    deps,
  };
}

export function checkLayers(crates: CrateInfo[]): string[] {
  const errors: string[] = [];
  const byName = new Map<string, CrateInfo>();

  for (const crate of crates) {
    if (crate.name.startsWith("siwx") && !(crate.name in ALLOWED)) {
      errors.push(`unknown crate "${crate.name}"`);
    }
    byName.set(crate.name, crate);
  }

  for (const crate of crates) {
    const allowed = ALLOWED[crate.name] ?? [];
    for (const dep of crate.deps) {
      if (!dep.startsWith("siwx")) {
        continue;
      }
      if (!(dep in ALLOWED)) {
        errors.push(`${crate.name}: unknown internal dependency "${dep}"`);
        continue;
      }
      if (!allowed.includes(dep)) {
        errors.push(`${crate.name}: must not depend on ${dep}`);
      }
      if (crate.publish && byName.get(dep)?.publish === false) {
        errors.push(`${crate.name}: published crate must not depend on ${dep}`);
      }
    }
  }

  return errors;
}

if (import.meta.main) {
  const crates: CrateInfo[] = [];
  for (const dir of readdirSync("crates", { withFileTypes: true })) {
    if (!dir.isDirectory()) {
      continue;
    }
    const manifestPath = join("crates", dir.name, "Cargo.toml");
    let manifest: string;
    try {
      manifest = readFileSync(manifestPath, "utf8");
    } catch {
      continue;
    }
    crates.push(crateFromManifest(Bun.TOML.parse(manifest), dir.name));
  }
  const errors = checkLayers(crates);
  for (const error of errors) {
    console.error(`check-layers: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
