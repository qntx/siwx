/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

type JsonObject = Record<string, unknown>;

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function escapeRegExp(text: string): string {
  return text.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

export type PackageEntry = { path: string; pkg: unknown };
export type CrateEntry = { path: string; manifest: unknown };

/**
 * Lockstep check: every published workspace package's `version` must equal
 * `[workspace.package].version`, every crate manifest must inherit it via `version.workspace`,
 * every internal `crates/` path dependency must pin `=<version>`, and the version string may appear
 * nowhere else in Cargo.toml (bumpp rewrites every occurrence). Private packages are ignored; the
 * private workspace root is not passed in and takes no part.
 */
export function checkVersion(
  packages: PackageEntry[],
  cargoToml: unknown,
  cargoText: string,
  crates: CrateEntry[],
): string[] {
  const errors: string[] = [];
  const workspace = asRecord(asRecord(cargoToml)["workspace"]);
  const { version: cargoVersion } = asRecord(workspace["package"]);

  if (typeof cargoVersion !== "string") {
    errors.push("Cargo.toml: missing string [workspace.package].version");
  }

  for (const { path, pkg } of packages) {
    const manifest = asRecord(pkg);
    if (manifest["private"] === true) {
      continue;
    }
    const { version } = manifest;
    if (typeof version !== "string") {
      errors.push(`${path}: missing string "version"`);
      continue;
    }
    if (typeof cargoVersion === "string" && version !== cargoVersion) {
      errors.push(`version mismatch: ${path} has ${version}, Cargo.toml has ${cargoVersion}`);
    }
  }

  for (const { path, manifest } of crates) {
    const crate = asRecord(asRecord(manifest)["package"]);
    const { version } = crate;
    if (isRecord(version) && version["workspace"] === true) {
      continue;
    }
    errors.push(`${path}: package version must be "version.workspace = true"`);
  }

  let internalDeps = 0;
  const dependencies = asRecord(workspace["dependencies"]);
  for (const [name, spec] of Object.entries(dependencies)) {
    const entry = asRecord(spec);
    const { path } = entry;
    if (typeof path !== "string" || !path.startsWith("crates/")) {
      continue;
    }
    internalDeps += 1;
    const expected = `=${typeof cargoVersion === "string" ? cargoVersion : ""}`;
    if (entry["version"] !== expected) {
      errors.push(
        `Cargo.toml: internal dependency "${name}" must use version "${expected}", got ${JSON.stringify(entry["version"])}`,
      );
    }
  }

  if (typeof cargoVersion === "string") {
    const occurrences =
      cargoText.match(new RegExp(`\\b${escapeRegExp(cargoVersion)}\\b`, "g"))?.length ?? 0;
    const expected = 1 + internalDeps;
    if (occurrences !== expected) {
      errors.push(
        `Cargo.toml: "${cargoVersion}" appears ${occurrences} times, expected ${expected} ([workspace.package] plus internal path dependencies)`,
      );
    }
  }

  return errors;
}

if (import.meta.main) {
  const packages: PackageEntry[] = readdirSync("packages", { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const path = join("packages", entry.name, "package.json");
      return { path, pkg: JSON.parse(readFileSync(path, "utf8")) as unknown };
    });
  const crates: CrateEntry[] = readdirSync("crates", { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const path = join("crates", entry.name, "Cargo.toml");
      return { path, manifest: Bun.TOML.parse(readFileSync(path, "utf8")) };
    });
  const cargoText = readFileSync("Cargo.toml", "utf8");
  const errors = checkVersion(packages, Bun.TOML.parse(cargoText), cargoText, crates);
  for (const error of errors) {
    console.error(`check-version: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
