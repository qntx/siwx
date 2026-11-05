//! Wallet-side request-origin verification, mirroring Rust `check_origin`.

import { SiwxError } from "./error.ts";
import type { Message } from "./message.ts";
import { isHost, isScheme } from "./rfc3986.ts";

/** Wallet-side request-origin policy (ERC-4361 "Verifying the Request Origin"). */
export type OriginPolicy = {
  /** Schemes the wallet accepts; default `["https"]`. Compared case-insensitively. */
  readonly allowedSchemes?: ReadonlyArray<string> | undefined;
  /** Scheme assumed when the message has none; default `"https"`. */
  readonly defaultScheme?: string | undefined;
  /** Developer mode: scheme and host mismatches are warnings instead of rejections. Default false. */
  readonly developerMode?: boolean | undefined;
};

/** Stable finding names shared with the Rust implementation. */
export type OriginFindingCode =
  | "SchemeNotAllowed"
  | "SchemeMismatch"
  | "HostMismatch"
  | "PortMismatch";

export type OriginFinding = {
  readonly code: OriginFindingCode;
  readonly severity: "reject" | "warn";
};

type Endpoint = { scheme: string; host: string; port: string | undefined };

const DEFAULT_PORTS: Readonly<Record<string, string>> = { https: "443", http: "80" };

const invalidOrigin = (): SiwxError => new SiwxError({ code: "InvalidOrigin" });

const isDigits = (s: string): boolean => s !== "" && /^[0-9]+$/.test(s);

/** Splits `host [":" port]`; an IPv6 literal keeps its brackets. `undefined` when malformed. */
function splitHostPort(
  hostPort: string,
): { host: string; port: string | undefined; hasPort: boolean } | undefined {
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end === -1) {
      return undefined;
    }
    const after = hostPort.slice(end + 1);
    if (after === "") {
      return { host: hostPort, port: undefined, hasPort: false };
    }
    return after.startsWith(":")
      ? { host: hostPort.slice(0, end + 1), port: after.slice(1), hasPort: true }
      : undefined;
  }
  const colon = hostPort.lastIndexOf(":");
  return colon === -1
    ? { host: hostPort, port: undefined, hasPort: false }
    : { host: hostPort.slice(0, colon), port: hostPort.slice(colon + 1), hasPort: true };
}

/** `scheme "://" host [ ":" port ]` with nothing else. */
function parseOrigin(origin: string): Endpoint {
  const sep = origin.indexOf("://");
  if (sep === -1) {
    throw invalidOrigin();
  }
  const scheme = origin.slice(0, sep);
  const split = splitHostPort(origin.slice(sep + 3));
  if (
    !isScheme(scheme) ||
    split === undefined ||
    split.host === "" ||
    !isHost(split.host) ||
    (split.hasPort && !isDigits(split.port ?? ""))
  ) {
    throw invalidOrigin();
  }
  return { scheme: scheme.toLowerCase(), host: split.host, port: split.port };
}

/** Effective port: the explicit one, else the scheme default; leading zeros are insignificant. */
function effectivePort(port: string | undefined, scheme: string): string | undefined {
  if (port === undefined) {
    return DEFAULT_PORTS[scheme];
  }
  let start = 0;
  while (start < port.length - 1 && port.charAt(start) === "0") {
    start += 1;
  }
  return port.slice(start);
}

/**
 * Verify the request origin against the message `scheme` and `domain`.
 *
 * Findings are returned in order: `SchemeNotAllowed`, `SchemeMismatch`, `HostMismatch`,
 * `PortMismatch`; an empty array means the origin verifies. `PortMismatch` is always a warning.
 *
 * @param origin A serialized web origin: `scheme "://" host [ ":" port ]`.
 * @throws {SiwxError} `InvalidOrigin` when `origin` is not a serialized web origin.
 */
export function checkOrigin(
  message: Message,
  origin: string,
  policy: OriginPolicy = {},
): ReadonlyArray<OriginFinding> {
  const target = parseOrigin(origin);
  const allowed = (policy.allowedSchemes ?? ["https"]).map((s) => s.toLowerCase());
  const mismatch = policy.developerMode === true ? "warn" : "reject";
  const findings: OriginFinding[] = [];

  const scheme = (message.scheme ?? policy.defaultScheme ?? "https").toLowerCase();
  if (!allowed.includes(scheme)) {
    findings.push({ code: "SchemeNotAllowed", severity: "reject" });
  }
  if (scheme !== target.scheme) {
    findings.push({ code: "SchemeMismatch", severity: mismatch });
  }

  const split = splitHostPort(message.domain);
  const host = split?.host ?? "";
  if (host.toLowerCase() !== target.host.toLowerCase()) {
    findings.push({ code: "HostMismatch", severity: mismatch });
  }

  const domainPort = effectivePort(split?.port === "" ? undefined : split?.port, scheme);
  const originPort = effectivePort(target.port, target.scheme);
  if (domainPort !== originPort) {
    findings.push({ code: "PortMismatch", severity: "warn" });
  }
  return findings;
}
