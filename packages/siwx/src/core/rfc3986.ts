//! RFC 3986 URI validation, matching Rust `iri-string` exactly:
//! `URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]`,
//! `authority = [ userinfo "@" ] host [ ":" port ]`, strict dec-octet
//! (no leading zeros), IPv6 / IPvFuture / pct-encoding.

const UNRESERVED = /[A-Za-z0-9._~-]/;
const SUB_DELIM = /[!$&'()*+,;=]/;
const HEX = /[0-9A-Fa-f]/;

function isScheme(s: string): boolean {
  if (s.length === 0 || !/[A-Za-z]/.test(s.charAt(0))) {
    return false;
  }
  for (const c of s) {
    if (!/[A-Za-z0-9+.-]/.test(c)) {
      return false;
    }
  }
  return true;
}

/** `(unreserved / pct-encoded / sub-delims / ":" / "@")*`, ASCII only. */
function everyPct(s: string, allowed: (c: string) => boolean): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (c === "%") {
      if (i + 2 >= s.length || !HEX.test(s.charAt(i + 1)) || !HEX.test(s.charAt(i + 2))) {
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

function isUserinfo(s: string): boolean {
  return everyPct(s, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":");
}

function isRegName(s: string): boolean {
  return everyPct(s, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c));
}

function isPcharString(s: string): boolean {
  return everyPct(s, (c) => UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":" || c === "@");
}

/** Dec-octet: 0-255, no leading zeros (RFC 3986 strict). */
function isDecOctet(s: string): boolean {
  if (s.length === 0 || s.length > 3) {
    return false;
  }
  if (s.length > 1 && s.startsWith("0")) {
    return false;
  }
  for (const c of s) {
    if (!/[0-9]/.test(c)) {
      return false;
    }
  }
  return Number(s) <= 255;
}

function isIPv4(s: string): boolean {
  const parts = s.split(".");
  return parts.length === 4 && parts.every(isDecOctet);
}

function isH16(s: string): boolean {
  return s.length > 0 && s.length <= 4 && s.split("").every((c) => HEX.test(c));
}

/**
 * Count h16-equivalent groups in one half of an IPv6 literal (an IPv4 tail counts as two groups and
 * must be last).
 */
function ipv6GroupCount(part: string): number {
  if (part === "") {
    return 0;
  }
  let n = 0;
  const groups = part.split(":");
  for (const g of groups) {
    if (g === "") {
      return -1;
    }
    if (g.includes(".")) {
      if (g !== groups.at(-1) || !isIPv4(g)) {
        return -1;
      }
      n += 2;
    } else if (isH16(g)) {
      n += 1;
    } else {
      return -1;
    }
  }
  return n;
}

/** IPv6address per RFC 3986, with optional IPv4 tail and `::` compression. */
function isIPv6(s: string): boolean {
  const halves = s.split("::");
  if (halves.length > 2) {
    return false;
  }
  if (halves.length === 1) {
    return ipv6GroupCount(halves[0] ?? "") === 8;
  }
  const hn = ipv6GroupCount(halves[0] ?? "");
  const tn = ipv6GroupCount(halves[1] ?? "");
  if (hn === -1 || tn === -1) {
    return false;
  }
  // "::" must stand for at least one 16-bit group.
  return hn + tn < 8;
}

function isIPvFuture(s: string): boolean {
  const m = /^[vV]([0-9A-Fa-f]+)\.(.*)$/.exec(s);
  if (m === null) {
    return false;
  }
  const tail = m[2] ?? "";
  if (tail.length === 0) {
    return false;
  }
  for (const c of tail) {
    if (!(UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":")) {
      return false;
    }
  }
  return true;
}

/** `host = IP-literal / IPv4address / reg-name` (first-match-wins). */
function isHost(s: string): boolean {
  if (s.startsWith("[")) {
    return s.endsWith("]") && (isIPv6(s.slice(1, -1)) || isIPvFuture(s.slice(1, -1)));
  }
  if (isIPv4(s)) {
    return true;
  }
  return isRegName(s);
}

/** `authority = [ userinfo "@" ] host [ ":" port ]`. */
function isAuthority(s: string): boolean {
  let rest = s;
  const at = rest.lastIndexOf("@");
  if (at !== -1) {
    if (rest.indexOf("@") !== at) {
      return false;
    } // raw '@' in userinfo
    if (!isUserinfo(rest.slice(0, at))) {
      return false;
    }
    rest = rest.slice(at + 1);
  }
  let host = rest;
  let port = "";
  if (rest.startsWith("[")) {
    const end = rest.indexOf("]");
    if (end === -1) {
      return false;
    }
    host = rest.slice(0, end + 1);
    const after = rest.slice(end + 1);
    if (after !== "") {
      if (!after.startsWith(":")) {
        return false;
      }
      port = after.slice(1);
    }
  } else {
    const colon = rest.lastIndexOf(":");
    if (colon !== -1) {
      host = rest.slice(0, colon);
      port = rest.slice(colon + 1);
      if (host.includes(":")) {
        return false;
      }
    }
  }
  if (port !== "" && !port.split("").every((c) => /[0-9]/.test(c))) {
    return false;
  }
  return isHost(host);
}

/** `path` characters: each segment is `*pchar`. */
function isPath(s: string): boolean {
  for (const seg of s.split("/")) {
    if (!isPcharString(seg)) {
      return false;
    }
  }
  return true;
}

/** `query` / `fragment`: `*( pchar / "/" / "?" )`. */
function isQueryOrFragment(s: string): boolean {
  return everyPct(
    s,
    (c) =>
      UNRESERVED.test(c) || SUB_DELIM.test(c) || c === ":" || c === "@" || c === "/" || c === "?",
  );
}

/** RFC 3986 `URI` (absolute, with scheme). */
function isUri(s: string): boolean {
  // `URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]`
  const hash = s.indexOf("#");
  if (hash !== -1 && s.includes("#", hash + 1)) {
    return false;
  }
  let rest = s;
  let fragment: string | undefined;
  if (hash !== -1) {
    fragment = rest.slice(hash + 1);
    rest = rest.slice(0, hash);
  }
  const q = rest.indexOf("?");
  let query: string | undefined;
  if (q !== -1) {
    query = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  const colon = rest.indexOf(":");
  if (colon === -1) {
    return false;
  }
  if (!isScheme(rest.slice(0, colon))) {
    return false;
  }
  let hier = rest.slice(colon + 1);
  if (hier.startsWith("//")) {
    hier = hier.slice(2);
    const slash = hier.indexOf("/");
    const authority = slash === -1 ? hier : hier.slice(0, slash);
    const path = slash === -1 ? "" : hier.slice(slash);
    if (!isAuthority(authority)) {
      return false;
    }
    if (!isPath(path)) {
      return false;
    }
  } else if (!isPath(hier)) {
    return false;
  }
  if (query !== undefined && !isQueryOrFragment(query)) {
    return false;
  }
  if (fragment !== undefined && !isQueryOrFragment(fragment)) {
    return false;
  }
  return true;
}

export { isScheme, isAuthority, isUri, isPcharString };
