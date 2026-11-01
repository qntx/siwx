//! Shared pieces of the CAIP-122 text layouts (eip4361 and SIWS): the
//! preamble infix/suffix and the optional trailing tags in fixed ABNF order.

import { syntaxError } from "./error.ts";
import type { MessageFields } from "./message.ts";

export const MID = " wants you to sign in with your ";
export const SUFFIX = " account:";

export type OptionalTail = Pick<
  MessageFields,
  "expirationTime" | "notBefore" | "requestId" | "resources"
>;

/**
 * Parse the optional trailing tags in fixed ABNF order: `Expiration Time`, `Not Before`, `Request
 * ID`, `Resources` (with `- ` items). Each may appear at most once and only in this order.
 */
export function optionalTags(lines: ReadonlyArray<string>, start: number): OptionalTail {
  let i = start;
  let resources: ReadonlyArray<string> | undefined;
  const take = (tag: string): string | undefined => {
    const line = lines[i];
    if (line !== undefined && line.startsWith(tag)) {
      i++;
      return line.slice(tag.length);
    }
    return undefined;
  };
  const expirationTime = take("Expiration Time: ");
  const notBefore = take("Not Before: ");
  const requestId = take("Request ID: ");
  if (lines[i] === "Resources:") {
    i++;
    const list: string[] = [];
    while (i < lines.length) {
      const r = lines[i] ?? "";
      if (r.startsWith("- ")) {
        list.push(r.slice(2));
        i++;
      } else if (r.startsWith("-")) {
        throw syntaxError("ResourceSyntax");
      } else {
        throw syntaxError("UnexpectedTrailing");
      }
    }
    resources = list;
  }
  if (i !== lines.length) {
    throw syntaxError("UnexpectedTrailing");
  }
  return { expirationTime, notBefore, requestId, resources };
}
