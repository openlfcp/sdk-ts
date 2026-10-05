// LFCP-021 item 19: no server account identifier takes part in LFCP
// authorization. Authority comes from the validated Control Chain and
// cryptographic Principal IDs only. This scans the authorization sources
// (a conformance test, since the portable packages may not read files).

import { describe, expect, it } from "vitest";
import { readRepoText } from "./spec.mjs";

const SOURCES = ["packages/wire/src/capability.ts", "packages/wire/src/chain.ts"];
// Identifiers a server-account shortcut would need.
const FORBIDDEN =
  /\b(account|accountId|user|userId|user_id|serverUser|username|login|session[A-Z]\w*|hosting\w*|isAuthorized)\b/i;

describe("no server-account authorization shortcut", () => {
  it.each(SOURCES)("%s names no account, user or hosting identity in code", (path) => {
    const code = readRepoText(path)
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|\/\*\*)/.test(line)); // doc comments may explain the rule
    const hits = code.filter((line) => FORBIDDEN.test(line));
    expect(hits).toEqual([]);
  });

  it("evaluates authority by Principal ID and Control state only", () => {
    const source = readRepoText("packages/wire/src/capability.ts");
    for (const fn of ["hasAbility", "abilitiesOf", "canDistributeKey", "authorizeControlRecord"]) {
      const signature =
        new RegExp(`export function ${fn}\\(([^)]*)\\)`, "s").exec(source)?.[1] ?? "";
      expect(signature, fn).not.toBe("");
      const types = [...signature.matchAll(/:\s*([A-Za-z]+)/g)].map((m) => m[1]);
      expect(
        types.every((t) =>
          ["ControlState", "PrincipalId", "bigint", "DataEpoch", "ControlRecord"].includes(
            t as string,
          ),
        ),
        `${fn}(${types})`,
      ).toBe(true);
    }
  });
});
