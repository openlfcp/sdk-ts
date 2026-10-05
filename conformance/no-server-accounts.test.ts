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

// LFCP-022 items 14, 15: Control validation and transitions are pure; no
// clock, randomness, timers or I/O decide or record anything.
describe("pure Control Plane logic", () => {
  const PURE = [
    "packages/wire/src/transition.ts",
    "packages/wire/src/chain.ts",
    "packages/wire/src/capability.ts",
    "packages/wire/src/data-unit.ts",
    "packages/client/src/data-unit.ts",
  ];
  const IMPURE =
    /\b(Date|performance|Math\.random|getRandomValues|randomBytes|generateObjectId|setTimeout|setInterval|fetch|WebSocket|indexedDB|localStorage|process)\b/;

  it.each(PURE)("%s uses no clock, randomness, timer or I/O", (path) => {
    const code = readRepoText(path)
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|\/\*\*)/.test(line));
    expect(code.filter((line) => IMPURE.test(line))).toEqual([]);
  });
});

// LFCP-025 item 34: the Data Unit core knows no Data Profile. Plaintext
// comes in and goes out through the generic DataProfileCodec only.
describe("no profile semantics in the Data Unit core", () => {
  const CORE = [
    "packages/crypto/src/aead.ts",
    "packages/wire/src/data-unit.ts",
    "packages/client/src/data-unit.ts",
  ];
  it.each(CORE)("%s imports no Automerge, Task, Shared Objects or Obsidian code", (path) => {
    const imports = readRepoText(path)
      .split("\n")
      .filter((line) => /\bfrom\s+["']/.test(line) || /\bimport\(/.test(line));
    expect(imports.filter((line) => /automerge|task|shared-objects|obsidian/i.test(line))).toEqual(
      [],
    );
  });
});
