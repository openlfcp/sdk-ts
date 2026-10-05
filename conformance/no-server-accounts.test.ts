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

// LFCP-024: deterministic HPKE sealing is test-only. The SDK's HPKE module
// never replaces the KEM's ephemeral key generation, and nothing in the
// packages reaches the conformance-only raw-skE wrapper.
describe("no deterministic HPKE in the SDK", () => {
  it("packages/crypto/src/hpke.ts never overrides GenerateKeyPair or takes an ephemeral key", () => {
    const code = readRepoText("packages/crypto/src/hpke.ts")
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|\/\*\*)/.test(line));
    expect(
      code.filter((line) => /GenerateKeyPair|DeriveKeyPair|skE|ikmE|ephemeral/.test(line)),
    ).toEqual([]);
  });

  it.each([
    "packages/wire/src/key-package.ts",
    "packages/crypto/src/hpke.ts",
    "packages/crypto/src/index.ts",
    "packages/wire/src/index.ts",
  ])("%s does not import the conformance raw-skE wrapper", (path) => {
    expect(readRepoText(path)).not.toMatch(/hpke-raw-ske|conformance\//);
  });
});
