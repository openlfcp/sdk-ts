// LFCP-021, ALIGN-TS-3: derived abilities along the published Control
// Chain (LFCP-TEST-VECTORS-01 C0-C10 at the pinned spec commit), validated
// with the capability engine enforced. The expectations follow from the
// spec text, not from the vectors:
//
// - §17.1: the owner holds every standard ability implicitly, except 9
//   (owner/transfer-offer), which is reserved and confers nothing (§23.1);
// - C1 (§17.2): OWNER grants BOB data/read, data/write, snapshot/publish;
// - C2 (§17.2, §18): OWNER grants INVITE data/read, data/write,
//   invite/claim with claim_limit 1;
// - C3 (§18.1): INVITE's claim gives CAROL data/read, data/write and
//   consumes the one claim, so C2 confers no invite/claim any more; its
//   other abilities stay;
// - C4 (§23.3): ownership moves OWNER -> BOB. OWNER holds no grant, so it
//   keeps no authority; BOB holds everything as the owner;
// - C7 (§17.2): BOB (owner, no parent) grants CAROL data/read, data/write,
//   capability/grant, capability/revoke, delegable data/read and
//   capability/grant;
// - C8 (§17.2): CAROL, through C7, grants OWNER data/read and
//   capability/grant, delegable data/read;
// - C9 (§17.2): OWNER, through C8, grants INVITE data/read;
// - C10 (§17.3): CAROL revokes C9, which descends from C8, a grant CAROL
//   issued; C7 and C8 stay active.

import { fromHex, principalId, toHex } from "@openlfcp/core";
import { ABILITY_NAMES, abilitiesOf, isGrantActive, validateControlChain } from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import type { VectorSuite } from "../runner.js";
import { openSpec } from "../spec.mjs";

const spec = openSpec();
const suite = spec.readJson("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json") as VectorSuite;
const hex = (id: string, field: string): string => {
  const c = suite.cases.find((x) => x.id === id);
  const v = (c?.expected as Record<string, { hex?: string }> | undefined)?.[field]?.hex;
  if (v === undefined) throw new Error(`no ${id}.expected.${field}`);
  return v;
};

const PRINCIPALS = ["OWNER", "BOB", "INVITE", "CAROL"] as const;
const principal = (name: string) =>
  principalId(fromHex(hex(`principal_${name.toLowerCase()}`, "principal_id")));
const ALL = [...ABILITY_NAMES.values()].filter((a) => a !== "owner/transfer-offer");
const names = (codes: readonly bigint[]) => codes.map((c) => ABILITY_NAMES.get(c));

const AFTER_TRANSFER = {
  owner: "BOB",
  abilities: {
    OWNER: [],
    BOB: ALL,
    INVITE: ["data/read", "data/write"],
    CAROL: ["data/read", "data/write"],
  },
};
const CAROL_DELEGATOR = ["data/read", "data/write", "capability/grant", "capability/revoke"];
const AFTER_C8 = {
  owner: "BOB",
  abilities: {
    OWNER: ["data/read", "capability/grant"],
    BOB: ALL,
    INVITE: ["data/read", "data/write"],
    CAROL: CAROL_DELEGATOR,
  },
};
const MATRIX: Record<
  string,
  { owner: string; abilities: Record<(typeof PRINCIPALS)[number], string[]> }
> = {
  C3_invite_claim_carol: {
    owner: "OWNER",
    abilities: {
      OWNER: ALL,
      BOB: ["data/read", "data/write", "snapshot/publish"],
      INVITE: ["data/read", "data/write"],
      CAROL: ["data/read", "data/write"],
    },
  },
  C4_owner_transfer_commit: AFTER_TRANSFER,
  C5_route_update: AFTER_TRANSFER,
  C6_key_epoch_1: AFTER_TRANSFER,
  C7_grant_carol_delegator: {
    owner: "BOB",
    abilities: { ...AFTER_TRANSFER.abilities, CAROL: CAROL_DELEGATOR },
  },
  C8_grant_owner_delegated: AFTER_C8,
  C9_grant_invite_grandchild: AFTER_C8,
  C10_revoke_grandchild: AFTER_C8,
};

/** Whether the grant created by `id` is active at `head` (§17.2). */
const activeAt = (head: string, id: string): boolean => {
  if (result.kind !== "linear") throw new Error(result.kind);
  const state = result.stateAt(fromHex(hex(head, "record_id")));
  if (state === undefined) throw new Error(`${head} is not on the chain`);
  return isGrantActive(state, fromHex(hex(id, "record_id")));
};

const chain = suite.cases
  .filter((c) => c.type === "bytes" && c.kind === "control_record")
  .map((c) => fromHex(hex(c.id, "cose_sign1")));
const result = validateControlChain(chain);

describe(`derived authority along C0-C6 at ${spec.lock.tag}`, () => {
  it("the published chain validates with authority enforced", () => {
    expect(result.kind).toBe("linear");
  });

  for (const [head, expected] of Object.entries(MATRIX)) {
    it(`at ${head}: owner ${expected.owner}; abilities as §17/§18/§23 imply`, () => {
      if (result.kind !== "linear") throw new Error(result.kind);
      const state = result.stateAt(fromHex(hex(head, "record_id")));
      if (state === undefined) throw new Error(`${head} is not on the chain`);
      expect(toHex(state.owner.principalId)).toBe(toHex(principal(expected.owner)));
      for (const p of PRINCIPALS)
        expect([p, names(abilitiesOf(state, principal(p)))]).toEqual([p, expected.abilities[p]]);
      // C2's invitation grant has used its one claim (§18.1).
      expect(state.grants.get(hex("C2_invite_grant", "record_id"))?.claimsUsed).toBe(1n);
    });
  }

  it("C10 revokes C9 only; the grants it descends from stay active (§17.2, §17.3)", () => {
    expect(activeAt("C9_grant_invite_grandchild", "C9_grant_invite_grandchild")).toBe(true);
    expect(activeAt("C10_revoke_grandchild", "C9_grant_invite_grandchild")).toBe(false);
    expect(activeAt("C10_revoke_grandchild", "C8_grant_owner_delegated")).toBe(true);
    expect(activeAt("C10_revoke_grandchild", "C7_grant_carol_delegator")).toBe(true);
  });
});
