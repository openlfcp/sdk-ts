// LFCP-021: derived abilities along the published Control Chain
// (LFCP-TEST-VECTORS-01 C0-C6 at the pinned spec commit), validated with
// the capability engine enforced. The expectations follow from the spec
// text, not from the vectors:
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
//   keeps no authority; BOB holds everything as the owner.

import { fromHex, principalId, toHex } from "@openlfcp/core";
import { ABILITY_NAMES, abilitiesOf, validateControlChain } from "@openlfcp/wire";
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
});
