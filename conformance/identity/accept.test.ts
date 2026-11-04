// The invitation accepted by a device against IDENTITY-FLOW-FIXTURES-01 F07
// (spec#3): the claim names the root and the device's self-registration
// are the fixtures' exact records.

import { claimForRootRecord, selfRegistrationRecord } from "@openlfcp/client";
import { fromHex, toHex } from "@openlfcp/core";
import { ABILITY, certificateChain } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { cert, chainAt, chainOf, contextOf, idOf, party, recordOf, wireCase } from "./corpus.js";

describe("F07: an invitation accepted by a device of DAVE (§7.2)", () => {
  test("the claim for the root, signed by INVITE, is flow.claim_for_root_dave", () => {
    const chain = chainOf(contextOf("flow.claim_for_root_dave"));
    const grantId = fromHex(wireCase("N1_invite_grant").inputs.record_id.hex);
    const grant = chain.state.grants.get(toHex(grantId));
    if (grant === undefined) throw new Error("no grant");
    // The claimed abilities: the grant's, invite/claim only when delegable (as acceptInvitation).
    const abilities = grant.abilities.filter(
      (a) => a !== ABILITY.INVITE_CLAIM || grant.delegable.includes(ABILITY.INVITE_CLAIM),
    );
    expect(abilities).toEqual([1n, 2n]);
    const bytes = claimForRootRecord(
      chain,
      party("INVITE"),
      grantId,
      party("DAVE").descriptor,
      abilities,
    );
    expect(toHex(bytes)).toBe(toHex(recordOf("flow.claim_for_root_dave")));
  });

  test("the self-registration of DEV_D is flow.self_register_dev_d, and DAVE then reads", () => {
    const chain = chainAt("flow.claim_for_root_dave");
    const bytes = selfRegistrationRecord(
      chain,
      party("DEV_D"),
      certificateChain([cert("CERT_D")], idOf("DAVE")),
    );
    expect(toHex(bytes)).toBe(toHex(recordOf("flow.self_register_dev_d")));
    expect(wireCase("flow.open_as_dave").expected.post_state.read).toBe("full");
  });
});
