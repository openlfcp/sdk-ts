// The pairing approval against IDENTITY-FLOW-FIXTURES-01 F08, F10 and F13
// (spec#3): the records the phases build from the journaled payload are
// the fixtures' exact bytes, and the feasibility check of §5.3 step 4
// agrees with the validators on the 32-device limit and chain depth.

import {
  approvedGrantRecord,
  candidateEvidence,
  checkIssuance,
  consumeRecord,
  leafPayload,
  MASK_PRESETS,
  signChain,
} from "@openlfcp/client";
import { fromHex, hash32, toHex } from "@openlfcp/core";
import {
  certificateChain,
  DEVICE_KIND,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  cert,
  certFixture,
  chainAt,
  chainOf,
  contextOf,
  flow,
  idOf,
  party,
  recordOf,
  wire,
  wireCase,
} from "./corpus.js";

describe("F13: phases rebuilt from the approval journal", () => {
  const f = flow("F13_durable_phases");
  const step = (n: number) =>
    f.inputs.steps.find((s) => s.n === n) as (typeof f.inputs.steps)[number];

  test("phase 1 on P2 is the exact P3 (consume with the journaled digest)", () => {
    const j = step(1).journal;
    expect(j.certificate_payload_cbor).toBe(certFixture("CERT_B").payload_cbor.hex);
    expect(j.certificate_payload_digest).toBe(certFixture("CERT_B").payload_digest.hex);
    const bytes = consumeRecord(
      chainAt("P2_pairing_device"),
      party("DEV_A"),
      idOf("OWNER"),
      idOf("PAIR_J"),
      hash32(fromHex(j.certificate_payload_digest)),
    );
    expect(toHex(bytes)).toBe(toHex(recordOf(j.next_record)));
  });

  test("phase 2 on P3 signs exactly the journaled payload: CERT_B, and the exact P4", () => {
    const j = step(4).journal;
    const chain = chainAt("P3_consume_for_dev_b");
    const payload = cert("CERT_B").payload;
    expect(j.certificate_payload_cbor).toBe(certFixture("CERT_B").payload_cbor.hex);
    const chainB = signChain(chain.state, party("DEV_A"), payload);
    expect(toHex(chainB.leaf.signed.bytes)).toBe(certFixture("CERT_B").cose_sign1.hex);
    const bytes = approvedGrantRecord(chain, party("DEV_A"), idOf("OWNER"), chainB, idOf("PAIR_J"));
    expect(toHex(bytes)).toBe(toHex(recordOf(j.next_record)));
  });
});

describe("F08: the 32-device limit and the forty sessions (W §17.4 rule 8)", {
  timeout: 60_000,
}, () => {
  test("at 32 live devices a further pairing device is infeasible: no link", () => {
    const chain = chainAt("flow.p31_pairing_device");
    const jm2 = cert("CERT_JM2").payload;
    const f = checkIssuance({ chain, issuer: party("DEV_A"), leaf: jm2 });
    expect(f.feasible).toBe(false);
    expect(wireCase("flow.p31_second_pairing_refused").expected.valid).toBe(false);
  });

  test("the consume frees the pairing device's place: DEV_B is feasible and the fixtures' records follow", () => {
    for (const set of ["p31", "p40"]) {
      const chain = chainAt(`flow.${set}_pairing_device`);
      const leaf = cert("CERT_B").payload;
      expect(
        checkIssuance({ chain, issuer: party("DEV_A"), leaf, pairing: idOf("PAIR_M") }),
      ).toEqual({
        feasible: true,
      });
      const consume = consumeRecord(
        chain,
        party("DEV_A"),
        idOf("OWNER"),
        idOf("PAIR_M"),
        cert("CERT_B").payloadDigest,
      );
      expect(toHex(consume)).toBe(toHex(recordOf(`flow.${set}_consume`)));
      const after = chainOf([...chain.records.map((r) => r.signed.bytes), consume]);
      const chainB = signChain(after.state, party("DEV_A"), leaf);
      const grant = approvedGrantRecord(
        after,
        party("DEV_A"),
        idOf("OWNER"),
        chainB,
        idOf("PAIR_M"),
      );
      expect(toHex(grant)).toBe(toHex(recordOf(`flow.${set}_register_dev_b`)));
    }
  });
});

describe("F10: the feasibility check before anything is committed (§5.3 step 4)", () => {
  test("a manager whose chain has three certificates is not offered Full; Edit and Read are", () => {
    // I at P1, then DEV_M3 registered with [CERT_M3, CERT_M2, CERT_A] by the root.
    const base = contextOf("device_grant_feasibility_full_depth_4");
    const p1 = chainOf(base);
    const m3 = certificateChain([cert("CERT_M3"), cert("CERT_M2"), cert("CERT_A")], idOf("OWNER"));
    const grant = signControlRecord(
      {
        resourceId: p1.state.resourceId,
        controlSeq: p1.state.seq + 1n,
        prevControlId: p1.state.head,
      },
      { type: "DEVICE_GRANT", root: idOf("OWNER"), chain: m3 },
      party("OWNER"),
    );
    const chain = validateControlChain([...base, grant.bytes]);
    if (chain.kind !== "linear") throw new Error(chain.kind);
    const offered = (["full", "edit", "read"] as const).map((preset) => {
      const p = MASK_PRESETS[preset];
      return checkIssuance({
        chain,
        issuer: party("DEV_M3"),
        leaf: leafPayload(idOf("OWNER"), party("DEV_H").descriptor, p.kind as 0, p.mask, []),
      }).feasible;
    });
    expect(offered).toEqual([false, true, true]);
    expect(wireCase("device_grant_feasibility_full_depth_4").expected.error.code).toBe(
      "MALFORMED_MESSAGE",
    );
  });

  test("an Edit device cannot issue at all; a mask beyond the issuer's is refused", () => {
    // DEV_B (Edit) registered under DEV_A at P1.
    const base = contextOf("device_grant_feasibility_edit_issuer");
    const p1 = chainOf(base);
    const b = certificateChain([cert("CERT_B"), cert("CERT_A")], idOf("OWNER"));
    const grant = signControlRecord(
      {
        resourceId: p1.state.resourceId,
        controlSeq: p1.state.seq + 1n,
        prevControlId: p1.state.head,
      },
      { type: "DEVICE_GRANT", root: idOf("OWNER"), chain: b },
      party("OWNER"),
    );
    const chain = chainOf([...base, grant.bytes]);
    const read = MASK_PRESETS.read;
    expect(
      checkIssuance({
        chain,
        issuer: party("DEV_B"),
        leaf: leafPayload(
          idOf("OWNER"),
          party("DEV_X").descriptor,
          DEVICE_KIND.PERSONAL,
          read.mask,
          [],
        ),
      }).feasible,
    ).toBe(false);
  });
});

describe("F09: the service device's result in each candidate (§5.3 step 8)", () => {
  const D = idOf("BRIDGE_O");
  const d = cert("CERT_SO").payloadDigest;
  const result = cert("CERT_SO").payload;
  const leaves = (e: { leaves: readonly Uint8Array[] }) =>
    e.leaves.map(
      (id) =>
        Object.entries(wire.fixtures.certificates).find(
          ([, c]) => c.certificate_id.hex === toHex(id),
        )?.[0],
    );

  test("X where C0 was never accepted: registered with C1, approval not provable here", () => {
    const e = candidateEvidence(chainAt("flow.f09a_register_c1"), D, d, result);
    expect(leaves(e)).toEqual(["CERT_SO_R"]);
    expect([e.proven, e.registration, e.usable]).toEqual([false, "active", false]);
  });

  test("X where C0 was registered first: C0 from the history, C1 used", () => {
    const e = candidateEvidence(chainAt("flow.f09b_register_c1"), D, d, result);
    expect(leaves(e)).toEqual(["CERT_SO", "CERT_SO_R"]);
    expect([e.proven, e.registration, e.usable]).toEqual([true, "active", true]);
  });

  test("X where another issuer registered C* (scope [X, Y], another digest): not used", () => {
    const e = candidateEvidence(chainAt("flow.f09_x_register_cstar"), D, d, result);
    expect(leaves(e)).toEqual(["CERT_SO_XY"]);
    expect(e.usable).toBe(false);
  });

  test("bound in I by phase 2 without registration: B cannot write there", () => {
    const e = candidateEvidence(chainAt("P4s_bind_bridge_o"), D, d, result);
    expect([e.proven, e.registration]).toEqual([true, "pending"]);
  });
});
