// Revocation, rotation and reconciliation against IDENTITY-FLOW-FIXTURES-01
// F05, F12, F13, F14 and F15.

import {
  classifyPackage,
  exposingRevocationsSince,
  planReconciliation,
  planRevocations,
  readersAt,
  reconcileRecord,
  rotatorTest,
  verifiedFrontier,
} from "@openlfcp/client";
import { fromHex, toHex } from "@openlfcp/core";
import { importResourceDEK, sha256 } from "@openlfcp/crypto";
import { parseDataUnit, rotateEpoch } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import {
  chainAt,
  chainOf,
  dek0Of,
  flow,
  idOf,
  party,
  recordOf,
  recordsAt,
  wire,
  wireCase,
} from "./corpus.js";

const labelOf = (id: Uint8Array): string => {
  for (const c of wire.cases)
    if (c.kind === "principal" && toHex(idOf(c.inputs.label)) === toHex(id)) return c.inputs.label;
  for (const label of Object.keys(wire.fixtures.certificates).map(
    (k) => wire.fixtures.certificates[k]?.device as string,
  ))
    if (toHex(idOf(label)) === toHex(id)) return label;
  return toHex(id);
};

describe("F12: the rotator test of §8.1 on concrete states", () => {
  const table = wireCase("flow.rotator_test").expected.tables as Record<
    string,
    { readers: string[]; candidates: Record<string, Record<string, boolean>> }
  >;
  const heads = wireCase("flow.rotator_test").inputs.heads as Record<string, string>;
  test.each(Object.entries(table))("%s", (name, expected) => {
    const chain = chainAt(heads[name.startsWith("X") ? "X" : "I"] as string);
    const t0 = rotatorTest(chain.state, idOf(Object.keys(expected.candidates)[0] as string));
    expect(t0.readers.map((r) => labelOf(r.principalId)).sort()).toEqual(
      [...expected.readers].sort(),
    );
    for (const [candidate, e] of Object.entries(expected.candidates)) {
      const t = rotatorTest(chain.state, idOf(candidate));
      expect({
        holds_6: t.holds6,
        holds_7: t.holds7,
        every_reader_of_own_root: t.everyReaderOfOwnRoot,
        rotator: t.rotator,
      }).toEqual(e);
    }
  });
});

describe("F05: reconciliation plans the fixtures' exact records (§7.1)", () => {
  const I = chainAt("P4_register_dev_b_approved");
  test("PAIR_J's consume is not relevant in X; the intermediate-only DEV_A is registered; DEV_B needs nothing", () => {
    let X = chainAt("flow.self_register_dev_b_on_j2");
    // baseline.4 §7.1 step 1: a pairing device not bound in X is never propagated there.
    const step1 = planRevocations(I, X);
    expect(step1.propose).toEqual([]);
    expect(step1.notRelevant.map(labelOf)).toEqual(["PAIR_J"]);
    const steps = planReconciliation(I, X);
    expect(steps.map((s) => `${s.kind}:${labelOf(s.device)}`)).toEqual(["register:DEV_A"]);
    const expected = ["flow.reconcile_register_dev_a_in_x"];
    steps.forEach((step, i) => {
      const bytes = reconcileRecord(X, step, party("OWNER"));
      expect(toHex(bytes)).toBe(toHex(recordOf(expected[i] as string)));
      X = chainOf([...X.records.map((r) => r.signed.bytes), bytes]);
    });
    // Idempotence: a second run proposes nothing.
    expect(planReconciliation(I, X)).toEqual([]);
    // The Identity Resource as its own target: steps 1 and 2 are vacuous.
    expect(planReconciliation(I, I)).toEqual([]);
  });
});

describe("F14: the final frontier from the verified accepted set (§8.3)", () => {
  test("advertised 1..100, fetchable 1, 2 and 4, BRIDGE refused: {DEV_A: 2, [[4, 4]]}", async () => {
    const server = new MemoryCoordinator();
    const Y = server.seed(recordsAt("Yb1_bridge_out_of_scope"));
    const hosted = server.hosted.get(toHex(Y));
    if (hosted === undefined) throw new Error("not hosted");
    for (const id of [
      "flow.y_dev_a_seq1",
      "flow.y_dev_a_seq2",
      "flow.y_dev_a_seq4",
      "D_bridge_in_y",
    ]) {
      const bytes = fromHex(wireCase(id).inputs.cose_sign1.hex);
      const p = parseDataUnit(bytes).payload;
      hosted.units.set(`${toHex(p.actor)}:${p.actorSeq}`, bytes);
    }
    const chain = chainAt("Yb1_bridge_out_of_scope");
    const channel = await server.network().connect(party("OWNER"), "wss://y.test");
    const frontier = await verifiedFrontier(
      channel,
      chain,
      { units: [], snapshot: [] },
      { deks: new Map([["0", dek0Of("Y")]]) },
    );
    expect(frontier.map((h) => [labelOf(h.principalId), h.contiguous, h.extras])).toEqual([
      ["DEV_A", 2n, [[4n, 4n]]],
    ]);
    const dek = importResourceDEK(
      sha256(new TextEncoder().encode("LFCP-TV-IDENTITY-DEK-Y-EPOCH-1")),
    );
    const r = rotateEpoch(chain.state, party("DEV_A"), {
      reason: 0n,
      finalFrontier: frontier,
      dek,
    });
    expect(toHex(r.bytes)).toBe(toHex(recordOf("flow.y_key_epoch_1")));
  });
});

describe("F15: rotation follows exposing revocations only (§8.4)", () => {
  const exposing = (id: string) => exposingRevocationsSince(chainAt(id)).length;
  /** Whether the case's own record calls for a rotation (earlier ones of the epoch aside). */
  const calls = (id: string) => {
    const chain = chainAt(id);
    return exposingRevocationsSince(chain).some((e) => e.seq === chain.state.seq) ? 1 : 0;
  };
  test.each([
    ["I9_device_revoke_dev_a", 1],
    ["Vu1_revoke_unbound", 0],
    ["flow.revoke_out_of_scope_bridge_in_y", 0],
    ["flow.revoke_suspended_dev_b", 0],
    ["W2", 0],
    ["V2_revoke_dev_c", 1],
  ] as const)("%s → %i", (id, n) => {
    expect(calls(id)).toBe(n);
  });
  test("a KEY_EPOCH after the revocation clears it: nothing to rotate at K1", () => {
    expect(exposing("K1_key_epoch")).toBe(0);
  });
  test("several exposing revocations in one epoch: one rotation covers them", () => {
    // I9 revokes DEV_A (exposing) and I13 expels DEV_C (exposing) without a KEY_EPOCH between.
    const at = chainAt("I13_owner_expels_dev_c");
    expect(exposingRevocationsSince(at).length).toBeGreaterThanOrEqual(2);
  });
});

describe("F13: package phases and the reader set after the revocation", () => {
  test("DEV_A reads at I8 and not at I9; DEV_B, suspended at K1, is skipped", () => {
    const reads = (id: string, who: string) =>
      readersAt(chainAt(id).state).some((r) => toHex(r.principalId) === toHex(idOf(who)));
    expect([reads("I8_bridge_grant", "DEV_A"), reads("I9_device_revoke_dev_a", "DEV_A")]).toEqual([
      true,
      false,
    ]);
    expect(reads("K1_key_epoch", "DEV_B")).toBe(false);
    expect(classifyPackage(false, reads("K1_key_epoch", "DEV_B"))).toBe("skipped");
    expect(classifyPackage(true, reads("K1_key_epoch", "BOB"))).toBe("complete");
    expect(classifyPackage(false, reads("K1_key_epoch", "CAROL"))).toBe("pending");
    const f = flow("F13_durable_phases");
    expect(f.expected.steps.find((s) => s.n === 13)?.package_phases).toEqual({
      BOB: "complete",
      CAROL: "pending",
    });
  });
});
