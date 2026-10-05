// LFCP-023: Data Epoch rotation and the strict cutoff along the published
// chain (LFCP-TEST-VECTORS-01 at the pinned spec commit):
//
// - C6 (KEY_EPOCH) opens epoch 1 with the dek_commitments case's epoch-1
//   commitment and closes epoch 0 with the final frontier BOB 1..2;
// - D1, D2 (BOB, epoch 0, seq 1-2) are within that cutoff: accepted;
// - D3 (BOB, epoch 0, seq 3) is stale after C6 (vector document §12.5):
//   quarantine BEYOND_CUTOFF, STALE_DATA_EPOCH;
// - D4 (CAROL, epoch 1) is current-epoch work: accepted;
// - stale_epoch_absent_actor (CAROL in closed epoch 0): quarantine
//   ACTOR_ABSENT, closed by its context's cutoff_record.

import { fromHex, toHex } from "@openlfcp/core";
import {
  classifyDataUnit,
  decodeDataUnitPayload,
  parseDataUnit,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import type { VectorSuite } from "../runner.js";
import { openSpec } from "../spec.mjs";

const spec = openSpec();
const suite = spec.readJson("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json") as VectorSuite;
const byId = (id: string) => {
  const c = suite.cases.find((x) => x.id === id);
  if (c === undefined) throw new Error(`no case ${id}`);
  return c;
};
const hex = (id: string, field: string, where: "expected" | "inputs" = "expected"): string => {
  const v = (byId(id)[where] as Record<string, { hex?: string }> | undefined)?.[field]?.hex;
  if (v === undefined) throw new Error(`no ${id}.${where}.${field}`);
  return v;
};

const chain = validateControlChain(
  suite.cases
    .filter((c) => c.type === "bytes" && c.kind === "control_record")
    .map((c) => fromHex(hex(c.id, "cose_sign1"))),
);
const bob = hex("principal_bob", "principal_id");

describe(`Data Epoch cutoff along the published chain at ${spec.lock.tag}`, () => {
  it("C6 opens epoch 1 with the published epoch-1 commitment and closes epoch 0 at BOB 1..2", () => {
    if (chain.kind !== "linear") throw new Error(chain.kind);
    const s = chain.state;
    expect(s.epoch.epoch).toBe(1n);
    expect(toHex(s.epoch.dekCommitment)).toBe(hex("dek_commitments", "dek1_commitment"));
    expect(toHex(s.epochs.get("0")?.dekCommitment as Uint8Array)).toBe(
      hex("dek_commitments", "dek0_commitment"),
    );
    const e0 = s.epochs.get("0");
    expect(toHex(e0?.closedBy as Uint8Array)).toBe(hex("C6_key_epoch_1", "record_id"));
    expect(e0?.finalFrontier?.map((h) => [toHex(h.principalId), h.contiguous, h.extras])).toEqual([
      [bob, 2n, []],
    ]);
  });

  it.each([
    ["D1_bob_epoch0_seq1", { kind: "accept" }],
    ["D2_bob_epoch0_seq2", { kind: "accept" }],
    [
      "D3_bob_epoch0_seq3_stale",
      { kind: "quarantine", code: "STALE_DATA_EPOCH", reason: "BEYOND_CUTOFF" },
    ],
    ["D4_carol_epoch1_seq1", { kind: "accept" }],
  ])("%s -> %o", (id, expected) => {
    if (chain.kind !== "linear") throw new Error(chain.kind);
    expect(
      classifyDataUnit(chain, decodeDataUnitPayload(fromHex(hex(id, "payload_cbor")))),
    ).toMatchObject(expected);
  });

  it("stale_epoch_absent_actor is quarantined as ACTOR_ABSENT by its context's cutoff record", () => {
    if (chain.kind !== "linear") throw new Error(chain.kind);
    const c = byId("stale_epoch_absent_actor");
    const context = c.context as {
      cutoff_record: { case: string; field: string };
      closed_epoch: number;
    };
    const result = classifyDataUnit(
      chain,
      parseDataUnit(fromHex(hex(c.id, "cose_sign1", "inputs"))).payload,
    );
    expect(result).toMatchObject({
      kind: "quarantine",
      code: "STALE_DATA_EPOCH",
      reason: "ACTOR_ABSENT",
    });
    if (result.kind !== "quarantine") return;
    expect(result.epoch).toBe(BigInt(context.closed_epoch));
    expect(toHex(result.closedBy)).toBe(
      hex(context.cutoff_record.case, context.cutoff_record.field),
    );
  });
});
