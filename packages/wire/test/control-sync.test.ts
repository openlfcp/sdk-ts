import { type ControlRecordId, controlRecordId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { localControlOf, planControlSync } from "../src/index.js";
import { seq32 } from "./synthetic.js";

// Control Plane anti-entropy (§44, §45, §67, G-HV2)

const rid = (n: number) => controlRecordId(seq32(n));
const ours = (seq: bigint, ids: Map<bigint, ControlRecordId>) => ({
  head: { seq, recordId: ids.get(seq) as ControlRecordId },
  recordIdAt: (s: bigint) => ids.get(s),
});
const CHAIN = new Map<bigint, ControlRecordId>(
  Array.from({ length: 11 }, (_, i) => [BigInt(i), rid(100 + i)] as const),
);

describe("Control synchronization planning", () => {
  it("§67: at 10 against a peer at 14, CONTROL_GET 11..14", () => {
    expect(planControlSync(ours(10n, CHAIN), [{ seq: 14n, recordId: rid(9) }])).toEqual({
      kind: "fetch",
      start: 11n,
      end: 14n,
    });
  });

  it("in sync, peer behind on our chain, nothing local, and G-HV2's empty CONTROL_HAVE", () => {
    expect(planControlSync(ours(10n, CHAIN), [{ seq: 10n, recordId: rid(110) }])).toEqual({
      kind: "in-sync",
    });
    expect(planControlSync(ours(10n, CHAIN), [{ seq: 7n, recordId: rid(107) }])).toEqual({
      kind: "peer-behind",
      peerSeq: 7n,
    });
    expect(planControlSync(null, [{ seq: 3n, recordId: rid(1) }])).toEqual({
      kind: "fetch",
      start: 0n,
      end: 3n,
    });
    expect(planControlSync(ours(10n, CHAIN), [])).toEqual({ kind: "peer-empty" });
  });

  it("surfaces forks and never resolves them", () => {
    const two = [
      { seq: 12n, recordId: rid(1) },
      { seq: 12n, recordId: rid(2) },
    ];
    expect(planControlSync(ours(10n, CHAIN), two)).toMatchObject({
      kind: "fork",
      reason: "PEER_HEADS",
      fetch: { start: 11n, end: 12n },
    });
    // A different record at a sequence we hold.
    expect(planControlSync(ours(10n, CHAIN), [{ seq: 10n, recordId: rid(9) }])).toEqual({
      kind: "fork",
      reason: "DIVERGED",
      heads: [{ seq: 10n, recordId: rid(9) }],
      fetch: { start: 10n, end: 10n },
    });
    expect(planControlSync(ours(10n, CHAIN), [{ seq: 6n, recordId: rid(9) }])).toMatchObject({
      kind: "fork",
      reason: "DIVERGED",
    });
  });
});

describe("localControlOf", () => {
  it("reads the head and the record ID at each sequence of a linear chain", () => {
    const records = [0n, 1n, 2n].map((seq) => ({
      signed: { id: rid(200 + Number(seq)) },
      payload: { controlSeq: seq },
    }));
    const local = localControlOf({ state: { head: rid(202), seq: 2n }, records });
    expect(local.head).toEqual({ seq: 2n, recordId: rid(202) });
    expect(local.recordIdAt(1n)).toEqual(rid(201));
    expect(planControlSync(local, [{ seq: 1n, recordId: rid(201) }])).toEqual({
      kind: "peer-behind",
      peerSeq: 1n,
    });
  });
});
