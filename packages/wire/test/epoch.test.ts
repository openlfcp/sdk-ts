import {
  actorSequence,
  type ControlRecordId,
  controlRecordId,
  dataEpoch,
  type PrincipalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  type ActorHave,
  type ChainResult,
  type ControlState,
  classifyDataUnit,
  type DataUnitHeader,
  isSequenceWithinFrontier,
  KEY_EPOCH_REASON,
  principalDescriptorFromKeys,
  proposeControlTransition,
  rotateEpoch,
  type Signer,
  serverAcceptsDataPut,
  signControlRecord,
  signObject,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic chains; the published C6 cutoff and D3/D4/stale vectors run in
// the conformance runner.

const signer = (seed: number): Signer => {
  const key = importSigningKey(seq32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(seed + 100))),
  };
};
const CARLA = signer(65);
const R = resourceId(seq32(200));
const DEK0 = importResourceDEK(seq32(90));
const id = (s: Signer): PrincipalId => s.descriptor.principalId;

const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: "org.example.custom.v1",
    owner: ALICE.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  ALICE,
);
const grantBruno = signControlRecord(
  { resourceId: R, controlSeq: 1n, prevControlId: genesis.recordId },
  { type: "CAPABILITY_GRANT", subject: BRUNO.descriptor, abilities: [1n, 2n], delegable: [] },
  ALICE,
);
const grantCarla = signControlRecord(
  { resourceId: R, controlSeq: 2n, prevControlId: grantBruno.recordId },
  { type: "CAPABILITY_GRANT", subject: CARLA.descriptor, abilities: [1n, 2n], delegable: [] },
  ALICE,
);
const H = grantCarla.recordId; // the head before rotation

function linear(records: readonly Uint8Array[]): Extract<ChainResult, { kind: "linear" }> {
  const r = validateControlChain(records);
  if (r.kind !== "linear") throw new Error(r.kind === "invalid" ? r.error.message : r.kind);
  return r;
}
const BASE = [genesis.bytes, grantBruno.bytes, grantCarla.bytes];
const before = (): ControlState => linear(BASE).state;

/** Epoch 0 closes with BRUNO 1..3 plus 6..7; CARLA is absent. */
const FRONTIER: readonly ActorHave[] = [
  { principalId: id(BRUNO), contiguous: 3n, extras: [[6n, 7n]] },
];
const rotation = (dek = importResourceDEK(seq32(91))) =>
  rotateEpoch(before(), ALICE, {
    reason: KEY_EPOCH_REASON.MEMBER_REVOKED,
    finalFrontier: FRONTIER,
    dek,
  });
const rotated = () => linear([...BASE, rotation().bytes]);

const unit = (
  actor: Signer,
  epoch: bigint,
  seq: bigint,
  head: ControlRecordId = H,
): DataUnitHeader => ({
  resourceId: R,
  dataEpoch: dataEpoch(epoch),
  actor: id(actor),
  actorSeq: actorSequence(seq),
  controlHead: head,
});

/** A KEY_EPOCH record signed as is (writers would refuse these). */
function rawKeyEpoch(epoch: number, frontier: unknown[], by = ALICE): Uint8Array {
  const payload = encode(
    cborMap([
      [0, R],
      [1, 3],
      [2, H],
      [3, 4],
      [4, id(by)],
      [
        5,
        cborMap([
          [0, epoch],
          [1, seq32(12)],
          [2, frontier as never],
          [3, 1],
        ]),
      ],
    ]),
  );
  return signObject(payload, by).bytes;
}
const have = (who: Signer, contiguous: number, extras?: number[][]) =>
  cborMap(
    extras === undefined
      ? [
          [0, id(who)],
          [1, contiguous],
        ]
      : [
          [0, id(who)],
          [1, contiguous],
          [2, extras],
        ],
  );

describe("Key Epoch rotation (§19)", () => {
  it("1, 5, 7. E -> E+1 commits the new commitment and closes E with its final frontier", () => {
    const rot = rotation();
    const r = proposeControlTransition(before(), H, rot.bytes);
    if (r.kind !== "accepted") throw new Error(r.kind);
    const s = r.nextState;
    expect(s.epoch).toEqual({ epoch: 1n, dekCommitment: rot.dekCommitment });
    expect(toHex(rot.dekCommitment)).toBe(toHex(dekCommitment(R, dataEpoch(1n), rot.dek)));
    const e0 = s.epochs.get("0");
    expect(e0?.finalFrontier).toEqual(FRONTIER);
    expect(toHex(e0?.closedBy as ControlRecordId)).toBe(toHex(rot.recordId));
    expect(s.epochs.get("1")).toMatchObject({ closedBy: null, finalFrontier: null });
  });

  it("2, 3. refuses skipping or reusing an epoch number (INVALID_CONTROL_CHAIN)", () => {
    for (const epoch of [2, 0]) {
      const r = proposeControlTransition(before(), H, rawKeyEpoch(epoch, [have(BRUNO, 3)]));
      expect(r).toMatchObject({
        kind: "invalid",
        problem: "EPOCH",
        wireCode: "INVALID_CONTROL_CHAIN",
      });
    }
  });

  it("4, 6. draws a fresh 32-byte DEK each time; a new DEK gives a new commitment", () => {
    const a = rotateEpoch(before(), ALICE, { reason: 0n, finalFrontier: FRONTIER });
    const b = rotateEpoch(before(), ALICE, { reason: 0n, finalFrontier: FRONTIER });
    const bytes = (k: typeof a.dek) => toHex(exportSecretKeyBytes(k));
    expect(exportSecretKeyBytes(a.dek)).toHaveLength(32);
    expect(bytes(a.dek)).not.toBe(bytes(b.dek));
    expect(bytes(a.dek)).not.toBe(bytes(DEK0));
    expect(toHex(a.dekCommitment)).not.toBe(toHex(b.dekCommitment));
  });

  it("never puts the DEK into the record", () => {
    const rot = rotation(importResourceDEK(seq32(91)));
    expect(toHex(rot.bytes)).not.toContain(toHex(seq32(91)));
    expect(toHex(rot.bytes)).toContain(toHex(rot.dekCommitment));
  });

  it.each([
    ["8. a reversed range", [have(BRUNO, 3, [[7, 6]])]],
    [
      "9. overlapping ranges",
      [
        have(BRUNO, 3, [
          [6, 8],
          [7, 9],
        ]),
      ],
    ],
    [
      "10. adjacent ranges",
      [
        have(BRUNO, 3, [
          [6, 7],
          [8, 9],
        ]),
      ],
    ],
    [
      "unsorted ranges",
      [
        have(BRUNO, 3, [
          [9, 9],
          [6, 7],
        ]),
      ],
    ],
    ["a range at contiguous + 1 (W3)", [have(BRUNO, 3, [[4, 5]])]],
    ["an empty extras list", [have(BRUNO, 3, [])]],
    ["a duplicate actor", [have(BRUNO, 3), have(BRUNO, 4)]],
  ])("refuses a final frontier with %s (MALFORMED_MESSAGE)", (_n, frontier) => {
    const r = proposeControlTransition(before(), H, rawKeyEpoch(1, frontier));
    expect(r).toMatchObject({
      kind: "invalid",
      problem: "MALFORMED",
      wireCode: "MALFORMED_MESSAGE",
    });
  });

  it("refuses an unsorted frontier (G-CP1)", () => {
    const sorted = [id(BRUNO), id(CARLA)].sort((a, b) => (toHex(a) < toHex(b) ? -1 : 1));
    const [first, second] = sorted.map((p) => (toHex(p) === toHex(id(BRUNO)) ? BRUNO : CARLA)) as [
      Signer,
      Signer,
    ];
    const ok = proposeControlTransition(
      before(),
      H,
      rawKeyEpoch(1, [have(first, 1), have(second, 1)]),
    );
    expect(ok.kind).toBe("accepted");
    const bad = proposeControlTransition(
      before(),
      H,
      rawKeyEpoch(1, [have(second, 1), have(first, 1)]),
    );
    expect(bad).toMatchObject({ kind: "invalid", wireCode: "MALFORMED_MESSAGE" });
  });

  it("16. refuses a rotation by an issuer without key/rotate", () => {
    const r = proposeControlTransition(
      before(),
      H,
      rotateEpoch(before(), BRUNO, { reason: 0n, finalFrontier: FRONTIER }).bytes,
    );
    expect(r).toMatchObject({ kind: "unauthorized", wireCode: "AUTHORIZATION_FAILED" });
  });

  it("keeps unknown reason codes (structure only) and every epoch's history", () => {
    const first = rotateEpoch(before(), ALICE, { reason: 99n, finalFrontier: FRONTIER });
    const s1 = linear([...BASE, first.bytes]).state;
    const second = rotateEpoch(s1, ALICE, {
      reason: 0n,
      finalFrontier: [{ principalId: id(CARLA), contiguous: 1n, extras: [] }],
    });
    const s2 = linear([...BASE, first.bytes, second.bytes]).state;
    expect([...s2.epochs.keys()]).toEqual(["0", "1", "2"]);
    expect(s2.epochs.get("0")?.finalFrontier).toEqual(FRONTIER);
    expect(s2.epochs.get("1")?.finalFrontier).toEqual([
      { principalId: id(CARLA), contiguous: 1n, extras: [] },
    ]);
    expect(s2.epoch.epoch).toBe(2n);
  });
});

describe("cutoff membership (§19.1)", () => {
  it.each([
    [1n, true],
    [3n, true], // 12. inside the contiguous run
    [6n, true], // 13. inside an explicit extra range
    [7n, true],
    [4n, false], // 14. a hole
    [5n, false],
    [8n, false], // 15. above the frontier
    [0n, false],
  ])("BRUNO seq %s within the frontier: %s", (seq, within) => {
    expect(isSequenceWithinFrontier(id(BRUNO), seq, FRONTIER)).toBe(within);
  });

  it("11. an absent actor covers nothing", () => {
    expect(isSequenceWithinFrontier(id(CARLA), 1n, FRONTIER)).toBe(false);
  });
});

describe("classifyDataUnit and serverAcceptsDataPut (§19.1, §26.3, §75)", () => {
  it("accepts closed-epoch units within the cutoff and current-epoch units", () => {
    const r = rotated();
    expect(classifyDataUnit(r, unit(BRUNO, 0n, 2n))).toEqual({ kind: "accept" });
    expect(classifyDataUnit(r, unit(BRUNO, 0n, 6n))).toEqual({ kind: "accept" });
    expect(classifyDataUnit(r, unit(CARLA, 1n, 1n, r.state.head))).toEqual({ kind: "accept" });
  });

  it("11, 14, 15, 18. quarantines stale closed-epoch work as STALE_DATA_EPOCH, never accepted or dropped", () => {
    const r = rotated();
    const closedBy = toHex(r.state.epochs.get("0")?.closedBy as ControlRecordId);
    for (const [u, reason] of [
      [unit(BRUNO, 0n, 4n), "BEYOND_CUTOFF"],
      [unit(BRUNO, 0n, 8n), "BEYOND_CUTOFF"],
      [unit(CARLA, 0n, 1n), "ACTOR_ABSENT"],
    ] as const) {
      const c = classifyDataUnit(r, u);
      expect(c).toMatchObject({ kind: "quarantine", code: "STALE_DATA_EPOCH", reason, epoch: 0n });
      expect(c.kind === "quarantine" && toHex(c.closedBy)).toBe(closedBy);
      expect(serverAcceptsDataPut(r, u)).toMatchObject({ ok: false, nack: "STALE_DATA_EPOCH" });
    }
  });

  it("holds a unit to the latest known cutoff, whichever head it referenced (G-EP1)", () => {
    const r = rotated();
    // BRUNO seq 4 referenced H, before the rotation: once the rotation is known, it is stale.
    expect(classifyDataUnit(r, unit(BRUNO, 0n, 4n, H)).kind).toBe("quarantine");
    // Before the rotation is known, the same unit is not yet subject to a cutoff.
    expect(classifyDataUnit(linear(BASE), unit(BRUNO, 0n, 4n, H))).toEqual({ kind: "accept" });
  });

  it("17. rotation keeps old units within the cutoff historical and valid", () => {
    const pre = linear(BASE);
    const post = rotated();
    const old = unit(BRUNO, 0n, 3n, H);
    expect(classifyDataUnit(pre, old)).toEqual({ kind: "accept" });
    expect(classifyDataUnit(post, old)).toEqual({ kind: "accept" });
    // The state at the old head is unchanged by the later rotation.
    expect(post.stateAt(H)?.epoch.epoch).toBe(0n);
  });

  it("rejects unknown heads and epochs not recognized at the unit's head (G-EP2: MISSING_DEPENDENCY)", () => {
    const r = rotated();
    expect(classifyDataUnit(r, unit(BRUNO, 0n, 1n, controlRecordId(seq32(5))))).toEqual({
      kind: "reject",
      reason: "UNKNOWN_CONTROL_HEAD",
      wireCode: "MISSING_DEPENDENCY",
    });
    // Epoch 1 referenced at H, where only epoch 0 exists.
    expect(classifyDataUnit(r, unit(BRUNO, 1n, 1n, H))).toMatchObject({
      kind: "reject",
      reason: "UNKNOWN_EPOCH",
    });
    expect(classifyDataUnit(r, unit(BRUNO, 5n, 1n, r.state.head))).toMatchObject({
      reason: "UNKNOWN_EPOCH",
    });
    expect(serverAcceptsDataPut(r, unit(BRUNO, 5n, 1n, r.state.head))).toMatchObject({
      ok: false,
      nack: "MISSING_DEPENDENCY",
    });
    expect(
      classifyDataUnit(r, { ...unit(BRUNO, 0n, 1n), resourceId: resourceId(seq32(1)) }),
    ).toMatchObject({ reason: "OTHER_RESOURCE" });
  });
});
