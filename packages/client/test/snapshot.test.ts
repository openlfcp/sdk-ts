import {
  type ControlRecordId,
  dataEpoch,
  type PrincipalId,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  InMemorySnapshotSequenceReservation,
  SnapshotSequenceGuard,
  type SnapshotSequenceReservation,
} from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  type DataProfileCodec,
  parseSnapshot,
  principalDescriptorFromKeys,
  receiveSnapshot,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { createSnapshot } from "../src/index.js";

// Synthetic keys and chains; SNAPSHOT-01 and SNAPSHOT-02 are re-created by
// the conformance runner.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const PUBLISHER = signer(33);
const READER = signer(65);
const R = resourceId(bytes32(200));
const PROFILE = "org.example.custom.v1";
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));
const P = PUBLISHER.descriptor.principalId;

const records: Uint8Array[] = [];
let head: ControlRecordId;
function add(body: ControlBody) {
  const s = signControlRecord(
    {
      resourceId: R,
      controlSeq: BigInt(records.length),
      prevControlId: records.length === 0 ? null : head,
    },
    body,
    OWNER,
  );
  records.push(s.bytes);
  head = s.recordId;
}
add({
  type: "GENESIS",
  dataProfile: PROFILE,
  owner: OWNER.descriptor,
  dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
  endpoints: [{ url: "wss://a.example.test", priority: 0n }],
  coordinatorUrl: "wss://a.example.test",
});
add({
  type: "CAPABILITY_GRANT",
  subject: PUBLISHER.descriptor,
  abilities: [1n, 2n, 3n],
  delegable: [],
});
add({ type: "CAPABILITY_GRANT", subject: READER.descriptor, abilities: [1n], delegable: [] });
type View = Extract<ChainResult, { kind: "linear" }>;
const validate = (list: readonly Uint8Array[]): View => {
  const r = validateControlChain(list);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
};
const VIEW = validate(records);

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (p) => String.fromCharCode(...p),
};
const live = (id: PrincipalId, contiguous: bigint, ranges?: [bigint, bigint][]) => ({
  principalId: id,
  contiguous,
  ...(ranges ? { ranges } : {}),
});

class Counting implements SnapshotSequenceReservation {
  calls = 0;
  readonly #inner = new InMemorySnapshotSequenceReservation();
  reserveNext(...args: Parameters<SnapshotSequenceReservation["reserveNext"]>) {
    this.calls++;
    return this.#inner.reserveNext(...args);
  }
}
const create = (
  o: Partial<Parameters<typeof createSnapshot<string>>[0]> & {
    sequences: SnapshotSequenceReservation;
  },
) =>
  createSnapshot({
    view: VIEW,
    controlHead: VIEW.state.head,
    publisher: PUBLISHER,
    dek: DEK0,
    frontier: [live(P, 4n)],
    profile: TEXT,
    value: "state",
    ...o,
  });

describe("createSnapshot (§29)", () => {
  it("creates a Snapshot that receiveSnapshot accepts, with reserved sequences", async () => {
    const sequences = new Counting();
    const a = await create({ sequences, value: "first" });
    const b = await create({ sequences, value: "second" });
    expect([a.seq, b.seq, a.epoch]).toEqual([1n, 2n, 0n]);
    const r = await receiveSnapshot(VIEW, b.bytes, { dek: () => DEK0, profile: TEXT });
    expect(r).toMatchObject({ kind: "accepted", value: "second", seq: 2n });
    expect(toHex(b.bytes)).not.toContain(toHex(ascii("second")));
  });

  it("5. normalizes and canonicalizes the frontier before encrypting and signing", async () => {
    const low = principalId(bytes32(0));
    const s = await create({
      sequences: new InMemorySnapshotSequenceReservation(),
      frontier: [
        live(P, 2n, [
          [3n, 3n],
          [6n, 7n],
        ]),
        live(low, 0n, [[1n, 1n]]),
        live(P, 0n, [[5n, 5n]]),
      ],
    });
    const frontier = parseSnapshot(s.bytes).payload.frontier;
    expect(frontier.map((h) => [toHex(h.principalId), h.contiguous, h.extras])).toEqual([
      [toHex(low), 1n, []],
      [toHex(P), 3n, [[5n, 7n]]],
    ]);
  });

  it("17. a Snapshot Sequence handed out twice is blocked by the guard", async () => {
    const stuck: SnapshotSequenceReservation = { reserveNext: () => Promise.resolve(1n) };
    const guard = new SnapshotSequenceGuard();
    await create({ sequences: stuck, guard });
    await expect(create({ sequences: stuck, guard })).rejects.toMatchObject({
      code: "SEQUENCE_REUSE",
    });
  });

  it("refuses before reserving: no snapshot/publish, wrong DEK, other profile, unknown head", async () => {
    const sequences = new Counting();
    for (const [o, code] of [
      [{ publisher: READER }, "AUTHORIZATION_FAILED"],
      [{ dek: DEK1 }, "DEK_COMMITMENT_MISMATCH"],
      [{ profile: { ...TEXT, dataProfile: "x" } }, "DATA_PROFILE_MISMATCH"],
      [{ controlHead: bytes32(3) }, "MISSING_DEPENDENCY"],
    ] as const)
      await expect(create({ sequences, ...o })).rejects.toMatchObject({ code });
    expect(sequences.calls).toBe(0);
  });

  it("PROVISIONAL G-EP4: a Snapshot of a closed epoch may not go beyond its final frontier", async () => {
    const rotation = rotateEpoch(VIEW.state, OWNER, {
      reason: 0n,
      finalFrontier: [{ principalId: P, contiguous: 4n, extras: [] }],
      dek: DEK1,
    });
    const rotated = validate([...records, rotation.bytes]);
    const sequences = new Counting();
    // Still authorized at the old head with epoch 0's DEK, but epoch 0 is now closed.
    await expect(
      create({ sequences, view: rotated, frontier: [live(P, 5n)] }),
    ).rejects.toMatchObject({ code: "INVALID_STRUCTURE" });
    expect(sequences.calls).toBe(0);
    const within = await create({ sequences, view: rotated, frontier: [live(P, 4n)] });
    expect(within.epoch).toBe(dataEpoch(0n));
  });
});
