import {
  type ActorSequence,
  actorSequence,
  type ControlRecordId,
  dataEpoch,
  dataUnitId,
  type PrincipalId,
  type ResourceId,
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
  type ActorSequenceReservation,
  InMemoryActorSequenceReservation,
  SequenceReuseGuard,
} from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  type DataProfileCodec,
  InMemorySeenUnits,
  parseDataUnit,
  principalDescriptorFromKeys,
  receiveDataUnit,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { createDataUnit } from "../src/index.js";

// Synthetic keys and chains; the published D1-D4 are re-created byte for
// byte from their vector inputs by the conformance runner.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const WRITER = signer(33);
const READER = signer(65);
const R = resourceId(bytes32(200));
const PROFILE = "org.example.custom.v1";
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));

const records: Uint8Array[] = [];
let head: ControlRecordId;
function add(body: ControlBody, by: Signer = OWNER) {
  const s = signControlRecord(
    {
      resourceId: R,
      controlSeq: BigInt(records.length),
      prevControlId: records.length === 0 ? null : head,
    },
    body,
    by,
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
add({ type: "CAPABILITY_GRANT", subject: WRITER.descriptor, abilities: [1n, 2n], delegable: [] });
add({ type: "CAPABILITY_GRANT", subject: READER.descriptor, abilities: [1n], delegable: [] });

type View = Extract<ChainResult, { kind: "linear" }>;
const validate = (list: readonly Uint8Array[]): View => {
  const r = validateControlChain(list);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
};
const VIEW = validate(records);
const HEAD = VIEW.state.head;

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
/** An opaque test profile over strings. */
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (plaintext) => String.fromCharCode(...plaintext),
};

/** Counts calls, to show that refused creations reserve nothing. */
class CountingReservation implements ActorSequenceReservation {
  calls = 0;
  readonly #inner = new InMemoryActorSequenceReservation();
  reserveNext(resource: ResourceId, principal: PrincipalId): Promise<ActorSequence> {
    this.calls++;
    return this.#inner.reserveNext(resource, principal);
  }
}

const create = (
  o: Partial<Parameters<typeof createDataUnit<string>>[0]> & {
    sequences: ActorSequenceReservation;
  },
) =>
  createDataUnit({
    view: VIEW,
    controlHead: HEAD,
    actor: WRITER,
    dek: DEK0,
    previousUnitId: null,
    profile: TEXT,
    value: "hello",
    ...o,
  });

describe("createDataUnit (§8, §12, §26)", () => {
  it("1-7, 32. creates a unit the receive pipeline accepts, with the reserved sequence", async () => {
    const sequences = new CountingReservation();
    const u1 = await create({ sequences, value: "first" });
    const u2 = await create({ sequences, value: "second", previousUnitId: u1.unitId });
    expect([u1.seq, u2.seq, u1.epoch]).toEqual([1n, 2n, 0n]);
    const p = parseDataUnit(u2.bytes).payload;
    expect(toHex(p.prevDataUnitId as Uint8Array)).toBe(toHex(u1.unitId));
    expect(toHex(p.controlHead)).toBe(toHex(HEAD));
    const seen = new InMemorySeenUnits();
    const receive = (b: Uint8Array) =>
      receiveDataUnit(VIEW, b, { seen, dek: () => DEK0, profile: TEXT });
    expect(await receive(u1.bytes)).toMatchObject({ kind: "accepted", value: "first" });
    expect(await receive(u2.bytes)).toMatchObject({ kind: "accepted", value: "second" });
  });

  it("privacy: the bytes for the server do not contain the plaintext", async () => {
    const value = "confidential application plaintext";
    const u = await create({ sequences: new InMemoryActorSequenceReservation(), value });
    expect(toHex(u.bytes)).not.toContain(toHex(ascii(value)));
    expect(toHex(u.bytes)).not.toContain(toHex(ascii("confidential")));
  });

  it("16. a sequence handed out twice is blocked by the reuse guard", async () => {
    const stuck: ActorSequenceReservation = {
      reserveNext: () => Promise.resolve(actorSequence(1n)),
    };
    const guard = new SequenceReuseGuard();
    await create({ sequences: stuck, guard });
    await expect(create({ sequences: stuck, guard })).rejects.toMatchObject({
      code: "SEQUENCE_REUSE",
    });
  });

  it("15. sequence 1 must have a null previous unit; later sequences need one", async () => {
    const sequences = new InMemoryActorSequenceReservation();
    await expect(
      create({ sequences, previousUnitId: dataUnitId(bytes32(9)) }),
    ).rejects.toMatchObject({ code: "INVALID_STRUCTURE" });
    // Sequence 1 was abandoned with the refusal; the next one is 2 and needs a previous unit.
    await expect(create({ sequences })).rejects.toMatchObject({ code: "INVALID_STRUCTURE" });
  });

  it("17. a Data Epoch rotation does not reset the actor sequence", async () => {
    const sequences = new InMemoryActorSequenceReservation();
    const u1 = await create({ sequences });
    const rotation = rotateEpoch(VIEW.state, OWNER, {
      reason: 0n,
      finalFrontier: [{ principalId: WRITER.descriptor.principalId, contiguous: 1n, extras: [] }],
      dek: DEK1,
    });
    const rotated = validate([...records, rotation.bytes]);
    const u2 = await create({
      sequences,
      view: rotated,
      controlHead: rotation.recordId,
      dek: DEK1,
      previousUnitId: u1.unitId,
    });
    expect([u2.seq, u2.epoch]).toEqual([2n, 1n]);
  });

  it("refuses before reserving: unauthorized actor, wrong DEK, other profile, unknown head", async () => {
    const sequences = new CountingReservation();
    await expect(create({ sequences, actor: READER })).rejects.toMatchObject({
      code: "AUTHORIZATION_FAILED",
    });
    await expect(create({ sequences, dek: DEK1 })).rejects.toMatchObject({
      code: "DEK_COMMITMENT_MISMATCH",
    });
    await expect(
      create({ sequences, profile: { ...TEXT, dataProfile: "lfcp.other.v1" } }),
    ).rejects.toMatchObject({ code: "DATA_PROFILE_MISMATCH" });
    await expect(create({ sequences, controlHead: bytes32(3) })).rejects.toMatchObject({
      code: "MISSING_DEPENDENCY",
    });
    expect(sequences.calls).toBe(0);
  });
});
