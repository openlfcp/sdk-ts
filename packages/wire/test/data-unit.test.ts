import {
  type ActorSequence,
  actorSequence,
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  dataUnitId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  deriveActorDataKey,
  encryptDataUnit,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  type ResourceDEK,
  sha256,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  type ChainResult,
  type ControlBody,
  checkDataUnit,
  type DataProfileCodec,
  type DataUnitAadFields,
  dataUnitAad,
  encodeDataUnitPayload,
  InMemorySeenUnits,
  objectId,
  parseDataUnit,
  principalDescriptorFromKeys,
  type ReceivedDataUnit,
  receiveDataUnit,
  type Signer,
  sealDataUnit,
  signControlRecord,
  signObject,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic chains and units; the published D1-D4 and their negatives run
// in the conformance runner.

const CARLA: Signer = (() => {
  const key = importSigningKey(seq32(65));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(165))) };
})();
const R = resourceId(seq32(200));
const PROFILE = "org.example.custom.v1";
const DEK0 = importResourceDEK(seq32(90));
const DEK1 = importResourceDEK(seq32(91));

// G (owner ALICE) <- C1 grant BRUNO data/read, data/write <- C2 grant CARLA data/read
//   <- C3 revoke C1 <- C4 KEY_EPOCH 1 (BRUNO's epoch-0 frontier: contiguous 2)
const records: { bytes: Uint8Array; id: ControlRecordId }[] = [];
function add(body: ControlBody, by: Signer = ALICE): ControlRecordId {
  const prev = records[records.length - 1];
  const s = signControlRecord(
    {
      resourceId: R,
      controlSeq: BigInt(records.length),
      prevControlId: prev === undefined ? null : prev.id,
    },
    body,
    by,
  );
  records.push({ bytes: s.bytes, id: s.recordId });
  return s.recordId;
}
const G = add({
  type: "GENESIS",
  dataProfile: PROFILE,
  owner: ALICE.descriptor,
  dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
  endpoints: [{ url: "wss://a.example.test", priority: 0n }],
  coordinatorUrl: "wss://a.example.test",
});
const C1 = add({
  type: "CAPABILITY_GRANT",
  subject: BRUNO.descriptor,
  abilities: [1n, 2n],
  delegable: [],
});
const C2 = add({
  type: "CAPABILITY_GRANT",
  subject: CARLA.descriptor,
  abilities: [1n],
  delegable: [],
});
const C3 = add({ type: "CAPABILITY_REVOKE", grantId: C1 });
const C4 = add({
  type: "KEY_EPOCH",
  epoch: dataEpoch(1n),
  dekCommitment: dekCommitment(R, dataEpoch(1n), DEK1),
  finalFrontier: [{ principalId: BRUNO.descriptor.principalId, contiguous: 2n, extras: [] }],
  reason: 1n,
});

type View = Extract<ChainResult, { kind: "linear" }>;
function viewThrough(count: number): View {
  const r = validateControlChain(records.slice(0, count).map((x) => x.bytes));
  if (r.kind !== "linear") throw new Error(`chain: ${r.kind}`);
  return r;
}
const BEFORE_ROTATION = viewThrough(4); // G..C3
const FULL = viewThrough(5); // G..C4

/** An opaque test profile: any bytes, except a plaintext starting with 0xff is invalid. */
const OPAQUE: DataProfileCodec<Uint8Array> = {
  dataProfile: PROFILE,
  encode: (value) => Uint8Array.from(value),
  decode: (plaintext) => {
    if (plaintext[0] === 0xff) throw new Error("the profile refuses this plaintext");
    return Uint8Array.from(plaintext);
  },
};
const text = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

interface UnitSpec {
  by?: Signer;
  seq?: bigint;
  prev?: DataUnitId | null;
  head?: Uint8Array;
  epoch?: bigint;
  dek?: ResourceDEK;
  plaintext?: Uint8Array;
}
function unit(o: UnitSpec = {}) {
  return sealDataUnit(
    {
      resourceId: R,
      dataEpoch: dataEpoch(o.epoch ?? 0n),
      actorSeq: actorSequence(o.seq ?? 1n),
      prevDataUnitId: o.prev ?? null,
      controlHead: (o.head ?? C1) as ControlRecordId,
    },
    o.plaintext ?? text(`unit ${o.seq ?? 1n}`),
    o.dek ?? DEK0,
    o.by ?? BRUNO,
  );
}

/** A unit whose payload and ciphertext are built by hand: `sealedAs` overrides the AAD fields used for encryption. */
function handmade(
  fields: Omit<DataUnitAadFields, "resourceId" | "actor">,
  sealedAs: Partial<DataUnitAadFields> = {},
  by: Signer = BRUNO,
) {
  const header: DataUnitAadFields = { resourceId: R, actor: by.descriptor.principalId, ...fields };
  const aadFields = { ...header, ...sealedAs };
  const key = deriveActorDataKey(DEK0, R, header.dataEpoch, header.actor);
  const ciphertext = encryptDataUnit(key, aadFields.actorSeq, dataUnitAad(aadFields), text("x"));
  const signed = signObject(encodePayloadUnchecked({ ...header, ciphertext }), by);
  return { bytes: signed.bytes, unitId: dataUnitId(signed.id) };
}
/** The §26 payload, built without the writer checks (to allow a previous unit at sequence 1). */
const encodePayloadUnchecked = (h: DataUnitAadFields & { ciphertext: Uint8Array }): Uint8Array =>
  encode(
    cborMap([
      [0, h.resourceId],
      [1, h.dataEpoch],
      [2, h.actor],
      [3, h.actorSeq],
      [4, h.prevDataUnitId],
      [5, h.controlHead],
      [6, h.ciphertext],
    ]),
  );

const deks = (epoch: bigint) => (epoch === 0n ? DEK0 : epoch === 1n ? DEK1 : undefined);
const receiver = (view: View = BEFORE_ROTATION, seen = new InMemorySeenUnits()) => ({
  seen,
  receive: (bytes: Uint8Array) =>
    receiveDataUnit(view, bytes, { seen, dek: deks, profile: OPAQUE }),
});
const kindOf = (r: ReceivedDataUnit<unknown>) =>
  r.kind === "rejected"
    ? `rejected:${r.wireCode}`
    : r.kind === "local-failure" || r.kind === "held" || r.kind === "quarantined"
      ? `${r.kind}:${r.reason}`
      : r.kind;

describe("Data Unit construction (§12, §26, §26.1)", () => {
  it("3. the AAD is exactly the seven-element §26.1 array, null previous included", () => {
    const fields: DataUnitAadFields = {
      resourceId: R,
      dataEpoch: dataEpoch(0n),
      actor: BRUNO.descriptor.principalId,
      actorSeq: actorSequence(1n),
      prevDataUnitId: null,
      controlHead: C1,
    };
    const aad = dataUnitAad(fields);
    expect(toHex(aad)).toBe(
      toHex(encode(["LFCP-DATA-v1", R, 0, BRUNO.descriptor.principalId, 1, null, C1])),
    );
    expect(toHex(aad.subarray(0, 14))).toBe(`876c${toHex(text("LFCP-DATA-v1"))}`);
    expect(decodeStrict(aad)).toHaveLength(7);
  });

  it("5, 6, 7. payload keys 0-6 exactly; the unit is the actor's COSE_Sign1; ID = SHA-256 of the exact bytes", () => {
    const u = unit({ seq: 1n });
    const parsed = parseDataUnit(u.bytes);
    expect(parsed.payload).toMatchObject({
      resourceId: R,
      dataEpoch: 0n,
      actor: BRUNO.descriptor.principalId,
      actorSeq: 1n,
      prevDataUnitId: null,
      controlHead: C1,
    });
    expect(toHex(parsed.signed.kid)).toBe(toHex(BRUNO.descriptor.principalId));
    expect(toHex(u.unitId)).toBe(toHex(sha256(u.bytes)));
    expect(toHex(u.unitId)).toBe(toHex(objectId(u.bytes)));
    expect(parsed.payload.ciphertext).toHaveLength(text("unit 1").length + 16);
  });

  it("privacy: the created bytes do not contain the plaintext", () => {
    const secret = text("a plaintext that must never be on the wire");
    const u = unit({ plaintext: secret });
    expect(toHex(u.bytes)).not.toContain(toHex(secret));
    expect(toHex(u.bytes)).not.toContain(toHex(secret.subarray(0, 8)));
  });

  it("15. sequence 1 with a previous unit is refused by the writer", () => {
    expect(() => unit({ seq: 1n, prev: dataUnitId(seq32(9)) })).toThrow(
      expect.objectContaining({ code: "INVALID_STRUCTURE" }),
    );
  });
});

describe("receiveDataUnit: signature (§10.5, §26.3 rule 1)", () => {
  it("8, 32. a valid unit is accepted and arbitrary opaque plaintext round-trips", async () => {
    const opaque = Uint8Array.from({ length: 300 }, (_, i) => (i * 7) & 0xfe);
    const r = await receiver().receive(unit({ plaintext: opaque }).bytes);
    if (r.kind !== "accepted") throw new Error(kindOf(r));
    expect(toHex(r.value)).toBe(toHex(opaque));
    expect([r.seq, r.epoch]).toEqual([1n, 0n]);
  });

  it("9. a payload signed by another Principal (kid ≠ actor) is INVALID_SIGNATURE", async () => {
    const payload = parseDataUnit(unit().bytes).signed.payloadBytes;
    const forged = signObject(payload, CARLA);
    expect(kindOf(await receiver().receive(forged.bytes))).toBe("rejected:INVALID_SIGNATURE");
  });

  it("10. a tampered signed payload is INVALID_SIGNATURE", async () => {
    const bytes = Uint8Array.from(unit().bytes);
    bytes[bytes.length - 70] = (bytes[bytes.length - 70] as number) ^ 1; // inside the ciphertext
    expect(kindOf(await receiver().receive(bytes))).toBe("rejected:INVALID_SIGNATURE");
  });

  it("an actor no record describes is MISSING_DEPENDENCY; malformed bytes are MALFORMED_MESSAGE", async () => {
    const stranger: Signer = (() => {
      const key = importSigningKey(seq32(77));
      return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(78))) };
    })();
    expect(kindOf(await receiver().receive(unit({ by: stranger }).bytes))).toBe(
      "rejected:MISSING_DEPENDENCY",
    );
    expect(kindOf(await receiver().receive(Uint8Array.of(0x80)))).toBe(
      "rejected:MALFORMED_MESSAGE",
    );
  });
});

describe("receiveDataUnit: AEAD (§26.3 rule 6, N3: client-local)", () => {
  it("12. a ciphertext sealed under one changed AAD field fails authentication", async () => {
    const u = handmade(
      {
        dataEpoch: dataEpoch(0n),
        actorSeq: actorSequence(1n),
        prevDataUnitId: null,
        controlHead: C1,
      },
      { actorSeq: actorSequence(2n) },
    );
    expect(kindOf(await receiver().receive(u.bytes))).toBe("local-failure:AEAD");
  });

  it("13, 14. tampered ciphertext (re-signed) and another actor's key fail authentication", async () => {
    const p = parseDataUnit(unit().bytes).payload;
    const tampered = Uint8Array.from(p.ciphertext);
    tampered[0] = (tampered[0] as number) ^ 1;
    const resigned = signObject(encodeDataUnitPayload({ ...p, ciphertext: tampered }), BRUNO);
    expect(kindOf(await receiver().receive(resigned.bytes))).toBe("local-failure:AEAD");
    // Encrypted under CARLA's actor key but signed as BRUNO's unit.
    const carlaKey = deriveActorDataKey(DEK0, R, dataEpoch(0n), CARLA.descriptor.principalId);
    const ct = encryptDataUnit(carlaKey, actorSequence(1n), dataUnitAad(p), text("x"));
    const wrongKey = signObject(encodeDataUnitPayload({ ...p, ciphertext: ct }), BRUNO);
    expect(kindOf(await receiver().receive(wrongKey.bytes))).toBe("local-failure:AEAD");
  });

  it("a missing DEK or one that does not match the commitment is client-local", async () => {
    const seen = new InMemorySeenUnits();
    const bytes = unit().bytes;
    const none = await receiveDataUnit(BEFORE_ROTATION, bytes, {
      seen,
      dek: () => undefined,
      profile: OPAQUE,
    });
    expect(kindOf(none)).toBe("local-failure:NO_DEK");
    const wrong = await receiveDataUnit(BEFORE_ROTATION, bytes, {
      seen,
      dek: () => DEK1,
      profile: OPAQUE,
    });
    expect(kindOf(wrong)).toBe("local-failure:DEK_COMMITMENT_MISMATCH");
  });

  it("33. plaintext the Data Profile rejects is not accepted, after a successful decryption", async () => {
    const r = await receiver().receive(unit({ plaintext: Uint8Array.of(0xff, 1) }).bytes);
    expect(kindOf(r)).toBe("local-failure:PROFILE_REJECTED");
  });

  it("refuses a profile codec of another data_profile", async () => {
    await expect(
      receiveDataUnit(BEFORE_ROTATION, unit().bytes, {
        seen: new InMemorySeenUnits(),
        dek: deks,
        profile: { ...OPAQUE, dataProfile: "lfcp.other.v1" },
      }),
    ).rejects.toMatchObject({ code: "DATA_PROFILE_MISMATCH" });
  });
});

describe("receiveDataUnit: the actor hash chain (§26.2, G-DP1)", () => {
  it("20. a missing previous unit is a held gap, accepted once the gap closes", async () => {
    const u1 = unit({ seq: 1n });
    const u2 = unit({ seq: 2n, prev: u1.unitId });
    const r = receiver();
    expect(kindOf(await r.receive(u2.bytes))).toBe("held:GAP");
    expect(await r.seen.acceptedAt(R, BRUNO.descriptor.principalId, actorSequence(2n))).toBe(
      undefined,
    );
    expect(kindOf(await r.receive(u1.bytes))).toBe("accepted");
    expect(kindOf(await r.receive(u2.bytes))).toBe("accepted");
  });

  it("19. a previous link to another unit is held (PREV_MISMATCH)", async () => {
    const u1 = unit({ seq: 1n });
    const u2 = unit({ seq: 2n, prev: dataUnitId(seq32(5)) });
    const r = receiver();
    await r.receive(u1.bytes);
    expect(kindOf(await r.receive(u2.bytes))).toBe("held:PREV_MISMATCH");
  });

  it("holds a previous unit at sequence 1 and a null previous after it", async () => {
    const atOne = handmade({
      dataEpoch: dataEpoch(0n),
      actorSeq: actorSequence(1n),
      prevDataUnitId: dataUnitId(seq32(5)),
      controlHead: C1,
    });
    const nullAfter = handmade({
      dataEpoch: dataEpoch(0n),
      actorSeq: actorSequence(2n),
      prevDataUnitId: null,
      controlHead: C1,
    });
    expect(kindOf(await receiver().receive(atOne.bytes))).toBe("held:PREV_AT_SEQ1");
    expect(kindOf(await receiver().receive(nullAfter.bytes))).toBe("held:NULL_PREV_AFTER_1");
  });
});

describe("receiveDataUnit: authorization at the referenced head (§26.3 rules 2-3)", () => {
  it("21, 23. data/write at the referenced head authorizes, even after a later revocation", async () => {
    // BRUNO's grant is revoked at C3; a unit made offline at C1 stays valid.
    const r = receiver(BEFORE_ROTATION);
    expect(kindOf(await r.receive(unit({ head: C1 }).bytes))).toBe("accepted");
  });

  it("22. an actor without data/write at the head is AUTHORIZATION_FAILED", async () => {
    expect(kindOf(await receiver().receive(unit({ by: CARLA, head: C2 }).bytes))).toBe(
      "rejected:AUTHORIZATION_FAILED",
    );
    // BRUNO no longer holds it at C3.
    expect(kindOf(await receiver().receive(unit({ head: C3 }).bytes))).toBe(
      "rejected:AUTHORIZATION_FAILED",
    );
  });

  it("24. a head that is not on the chain is MISSING_DEPENDENCY", async () => {
    expect(kindOf(await receiver().receive(unit({ head: seq32(3) }).bytes))).toBe(
      "rejected:MISSING_DEPENDENCY",
    );
  });
});

describe("receiveDataUnit: epochs (§26.3 rules 4-5, LFCP-023)", () => {
  it("25. a unit of the current epoch is accepted; an actor absent from a closed epoch's frontier is quarantined", async () => {
    expect(
      kindOf(
        await receiver(FULL).receive(unit({ head: C4, by: ALICE, epoch: 1n, dek: DEK1 }).bytes),
      ),
    ).toBe("accepted");
    expect(kindOf(await receiver(FULL).receive(unit({ head: G, by: ALICE }).bytes))).toBe(
      "quarantined:ACTOR_ABSENT",
    );
  });

  it("17. a new epoch does not reset the actor sequence: seq 1 again in epoch 1 is equivocation", async () => {
    const r = receiver(FULL);
    expect(kindOf(await r.receive(unit({ head: G, by: ALICE }).bytes))).toBe(
      "quarantined:ACTOR_ABSENT",
    );
    expect(kindOf(await r.receive(unit({ head: C4, by: ALICE, epoch: 1n, dek: DEK1 }).bytes))).toBe(
      "equivocation",
    );
  });

  it("26, 27. a closed epoch's unit within the frontier stays eligible; beyond it is quarantined", async () => {
    const u1 = unit({ seq: 1n });
    const u2 = unit({ seq: 2n, prev: u1.unitId });
    const u3 = unit({ seq: 3n, prev: u2.unitId });
    const r = receiver(FULL);
    expect(kindOf(await r.receive(u1.bytes))).toBe("accepted");
    expect(kindOf(await r.receive(u2.bytes))).toBe("accepted");
    const stale = await r.receive(u3.bytes);
    expect(stale).toMatchObject({
      kind: "quarantined",
      code: "STALE_DATA_EPOCH",
      reason: "BEYOND_CUTOFF",
      closedBy: C4,
    });
  });

  it("a unit claiming an epoch the head does not know is MISSING_DEPENDENCY", async () => {
    expect(kindOf(await receiver(FULL).receive(unit({ epoch: 1n, dek: DEK1 }).bytes))).toBe(
      "rejected:MISSING_DEPENDENCY",
    );
  });
});

describe("replay and equivocation (§26.2)", () => {
  it("28, 29. an exact replay is a harmless duplicate", async () => {
    const u = unit();
    const r = receiver();
    expect(kindOf(await r.receive(u.bytes))).toBe("accepted");
    expect(await r.receive(u.bytes)).toEqual({ kind: "duplicate", unitId: u.unitId });
  });

  it("30, 31. a second signature-valid unit for the same (resource, actor, seq) is equivocation; no winner is chosen", async () => {
    const a = unit({ plaintext: text("first") });
    const b = unit({ plaintext: text("second") });
    const r = receiver();
    expect(kindOf(await r.receive(a.bytes))).toBe("accepted");
    const e = await r.receive(b.bytes);
    const sorted = [a.unitId, b.unitId].map(toHex).sort();
    expect(e).toMatchObject({ kind: "equivocation", wireCode: "ACTOR_EQUIVOCATION", seq: 1n });
    if (e.kind !== "equivocation") throw new Error(e.kind);
    expect(e.unitIds.map(toHex)).toEqual(sorted);
    expect(toHex(e.accepted as DataUnitId)).toBe(toHex(a.unitId));
    // Neither unit is now taken as the plain answer: the original also reports it.
    expect((await r.receive(a.bytes)).kind).toBe("equivocation");
    expect((await r.receive(b.bytes)).kind).toBe("equivocation");
  });

  it("is equivocation whatever the units' authorization or decryptability", async () => {
    // CARLA has no data/write: both units would be refused, yet both are signature-valid.
    const a = unit({ by: CARLA, head: C2, plaintext: text("a") });
    const b = unit({ by: CARLA, head: C2, plaintext: text("b"), dek: DEK1 });
    const r = receiver();
    expect(kindOf(await r.receive(a.bytes))).toBe("rejected:AUTHORIZATION_FAILED");
    expect(kindOf(await r.receive(b.bytes))).toBe("equivocation");
  });

  it("different actors may use the same sequence", async () => {
    const r = receiver(FULL);
    expect(kindOf(await r.receive(unit({ by: ALICE, head: C4, epoch: 1n, dek: DEK1 }).bytes))).toBe(
      "accepted",
    );
    expect(kindOf(await r.receive(unit({ seq: 1n }).bytes))).toBe("accepted");
  });
});

describe("checkDataUnit: the DEK-free checks a server runs", () => {
  it("validates without a DEK or a profile and flags replays", async () => {
    const seen = new InMemorySeenUnits();
    const u = unit();
    const first = await checkDataUnit(BEFORE_ROTATION, u.bytes, seen);
    expect(first).toMatchObject({ kind: "valid", firstSeen: true });
    expect(await checkDataUnit(BEFORE_ROTATION, u.bytes, seen)).toMatchObject({
      kind: "valid",
      firstSeen: false,
    });
    expect(
      (await checkDataUnit(BEFORE_ROTATION, unit({ plaintext: text("other") }).bytes, seen)).kind,
    ).toBe("equivocation");
  });

  it("quarantines stale units and refuses unauthorized ones like the client", async () => {
    const seen = new InMemorySeenUnits();
    expect(
      (await checkDataUnit(FULL, unit({ seq: 3n, prev: dataUnitId(seq32(4)) }).bytes, seen)).kind,
    ).toBe("quarantined");
    expect(
      await checkDataUnit(
        FULL,
        unit({ head: C3, seq: 4n, prev: dataUnitId(seq32(4)) }).bytes,
        seen,
      ),
    ).toMatchObject({ kind: "rejected", wireCode: "AUTHORIZATION_FAILED" });
  });
});

describe("sequence typing", () => {
  it("18. sequences outside 1..2^64-1 are refused", () => {
    for (const s of [0n, 2n ** 64n])
      expect(() => unit({ seq: s as ActorSequence })).toThrow(
        expect.objectContaining({ code: "OUT_OF_RANGE" }),
      );
  });
});
