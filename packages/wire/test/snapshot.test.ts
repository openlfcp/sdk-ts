import { type ControlRecordId, dataEpoch, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  deriveSnapshotKey,
  encryptSnapshot,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  sha256,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  type ActorHave,
  type ChainResult,
  type ControlBody,
  checkSnapshot,
  type DataProfileCodec,
  encodeSnapshotPayload,
  normalizeLiveHaves,
  parseSnapshot,
  principalDescriptorFromKeys,
  receiveSnapshot,
  type Signer,
  type SnapshotAadFields,
  sealSnapshot,
  signControlRecord,
  signObject,
  snapshotAad,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic chains and Snapshots; SNAPSHOT-01 and SNAPSHOT-02 are re-created
// byte for byte by the conformance runner.

const CARLA: Signer = (() => {
  const key = importSigningKey(seq32(65));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(165))) };
})();
const R = resourceId(seq32(200));
const PROFILE = "org.example.custom.v1";
const DEK0 = importResourceDEK(seq32(90));
const DEK1 = importResourceDEK(seq32(91));

// G (owner ALICE) <- C1 grant BRUNO data/read + snapshot/publish <- C2 grant CARLA data/read
//   <- C3 KEY_EPOCH 1 (epoch 0 closed with BRUNO contiguous 2)
const records: { bytes: Uint8Array; id: ControlRecordId }[] = [];
function add(body: ControlBody): ControlRecordId {
  const prev = records[records.length - 1];
  const s = signControlRecord(
    {
      resourceId: R,
      controlSeq: BigInt(records.length),
      prevControlId: prev === undefined ? null : prev.id,
    },
    body,
    ALICE,
  );
  records.push({ bytes: s.bytes, id: s.recordId });
  return s.recordId;
}
add({
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
  abilities: [1n, 3n],
  delegable: [],
});
const C2 = add({
  type: "CAPABILITY_GRANT",
  subject: CARLA.descriptor,
  abilities: [1n],
  delegable: [],
});
const C3 = add({
  type: "KEY_EPOCH",
  epoch: dataEpoch(1n),
  dekCommitment: dekCommitment(R, dataEpoch(1n), DEK1),
  finalFrontier: [{ principalId: BRUNO.descriptor.principalId, contiguous: 2n, extras: [] }],
  reason: 0n,
});
type View = Extract<ChainResult, { kind: "linear" }>;
const viewThrough = (n: number): View => {
  const r = validateControlChain(records.slice(0, n).map((x) => x.bytes));
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
};
const BEFORE = viewThrough(3);
const AFTER = viewThrough(4);

const OPAQUE: DataProfileCodec<Uint8Array> = {
  dataProfile: PROFILE,
  encode: (v) => Uint8Array.from(v),
  decode: (p) => {
    if (p[0] === 0xff) throw new Error("refused");
    return Uint8Array.from(p);
  },
};
const B = BRUNO.descriptor.principalId;
const frontierOf = (...entries: [Uint8Array, bigint, [bigint, bigint][]?][]) =>
  normalizeLiveHaves(
    entries.map(([id, contiguous, ranges]) => ({
      principalId: principalId(id),
      contiguous,
      ...(ranges ? { ranges } : {}),
    })),
  );
const snap = (
  o: {
    by?: Signer;
    seq?: bigint;
    head?: Uint8Array;
    epoch?: bigint;
    dek?: typeof DEK0;
    frontier?: readonly ActorHave[];
    plaintext?: Uint8Array;
  } = {},
) =>
  sealSnapshot(
    {
      resourceId: R,
      dataEpoch: dataEpoch(o.epoch ?? 0n),
      snapshotSeq: o.seq ?? 1n,
      controlHead: (o.head ?? C1) as ControlRecordId,
      frontier: o.frontier ?? frontierOf([B, 2n]),
    },
    o.plaintext ?? Uint8Array.of(1, 2, 3),
    o.dek ?? DEK0,
    o.by ?? BRUNO,
  );
const deks = (e: bigint) => (e === 0n ? DEK0 : e === 1n ? DEK1 : undefined);
const receive = (bytes: Uint8Array, view: View = BEFORE) =>
  receiveSnapshot(view, bytes, { dek: deks, profile: OPAQUE });
const kindOf = (r: { kind: string; reason?: string; wireCode?: string }) =>
  r.kind === "rejected"
    ? `rejected:${r.wireCode}`
    : r.kind === "local-failure"
      ? `local:${r.reason}`
      : r.kind;

/** A Snapshot whose ciphertext was sealed under `sealedAs` AAD fields but whose payload says `fields`. */
function mismatched(fields: SnapshotAadFields, sealedAs: Partial<SnapshotAadFields>) {
  const key = deriveSnapshotKey(DEK0, R, fields.dataEpoch, fields.publisher);
  const ct = encryptSnapshot(
    key,
    fields.snapshotSeq,
    snapshotAad({ ...fields, ...sealedAs }),
    Uint8Array.of(7),
  );
  return signObject(encodeSnapshotPayload({ ...fields, ciphertext: ct }), BRUNO).bytes;
}
const baseFields = (): SnapshotAadFields => ({
  resourceId: R,
  dataEpoch: dataEpoch(0n),
  publisher: B,
  snapshotSeq: 1n,
  controlHead: C1,
  frontier: frontierOf([B, 2n]),
});

describe("canonical frontier and exact AAD (§28.2, §29.1.3)", () => {
  it("1, 2. empty and multi-actor frontiers are canonical", () => {
    for (const frontier of [
      [],
      frontierOf([seq32(250), 1n], [B, 2n, [[5n, 6n]]], [seq32(1), 7n]),
    ]) {
      const s = snap({ frontier });
      expect(parseSnapshot(s.bytes).payload.frontier).toEqual(frontier);
    }
  });

  it("3, 4. a non-canonical order or a duplicate actor is refused, by the writer and the receiver", () => {
    const sorted = frontierOf([seq32(1), 1n], [seq32(250), 1n]);
    const reversed = [...sorted].reverse();
    expect(() => snap({ frontier: reversed })).toThrow(
      expect.objectContaining({ code: "INVALID_STRUCTURE" }),
    );
    const dup = [sorted[0], sorted[0]] as ActorHave[];
    expect(() => snap({ frontier: dup })).toThrow(
      expect.objectContaining({ code: "INVALID_STRUCTURE" }),
    );
    // A received payload with an unsorted frontier, signed: MALFORMED_MESSAGE, never re-normalized.
    const s = snap();
    const p = parseSnapshot(s.bytes).payload;
    const raw = encode(
      cborMap([
        [0, p.resourceId],
        [1, 0],
        [2, p.publisher],
        [3, 1],
        [4, p.controlHead],
        [
          5,
          reversed.map((h) =>
            cborMap([
              [0, h.principalId],
              [1, h.contiguous],
            ]),
          ),
        ],
        [6, p.ciphertext],
      ]),
    );
    expect(checkSnapshot(BEFORE, signObject(raw, BRUNO).bytes)).toMatchObject({
      kind: "rejected",
      wireCode: "MALFORMED_MESSAGE",
    });
  });

  it("8. the AAD is exactly the seven-element §29.1.3 array", () => {
    const f = baseFields();
    expect(toHex(snapshotAad(f))).toBe(
      toHex(
        encode([
          "LFCP-SNAPSHOT-v1",
          R,
          0,
          B,
          1,
          C1,
          [
            cborMap([
              [0, B],
              [1, 2],
            ]),
          ],
        ]),
      ),
    );
  });

  it("10, 11. the Snapshot is the publisher's COSE_Sign1; its ID is SHA-256 of the exact bytes", () => {
    const s = snap();
    expect(toHex(parseSnapshot(s.bytes).signed.kid)).toBe(toHex(B));
    expect(toHex(s.snapshotId)).toBe(toHex(sha256(s.bytes)));
  });
});

describe("receiveSnapshot (§29, §29.1.4, §29.2)", () => {
  it("12, 18. a valid Snapshot decrypts and opaque plaintext round-trips", async () => {
    const plaintext = Uint8Array.from({ length: 500 }, (_, i) => (i * 13) & 0xfe);
    const r = await receive(snap({ plaintext }).bytes);
    if (r.kind !== "accepted") throw new Error(kindOf(r));
    expect(toHex(r.value)).toBe(toHex(plaintext));
    expect([r.seq, r.epoch]).toEqual([1n, 0n]);
  });

  it("the bytes for the server do not contain the plaintext", () => {
    const plaintext = Uint8Array.from("a private snapshot of application state", (c) =>
      c.charCodeAt(0),
    );
    expect(toHex(snap({ plaintext }).bytes)).not.toContain(toHex(plaintext.subarray(0, 12)));
  });

  it("13, 14. a ciphertext sealed under another frontier or Control Head fails AEAD (client-local)", async () => {
    const f = baseFields();
    expect(kindOf(await receive(mismatched(f, { frontier: frontierOf([B, 1n]) })))).toBe(
      "local:AEAD",
    );
    expect(kindOf(await receive(mismatched(f, { controlHead: C2 })))).toBe("local:AEAD");
  });

  it("15. a wrong DEK fails: sealed under another epoch's DEK it does not authenticate", async () => {
    expect(kindOf(await receive(snap({ dek: DEK1 }).bytes))).toBe("local:AEAD");
    const none = await receiveSnapshot(BEFORE, snap().bytes, {
      dek: () => undefined,
      profile: OPAQUE,
    });
    expect(kindOf(none)).toBe("local:NO_DEK");
    const wrong = await receiveSnapshot(BEFORE, snap().bytes, { dek: () => DEK1, profile: OPAQUE });
    expect(kindOf(wrong)).toBe("local:DEK_COMMITMENT_MISMATCH");
  });

  it("16. a tampered signature is INVALID_SIGNATURE; a payload re-signed by another Principal too", async () => {
    const bytes = Uint8Array.from(snap().bytes);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] as number) ^ 1;
    expect(kindOf(await receive(bytes))).toBe("rejected:INVALID_SIGNATURE");
    const payload = parseSnapshot(snap().bytes).signed.payloadBytes;
    expect(kindOf(await receive(signObject(payload, CARLA).bytes))).toBe(
      "rejected:INVALID_SIGNATURE",
    );
  });

  it("the profile's Snapshot codec may refuse the plaintext after decryption", async () => {
    expect(kindOf(await receive(snap({ plaintext: Uint8Array.of(0xff) }).bytes))).toBe(
      "local:PROFILE_REJECTED",
    );
  });

  it("§29.2: snapshot/publish at the referenced head; the head and epoch must be known", async () => {
    expect(kindOf(await receive(snap({ by: CARLA, head: C2 }).bytes))).toBe(
      "rejected:AUTHORIZATION_FAILED",
    );
    expect(kindOf(await receive(snap({ head: seq32(3) }).bytes))).toBe(
      "rejected:MISSING_DEPENDENCY",
    );
    expect(kindOf(await receive(snap({ epoch: 1n, dek: DEK1 }).bytes, AFTER))).toBe(
      "rejected:MISSING_DEPENDENCY",
    ); // epoch 1 is unknown at C1
    expect(kindOf(await receive(snap({ epoch: 1n, dek: DEK1, head: C3 }).bytes, AFTER))).toBe(
      "accepted",
    );
  });

  it("PROVISIONAL G-EP4: after epoch 0 closes, a Snapshot may cover only its final frontier", async () => {
    expect(kindOf(await receive(snap({ frontier: frontierOf([B, 2n]) }).bytes, AFTER))).toBe(
      "accepted",
    );
    for (const frontier of [frontierOf([B, 3n]), frontierOf([B, 2n], [seq32(1), 1n])])
      expect(checkSnapshot(AFTER, snap({ frontier }).bytes)).toMatchObject({
        kind: "rejected",
        reason: "BEYOND_CUTOFF",
        wireCode: "STALE_DATA_EPOCH",
      });
    // The same Snapshot before the rotation is fine.
    expect(kindOf(await receive(snap({ frontier: frontierOf([B, 3n]) }).bytes, BEFORE))).toBe(
      "accepted",
    );
  });

  it("Snapshot Sequence 0 is refused by the writer and the receiver (§29, W5)", () => {
    expect(() => snap({ seq: 0n })).toThrow(expect.objectContaining({ code: "OUT_OF_RANGE" }));
    const p = parseSnapshot(snap().bytes).payload;
    const raw = encode(
      cborMap([
        [0, p.resourceId],
        [1, 0],
        [2, p.publisher],
        [3, 0],
        [4, p.controlHead],
        [
          5,
          [
            cborMap([
              [0, B],
              [1, 2],
            ]),
          ],
        ],
        [6, p.ciphertext],
      ]),
    );
    expect(checkSnapshot(BEFORE, signObject(raw, BRUNO).bytes)).toMatchObject({
      wireCode: "MALFORMED_MESSAGE",
    });
  });

  it("refuses a profile codec of another data_profile", async () => {
    await expect(
      receiveSnapshot(BEFORE, snap().bytes, {
        dek: deks,
        profile: { ...OPAQUE, dataProfile: "x" },
      }),
    ).rejects.toMatchObject({ code: "DATA_PROFILE_MISMATCH" });
  });
});
