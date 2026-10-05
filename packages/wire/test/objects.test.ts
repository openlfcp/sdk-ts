import { bytesEqual, fromHex, LfcpError, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey, sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { type CborMap, type CborValue, cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  actorHaveFromCbor,
  CONTROL_TYPE,
  canonicalFrontierFromCbor,
  controlRecordPayloadFromCbor,
  dataUnitPayloadFromCbor,
  decodeDataUnitPayload,
  endpointFromCbor,
  expectedSignerOf,
  keyPackagePayloadFromCbor,
  parseDataUnit,
  principalDescriptorFromKeys,
  type Signer,
  signObject,
  sigStructureBytes,
  verifySignedObject,
} from "../src/index.js";
import * as K from "./cose-vectors.fixtures.js";
import * as V from "./payload-vectors.fixtures.js";

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};
const signer = (seed: string, x25519: string): Signer => {
  const key = importSigningKey(fromHex(seed));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(fromHex(x25519))) };
};
const BOB = signer(K.BOB_SEED, K.BOB_X25519);
const CAROL = signer(K.CAROL_SEED, K.CAROL_X25519);

const D1 = fromHex(V.D1_COSE);
const D1_PAYLOAD = fromHex(V.D1_PAYLOAD);
const [D1_PROTECTED, , , D1_SIGNATURE] = decodeStrict(D1) as [
  Uint8Array,
  unknown,
  Uint8Array,
  Uint8Array,
];
const D1_FIELDS = (decodeStrict(D1_PAYLOAD) as CborMap).entries as readonly [number, CborValue][];

/** A COSE_Sign1 array from parts; parsing does not check the signature. */
const cose = (
  protectedBytes: CborValue,
  unprotected: CborValue,
  payload: CborValue,
  sig: CborValue,
) => encode([protectedBytes, unprotected, payload, sig]);
/** Raw CBOR map bytes with entries in the given order (may be non-deterministic). */
const rawMap = (entries: readonly (readonly [CborValue, CborValue])[]): Uint8Array => {
  const parts = entries.flatMap(([k, v]) => [encode(k), encode(v)]);
  const out = new Uint8Array(1 + parts.reduce((n, p) => n + p.length, 0));
  out[0] = 0xa0 + entries.length;
  let at = 1;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
/** The D1 payload with field `key` replaced (or removed with `undefined`), re-encoded deterministically. */
const d1With = (key: number, value: CborValue | undefined): CborValue =>
  cborMap(
    D1_FIELDS.flatMap(([k, v]): [number, CborValue][] =>
      k !== key ? [[k, v]] : value === undefined ? [] : [[k, value]],
    ),
  );
const d1Cose = (payload: CborValue) =>
  cose(D1_PROTECTED, cborMap([]), encode(payload), D1_SIGNATURE);
const protectedWith = (entries: [number, CborValue][]) => encode(cborMap(entries));

describe("LFCP-016 prompt tests, at the typed Data Unit layer", () => {
  it("1. a valid canonical signed object parses (D1_bob_epoch0_seq1)", () => {
    const { signed, payload } = parseDataUnit(D1);
    expect(payload.kind).toBe("data-unit");
    expect(toHex(signed.id)).toBe(V.D1_ID);
  });

  it("2. COSE tag 18 is rejected", () => {
    expect(codeOf(() => parseDataUnit(fromHex(V.TAGGED_COSE_D1)))).toBe("COSE_MALFORMED");
  });

  it("3. a non-canonical integer encoding is rejected (noncanonical_payload_D1: seq 1 as 18 01)", () => {
    expect(codeOf(() => parseDataUnit(fromHex(V.NONCANONICAL_PAYLOAD_D1)))).toBe(
      "CBOR_NON_CANONICAL",
    );
  });

  it("4. non-deterministic map ordering is rejected", () => {
    const reversed = rawMap([...D1_FIELDS].reverse());
    expect(
      codeOf(() => parseDataUnit(cose(D1_PROTECTED, cborMap([]), reversed, D1_SIGNATURE))),
    ).toBe("CBOR_NON_CANONICAL");
    expect(codeOf(() => decodeDataUnitPayload(reversed))).toBe("CBOR_NON_CANONICAL");
  });

  it("5. a duplicate map key is rejected", () => {
    const dup = rawMap([...D1_FIELDS, D1_FIELDS[6] as [number, CborValue]]);
    expect(codeOf(() => parseDataUnit(cose(D1_PROTECTED, cborMap([]), dup, D1_SIGNATURE)))).toBe(
      "CBOR_DUPLICATE_KEY",
    );
  });

  it("6. a malformed protected header is rejected (CDDL fixture: a descriptor as the header)", () => {
    const bad = cose(fromHex(V.OWNER_DESCRIPTOR), cborMap([]), D1_PAYLOAD, D1_SIGNATURE);
    expect(codeOf(() => parseDataUnit(bad))).toBe("COSE_MALFORMED");
    const notBstr = cose(cborMap([[1, -8]]), cborMap([]), D1_PAYLOAD, D1_SIGNATURE);
    expect(codeOf(() => parseDataUnit(notBstr))).toBe("COSE_MALFORMED");
  });

  it("7. an additional protected field is rejected", () => {
    const kid = (decodeStrict(D1_PROTECTED) as CborMap).entries[1]?.[1];
    const extra = protectedWith([
      [1, -8],
      [3, 0],
      [4, kid as Uint8Array],
    ]);
    expect(codeOf(() => parseDataUnit(cose(extra, cborMap([]), D1_PAYLOAD, D1_SIGNATURE)))).toBe(
      "COSE_MALFORMED",
    );
  });

  it("8. a non-empty unprotected map is rejected", () => {
    const bad = cose(D1_PROTECTED, cborMap([[4, new Uint8Array(32)]]), D1_PAYLOAD, D1_SIGNATURE);
    expect(codeOf(() => parseDataUnit(bad))).toBe("COSE_MALFORMED");
  });

  it("9. a missing (detached) payload is rejected", () => {
    expect(codeOf(() => parseDataUnit(cose(D1_PROTECTED, cborMap([]), null, D1_SIGNATURE)))).toBe(
      "COSE_MALFORMED",
    );
    expect(codeOf(() => parseDataUnit(encode([D1_PROTECTED, cborMap([]), D1_SIGNATURE])))).toBe(
      "COSE_MALFORMED",
    );
  });

  it("10. a wrong signature length is rejected", () => {
    for (const n of [0, 63, 65]) {
      const bad = cose(D1_PROTECTED, cborMap([]), D1_PAYLOAD, new Uint8Array(n));
      expect(codeOf(() => parseDataUnit(bad))).toBe("COSE_MALFORMED");
    }
  });

  it("11. a malformed Principal ID is rejected, in the kid and in the payload", () => {
    const shortKid = protectedWith([
      [1, -8],
      [4, new Uint8Array(31)],
    ]);
    expect(codeOf(() => parseDataUnit(cose(shortKid, cborMap([]), D1_PAYLOAD, D1_SIGNATURE)))).toBe(
      "COSE_MALFORMED",
    );
    for (const actor of [new Uint8Array(31), new Uint8Array(33), "bob", null]) {
      expect(codeOf(() => parseDataUnit(d1Cose(d1With(2, actor))))).toBe("INVALID_STRUCTURE");
    }
  });

  it("12. the object ID is SHA-256 of the exact received bytes", () => {
    const { signed } = parseDataUnit(D1);
    expect(toHex(signed.id)).toBe(toHex(sha256(D1)));
    expect(toHex(signed.id)).toBe(V.D1_ID);
  });

  it("13. verification uses the received header and payload bytes, not a re-encoding", () => {
    const { signed } = parseDataUnit(D1);
    // The parsed byte strings are the exact slices of the received object.
    const at = (part: Uint8Array) =>
      D1.findIndex((_, i) => bytesEqual(D1.subarray(i, i + part.length), part));
    expect(at(signed.protectedBytes)).toBeGreaterThan(0);
    expect(at(signed.payloadBytes)).toBeGreaterThan(at(signed.protectedBytes));
    expect(toHex(signed.payloadBytes)).toBe(V.D1_PAYLOAD);
    expect(verifySignedObject(signed, BOB.descriptor)).toEqual({ valid: true });
    // A Sig_structure over a different payload encoding does not verify, so a
    // verifier that re-encoded could not stay compatible with the signer.
    const reEncoded = rawMap([...D1_FIELDS].reverse());
    expect(
      BOB.key
        .sign(sigStructureBytes(signed.protectedBytes, reEncoded))
        .every((b, i) => b === signed.signature[i]),
    ).toBe(false);
  });

  it("14. byte-different objects over the same payload get different IDs", () => {
    // Ed25519 is deterministic: re-signing D1's payload as Bob gives D1's bytes again.
    expect(toHex(signObject(D1_PAYLOAD, BOB).bytes)).toBe(V.D1_COSE);
    // The same payload under another kid and signature is a different object (wrong_kid_D1).
    const wrongKid = parseDataUnit(fromHex(V.WRONG_KID_D1));
    expect(toHex(wrongKid.signed.payloadBytes)).toBe(V.D1_PAYLOAD);
    expect(toHex(wrongKid.signed.id)).toBe(toHex(sha256(fromHex(V.WRONG_KID_D1))));
    expect(toHex(wrongKid.signed.id)).not.toBe(V.D1_ID);
    const byCarol = signObject(D1_PAYLOAD, CAROL);
    expect(toHex(parseDataUnit(byCarol.bytes).signed.id)).toBe(toHex(byCarol.id));
    expect(toHex(byCarol.id)).not.toBe(V.D1_ID);
    // ... and only the actor's signature is accepted (INVALID_SIGNATURE otherwise).
    expect(
      verifySignedObject(wrongKid.signed, BOB.descriptor).valid ||
        verifySignedObject(parseDataUnit(byCarol.bytes).signed, BOB.descriptor).valid,
    ).toBe(false);
    // The only other encoding of the same values is non-canonical and is rejected.
    expect(codeOf(() => parseDataUnit(fromHex(V.NONCANONICAL_PAYLOAD_D1)))).toBe(
      "CBOR_NON_CANONICAL",
    );
  });
});

describe("expectedSignerOf", () => {
  it("is the Data Unit actor; wrong_kid_D1 fails against it with KID_MISMATCH", () => {
    const { signed, payload } = parseDataUnit(fromHex(V.WRONG_KID_D1));
    expect(toHex(expectedSignerOf(payload))).toBe(toHex(BOB.descriptor.principalId));
    expect(toHex(signed.kid)).toBe(toHex(CAROL.descriptor.principalId));
    expect(verifySignedObject(signed, BOB.descriptor)).toEqual({
      valid: false,
      reason: "KID_MISMATCH",
    });
  });
});

describe("payload structure", () => {
  const id = (b: number) => new Uint8Array(32).fill(b);
  const control = (over: Record<number, CborValue | undefined> = {}) => {
    const base: [number, CborValue][] = [
      [0, id(1)],
      [1, 3],
      [2, id(2)],
      [3, 1],
      [4, id(3)],
      [5, cborMap([[0, "body"]])],
    ];
    return cborMap(
      base.flatMap(([k, v]): [number, CborValue][] =>
        !(k in over) ? [[k, v]] : over[k] === undefined ? [] : [[k, over[k] as CborValue]],
      ),
    );
  };

  it("data-unit: actor sequence 0 is INVALID_STRUCTURE (§8, N4); sequence 1 with a link is kept for §26.2 reporting", () => {
    expect(codeOf(() => dataUnitPayloadFromCbor(d1With(3, 0)))).toBe("INVALID_STRUCTURE");
    expect(dataUnitPayloadFromCbor(d1With(4, id(9))).actorSeq).toBe(1n);
  });

  it("data-unit: missing, extra, negative and wrong-type fields are INVALID_STRUCTURE", () => {
    const D1_MAP = decodeStrict(D1_PAYLOAD);
    expect(dataUnitPayloadFromCbor(D1_MAP).kind).toBe("data-unit");
    for (const bad of [
      d1With(6, undefined),
      cborMap([...D1_FIELDS, [7, 0]]),
      cborMap([...D1_FIELDS.slice(1), ["0", id(1)]]),
      d1With(1, -1),
      d1With(3, "1"),
      d1With(4, id(9).subarray(1)),
      d1With(5, null),
      d1With(6, "ciphertext"),
      [1, 2],
    ]) {
      expect(codeOf(() => dataUnitPayloadFromCbor(bad))).toBe("INVALID_STRUCTURE");
    }
  });

  it("data-unit: unsigned integers above 2^53 decode exactly", () => {
    const big = 2n ** 64n - 1n;
    expect(dataUnitPayloadFromCbor(d1With(1, big)).dataEpoch).toBe(big);
  });

  it("key-package: the payload fields and their types", () => {
    const kp = cborMap([
      [0, id(1)],
      [1, 0],
      [2, id(2)],
      [3, id(3)],
      [4, id(4)],
      [5, new Uint8Array(32)],
      [6, new Uint8Array(48)],
    ]);
    const p = keyPackagePayloadFromCbor(kp);
    expect(toHex(expectedSignerOf(p))).toBe(toHex(id(4)));
    expect(codeOf(() => keyPackagePayloadFromCbor(cborMap([[0, id(1)]])))).toBe(
      "INVALID_STRUCTURE",
    );
  });

  it("control-record: the generic payload keeps the body opaque", () => {
    const p = controlRecordPayloadFromCbor(control());
    expect(p.controlType).toBe(CONTROL_TYPE.CAPABILITY_GRANT);
    expect(p.body).toEqual(cborMap([[0, "body"]]));
    expect(toHex(p.issuer)).toBe(toHex(id(3)));
    expect(codeOf(() => controlRecordPayloadFromCbor(control({ 5: undefined })))).toBe(
      "INVALID_STRUCTURE",
    );
    expect(codeOf(() => controlRecordPayloadFromCbor(control({ 2: id(2).subarray(1) })))).toBe(
      "INVALID_STRUCTURE",
    );
  });

  it("control-record: reserved core types 9-31 are UNSUPPORTED_VALUE; 32+ are kept as extensions (§14)", () => {
    for (const t of [9, 31])
      expect(codeOf(() => controlRecordPayloadFromCbor(control({ 3: t })))).toBe(
        "UNSUPPORTED_VALUE",
      );
    for (const t of [32, 1000]) {
      const p = controlRecordPayloadFromCbor(control({ 3: t }));
      expect(p.extension).toBe(true);
    }
    expect(controlRecordPayloadFromCbor(control({ 3: 8 })).extension).toBe(false);
  });

  it("control-record: Genesis must be at control_seq 0 with a null link (§13.1)", () => {
    expect(controlRecordPayloadFromCbor(control({ 1: 0, 2: null, 3: 0 })).controlSeq).toBe(0n);
    expect(codeOf(() => controlRecordPayloadFromCbor(control({ 1: 1, 2: null, 3: 0 })))).toBe(
      "INVALID_STRUCTURE",
    );
    expect(codeOf(() => controlRecordPayloadFromCbor(control({ 1: 0, 3: 0 })))).toBe(
      "INVALID_STRUCTURE",
    );
  });
});

describe("actor-have and canonical frontier (§28.1, §28.2)", () => {
  const pid = (b: number) => new Uint8Array(32).fill(b);
  const have = (p: number, contiguous: number, ranges?: number[][]) =>
    cborMap(
      ranges === undefined
        ? [
            [0, pid(p)],
            [1, contiguous],
          ]
        : [
            [0, pid(p)],
            [1, contiguous],
            [2, ranges],
          ],
    );

  it("accepts canonical forms", () => {
    expect(actorHaveFromCbor(have(1, 7)).extras).toEqual([]);
    expect(
      actorHaveFromCbor(
        have(1, 100, [
          [105, 107],
          [109, 109],
        ]),
      ).extras,
    ).toEqual([
      [105n, 107n],
      [109n, 109n],
    ]);
    expect(canonicalFrontierFromCbor([])).toEqual([]);
    expect(canonicalFrontierFromCbor([have(1, 1), have(2, 0), have(0xff, 3)]).length).toBe(3);
  });

  it.each([
    ["key 2 present and empty (rule 2)", have(1, 7, [])],
    ["range start > end (rule 4)", have(1, 100, [[107, 105]])],
    ["range at contiguous (rule 5)", have(1, 100, [[100, 101]])],
    ["range below contiguous (rule 5)", have(1, 100, [[95, 107]])],
    [
      "unsorted (rule 6)",
      have(1, 100, [
        [110, 112],
        [105, 107],
      ]),
    ],
    [
      "overlapping (rule 7)",
      have(1, 100, [
        [105, 107],
        [106, 110],
      ]),
    ],
    [
      "adjacent (rule 8)",
      have(1, 100, [
        [105, 107],
        [108, 110],
      ]),
    ],
    ["range not a pair", have(1, 100, [[105]])],
    ["negative bound", have(1, 100, [[105, -1]])],
    ["missing key 1 (rule 1)", cborMap([[0, pid(1)]])],
    [
      "extra key 3",
      cborMap([
        [0, pid(1)],
        [1, 1],
        [3, 0],
      ]),
    ],
  ])("rejects %s with INVALID_STRUCTURE", (_, value) => {
    expect(codeOf(() => actorHaveFromCbor(value))).toBe("INVALID_STRUCTURE");
  });

  it("rejects duplicate (rule 9) and unsorted (§28.2) frontier entries", () => {
    expect(codeOf(() => canonicalFrontierFromCbor([have(1, 1), have(1, 2)]))).toBe(
      "INVALID_STRUCTURE",
    );
    expect(codeOf(() => canonicalFrontierFromCbor([have(2, 1), have(1, 2)]))).toBe(
      "INVALID_STRUCTURE",
    );
    expect(codeOf(() => canonicalFrontierFromCbor(cborMap([])))).toBe("INVALID_STRUCTURE");
  });
});

describe("endpoint (§16)", () => {
  it("decodes url, priority and optional flags", () => {
    expect(
      endpointFromCbor(
        cborMap([
          [0, "wss://a.test/v1/ws"],
          [1, 0],
        ]),
      ),
    ).toEqual({
      url: "wss://a.test/v1/ws",
      priority: 0n,
    });
    expect(
      endpointFromCbor(
        cborMap([
          [0, "wss://a"],
          [1, 2],
          [2, 63],
        ]),
      ).flags,
    ).toBe(63n);
  });

  it.each([
    ["missing priority", cborMap([[0, "wss://a"]])],
    [
      "url not text",
      cborMap([
        [0, new Uint8Array(1)],
        [1, 0],
      ]),
    ],
    [
      "negative priority",
      cborMap([
        [0, "wss://a"],
        [1, -1],
      ]),
    ],
    [
      "extra field",
      cborMap([
        [0, "wss://a"],
        [1, 0],
        [3, 0],
      ]),
    ],
    ["not a map", ["wss://a", 0]],
  ])("rejects %s with INVALID_STRUCTURE", (_, value) => {
    expect(codeOf(() => endpointFromCbor(value as CborValue))).toBe("INVALID_STRUCTURE");
  });
});
