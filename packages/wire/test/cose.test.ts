import { fromHex, LfcpError, toBase64url, toHex } from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  generateSigningKeyPair,
  importAgreementKey,
  importSigningKey,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { type CborMap, type CborValue, cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  objectId,
  parseSignedObject,
  principalDescriptorFromKeys,
  type Signer,
  signObject,
  sigStructureBytes,
  verifySignedObject,
} from "../src/index.js";
import * as V from "./cose-vectors.fixtures.js";

const signer = (seed: string, x25519: string): Signer => {
  const key = importSigningKey(fromHex(seed));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(fromHex(x25519))) };
};
const OWNER = signer(V.OWNER_SEED, V.OWNER_X25519);
const BOB = signer(V.BOB_SEED, V.BOB_X25519);
const CAROL = signer(V.CAROL_SEED, V.CAROL_X25519);

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

// Sign path: published payload + fixture key -> exact published bytes (Ed25519 is deterministic).
const SIGN_CASES = [
  { id: "C0_genesis", who: OWNER, payload: V.C0_PAYLOAD, cose: V.C0_COSE, objectId: V.C0_ID },
  { id: "D1_bob_epoch0_seq1", who: BOB, payload: V.D1_PAYLOAD, cose: V.D1_COSE, objectId: V.D1_ID },
  { id: "SNAPSHOT-01", who: BOB, payload: V.S1_PAYLOAD, cose: V.S1_COSE, objectId: V.S1_ID },
];

describe.each(SIGN_CASES)("$id", (c) => {
  const signed = signObject(fromHex(c.payload), c.who);
  const parsed = parseSignedObject(fromHex(c.cose));

  it("9. signing reproduces the published COSE bytes exactly", () => {
    expect(toHex(signed.bytes)).toBe(c.cose);
  });

  it("7. the Ed25519 signature equals the vector's", () => {
    const signature = (decodeStrict(fromHex(c.cose)) as CborValue[])[3] as Uint8Array;
    expect(toHex(parsed.signature)).toBe(toHex(signature));
    expect(parsed.signature).toHaveLength(64);
  });

  it("10. the object ID is SHA-256 of the exact bytes and equals the vector's", () => {
    expect(toHex(signed.id)).toBe(c.objectId);
    expect(toHex(parsed.id)).toBe(c.objectId);
    expect(toHex(objectId(fromHex(c.cose)))).toBe(c.objectId);
  });

  it("8, 15. the object is an untagged four-element array", () => {
    expect(signed.bytes[0]).toBe(0x84);
    expect((signed.bytes[0] as number) >> 5).not.toBe(6);
    expect(decodeStrict(signed.bytes)).toHaveLength(4);
  });

  it("2, 3, 5. protected = {1: -8, 4: kid}, unprotected = {}, payload present", () => {
    const [prot, unprot, payload] = decodeStrict(signed.bytes) as CborValue[];
    const header = decodeStrict(prot as Uint8Array) as CborMap;
    expect(header.entries.map(([k]) => k)).toEqual([1, 4]);
    expect(header.entries[0]?.[1]).toBe(-8);
    expect(toHex(header.entries[1]?.[1] as Uint8Array)).toBe(toHex(c.who.descriptor.principalId));
    expect((unprot as CborMap).entries).toHaveLength(0);
    expect(toHex(payload as Uint8Array)).toBe(c.payload);
    expect(toHex(parsed.payloadBytes)).toBe(c.payload);
    expect(toHex(parsed.kid)).toBe(toHex(c.who.descriptor.principalId));
  });

  it("11. the published object verifies under its signer", () => {
    expect(verifySignedObject(parsed, c.who.descriptor)).toEqual({ valid: true });
  });

  it("12. a modified payload fails verification", () => {
    const payload = Uint8Array.from(parsed.payloadBytes);
    payload[payload.length - 1] = (payload[payload.length - 1] as number) ^ 1;
    expect(verifySignedObject({ ...parsed, payloadBytes: payload }, c.who.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("13. a modified signature fails verification", () => {
    const signature = Uint8Array.from(parsed.signature);
    signature[0] = (signature[0] as number) ^ 1;
    expect(verifySignedObject({ ...parsed, signature }, c.who.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("14. a different expected signer fails on kid", () => {
    const other = c.who === OWNER ? BOB : OWNER;
    expect(verifySignedObject(parsed, other.descriptor)).toEqual({
      valid: false,
      reason: "KID_MISMATCH",
    });
  });
});

describe("1, 4, 6. exact header and Sig_structure bytes", () => {
  it.each([
    ["C0_genesis", V.C0_PROTECTED, V.C0_SIG_STRUCTURE, V.C0_COSE],
    ["SNAPSHOT-01", V.S1_PROTECTED, V.S1_SIG_STRUCTURE, V.S1_COSE],
  ])("%s", (_id, protectedHex, sigStructureHex, coseHex) => {
    const parsed = parseSignedObject(fromHex(coseHex));
    expect(toHex(parsed.protectedBytes)).toBe(protectedHex);
    expect(toHex(sigStructureBytes(parsed.protectedBytes, parsed.payloadBytes))).toBe(
      sigStructureHex,
    );
    // External AAD is the empty byte string (§10.4): third element of Sig_structure.
    const structure = decodeStrict(fromHex(sigStructureHex)) as CborValue[];
    expect(structure[0]).toBe("Signature1");
    expect(structure[2]).toEqual(new Uint8Array(0));
  });
});

describe("published negative vectors", () => {
  it("invalid_signature_D1: parses, signature fails", () => {
    const parsed = parseSignedObject(fromHex(V.INVALID_SIGNATURE_D1));
    expect(verifySignedObject(parsed, BOB.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("tampered_D1: parses, signature fails", () => {
    const parsed = parseSignedObject(fromHex(V.TAMPERED_D1));
    expect(verifySignedObject(parsed, BOB.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("wrong_kid_D1: kid is CAROL, so it fails for the expected signer BOB", () => {
    const parsed = parseSignedObject(fromHex(V.WRONG_KID_D1));
    expect(toHex(parsed.kid)).toBe(toHex(CAROL.descriptor.principalId));
    expect(verifySignedObject(parsed, BOB.descriptor)).toEqual({
      valid: false,
      reason: "KID_MISMATCH",
    });
    // The COSE layer alone would accept CAROL; requiring the actor as signer is the Data Unit rule (LFCP-016).
    expect(verifySignedObject(parsed, CAROL.descriptor)).toEqual({ valid: true });
  });

  it("15. tagged_cose_D1: tag 18 is rejected", () => {
    expect(V.TAGGED_COSE_D1.slice(0, 2)).toBe("d2");
    expect(codeOf(() => parseSignedObject(fromHex(V.TAGGED_COSE_D1)))).toBe("COSE_MALFORMED");
  });

  it("noncanonical_payload_D1: rejected by the §5.2 payload check", () => {
    expect(codeOf(() => parseSignedObject(fromHex(V.NONCANONICAL_PAYLOAD_D1)))).toBe(
      "CBOR_NON_CANONICAL",
    );
  });
});

describe("synthetic malformed objects", () => {
  const good = decodeStrict(fromHex(V.D1_COSE)) as CborValue[];
  const [prot, unprot, payload, signature] = good as [Uint8Array, CborMap, Uint8Array, Uint8Array];
  const kid = (decodeStrict(prot) as CborMap).entries[1]?.[1] as Uint8Array;
  const build = (items: CborValue[]): Uint8Array => encode(items);

  it.each([
    [
      "extra protected parameter",
      () => [
        encode(
          cborMap([
            [1, -8],
            [4, kid],
            [3, 0],
          ]),
        ),
        unprot,
        payload,
        signature,
      ],
    ],
    ["protected missing kid", () => [encode(cborMap([[1, -8]])), unprot, payload, signature]],
    [
      "wrong alg",
      () => [
        encode(
          cborMap([
            [1, -7],
            [4, kid],
          ]),
        ),
        unprot,
        payload,
        signature,
      ],
    ],
    [
      "31-byte kid",
      () => [
        encode(
          cborMap([
            [1, -8],
            [4, kid.subarray(1)],
          ]),
        ),
        unprot,
        payload,
        signature,
      ],
    ],
    [
      "protected as a map, not bytes",
      () => [
        cborMap([
          [1, -8],
          [4, kid],
        ]),
        unprot,
        payload,
        signature,
      ],
    ],
    ["non-empty unprotected", () => [prot, cborMap([[4, kid]]), payload, signature]],
    ["detached (nil) payload", () => [prot, unprot, null, signature]],
    ["63-byte signature", () => [prot, unprot, payload, signature.subarray(1)]],
    ["three elements", () => [prot, unprot, payload]],
    ["five elements", () => [prot, unprot, payload, signature, signature]],
  ] as [string, () => CborValue[]][])("%s -> COSE_MALFORMED", (_name, make) => {
    expect(codeOf(() => parseSignedObject(build(make())))).toBe("COSE_MALFORMED");
  });

  it("rejects non-deterministic protected-header bytes", () => {
    // {1: -8, 4: kid} with the alg encoded as 0x38 0x07 instead of 0x27.
    const loose = Uint8Array.from([0xa2, 0x01, 0x38, 0x07, ...prot.subarray(3)]);
    expect(codeOf(() => parseSignedObject(build([loose, unprot, payload, signature])))).toBe(
      "CBOR_NON_CANONICAL",
    );
  });

  it("reports the specific CBOR error of a malformed payload", () => {
    // {1: 1, 1: 1}: a duplicate key; and a payload with trailing bytes.
    const duplicate = Uint8Array.from([0xa2, 0x01, 0x01, 0x01, 0x01]);
    expect(codeOf(() => parseSignedObject(build([prot, unprot, duplicate, signature])))).toBe(
      "CBOR_DUPLICATE_KEY",
    );
    const trailing = Uint8Array.from([...payload, 0x00]);
    expect(codeOf(() => parseSignedObject(build([prot, unprot, trailing, signature])))).toBe(
      "CBOR_TRAILING_BYTES",
    );
  });

  it("rejects trailing bytes and a non-array", () => {
    expect(codeOf(() => parseSignedObject(Uint8Array.from([...fromHex(V.D1_COSE), 0])))).toBe(
      "CBOR_TRAILING_BYTES",
    );
    expect(codeOf(() => parseSignedObject(encode(cborMap([]))))).toBe("COSE_MALFORMED");
  });

  it("keeps the exact received bytes", () => {
    const input = fromHex(V.D1_COSE);
    const parsed = parseSignedObject(input);
    input.fill(0);
    expect(toHex(parsed.bytes)).toBe(V.D1_COSE);
  });
});

describe("signObject guards", () => {
  it("refuses a key that does not belong to the descriptor", () => {
    expect(
      codeOf(() =>
        signObject(fromHex(V.D1_PAYLOAD), { key: OWNER.key, descriptor: BOB.descriptor }),
      ),
    ).toBe("COSE_SIGNER_MISMATCH");
  });

  it("refuses payload bytes that are not deterministic CBOR, without re-encoding them", () => {
    expect(codeOf(() => signObject(Uint8Array.from([0x18, 0x01]), BOB))).toBe("CBOR_NON_CANONICAL");
    expect(codeOf(() => signObject(Uint8Array.from([0xff]), BOB))).toBe("CBOR_NON_CANONICAL");
  });

  it("signs fresh keys and round-trips", () => {
    const key = generateSigningKeyPair();
    const fresh: Signer = {
      key,
      descriptor: principalDescriptorFromKeys(key, importAgreementKey(fromHex(V.BOB_X25519))),
    };
    const signed = signObject(encode(cborMap([[0, "x"]])), fresh);
    expect(verifySignedObject(parseSignedObject(signed.bytes), fresh.descriptor)).toEqual({
      valid: true,
    });
  });

  it("never puts secret key bytes into errors", () => {
    const secret = toHex(exportSecretKeyBytes(BOB.key));
    const forms = [secret, toBase64url(fromHex(secret))];
    const errors: unknown[] = [];
    for (const attempt of [
      () => signObject(fromHex(V.D1_PAYLOAD), { key: BOB.key, descriptor: OWNER.descriptor }),
      () => signObject(Uint8Array.from([0x18, 0x01]), BOB),
    ]) {
      try {
        attempt();
      } catch (e) {
        errors.push(e);
      }
    }
    expect(errors).toHaveLength(2);
    for (const e of errors) {
      const text = [String(e), (e as Error).stack ?? "", JSON.stringify(e)].join("\n");
      for (const form of forms) expect(text).not.toContain(form);
    }
  });
});
