import { fromHex, LfcpError, toBase64url, toHex } from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  generateSigningKeyPair,
  importAgreementKey,
  sha256,
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
import { ALICE, BRUNO, DATA_UNIT, DATA_UNIT_PAYLOAD, seq32 } from "./synthetic.js";

// Byte-exact agreement with the published vectors (signing, IDs, headers,
// Sig_structure, negatives) is checked by the conformance runner (LFCP-017).

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

describe("a signed synthetic object", () => {
  const signed = DATA_UNIT;
  const parsed = parseSignedObject(signed.bytes);

  it("9. signing is deterministic (Ed25519, deterministic CBOR)", () => {
    expect(toHex(signObject(DATA_UNIT_PAYLOAD, ALICE).bytes)).toBe(toHex(signed.bytes));
  });

  it("7. the signature is 64 bytes and survives parsing", () => {
    const signature = (decodeStrict(signed.bytes) as CborValue[])[3] as Uint8Array;
    expect(toHex(parsed.signature)).toBe(toHex(signature));
    expect(parsed.signature).toHaveLength(64);
  });

  it("10. the object ID is SHA-256 of the exact bytes", () => {
    expect(toHex(signed.id)).toBe(toHex(sha256(signed.bytes)));
    expect(toHex(parsed.id)).toBe(toHex(signed.id));
    expect(toHex(objectId(signed.bytes))).toBe(toHex(signed.id));
  });

  it("8, 15. the object is an untagged four-element array", () => {
    expect(signed.bytes[0]).toBe(0x84);
    expect(decodeStrict(signed.bytes)).toHaveLength(4);
  });

  it("1, 2, 3, 5. protected = {1: -8, 4: kid} exactly, unprotected = {}, payload present", () => {
    const [prot, unprot, payload] = decodeStrict(signed.bytes) as CborValue[];
    // a2 01 27 04 58 20 <kid>: map(2), 1 => -8, 4 => bstr(32).
    expect(toHex(prot as Uint8Array)).toBe(`a20127045820${toHex(ALICE.descriptor.principalId)}`);
    expect(toHex(parsed.protectedBytes)).toBe(toHex(prot as Uint8Array));
    expect((unprot as CborMap).entries).toHaveLength(0);
    expect(toHex(payload as Uint8Array)).toBe(toHex(DATA_UNIT_PAYLOAD));
    expect(toHex(parsed.payloadBytes)).toBe(toHex(DATA_UNIT_PAYLOAD));
    expect(toHex(parsed.kid)).toBe(toHex(ALICE.descriptor.principalId));
  });

  it("4, 6. Sig_structure is [\"Signature1\", protected, h'', payload]", () => {
    const structure = decodeStrict(
      sigStructureBytes(parsed.protectedBytes, parsed.payloadBytes),
    ) as CborValue[];
    expect(structure[0]).toBe("Signature1");
    expect(toHex(structure[1] as Uint8Array)).toBe(toHex(parsed.protectedBytes));
    expect(structure[2]).toEqual(new Uint8Array(0));
    expect(toHex(structure[3] as Uint8Array)).toBe(toHex(parsed.payloadBytes));
  });

  it("11. verifies under its signer", () => {
    expect(verifySignedObject(parsed, ALICE.descriptor)).toEqual({ valid: true });
  });

  it("12. a modified payload fails verification", () => {
    const payload = Uint8Array.from(parsed.payloadBytes);
    payload[payload.length - 1] = (payload[payload.length - 1] as number) ^ 1;
    expect(verifySignedObject({ ...parsed, payloadBytes: payload }, ALICE.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("13. a modified signature fails verification", () => {
    const signature = Uint8Array.from(parsed.signature);
    signature[0] = (signature[0] as number) ^ 1;
    expect(verifySignedObject({ ...parsed, signature }, ALICE.descriptor)).toEqual({
      valid: false,
      reason: "BAD_SIGNATURE",
    });
  });

  it("14. a different expected signer fails on kid; the same payload under another kid verifies only for that kid", () => {
    expect(verifySignedObject(parsed, BRUNO.descriptor)).toEqual({
      valid: false,
      reason: "KID_MISMATCH",
    });
    const other = parseSignedObject(signObject(DATA_UNIT_PAYLOAD, BRUNO).bytes);
    expect(verifySignedObject(other, ALICE.descriptor)).toEqual({
      valid: false,
      reason: "KID_MISMATCH",
    });
    expect(verifySignedObject(other, BRUNO.descriptor)).toEqual({ valid: true });
  });
});

describe("synthetic malformed objects", () => {
  const [prot, unprot, payload, signature] = decodeStrict(DATA_UNIT.bytes) as [
    Uint8Array,
    CborMap,
    Uint8Array,
    Uint8Array,
  ];
  const kid = ALICE.descriptor.principalId;
  const build = (items: CborValue[]): Uint8Array => encode(items);

  it("15. tag 18 is rejected", () => {
    expect(codeOf(() => parseSignedObject(Uint8Array.from([0xd2, ...DATA_UNIT.bytes])))).toBe(
      "COSE_MALFORMED",
    );
  });

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

  it("rejects a payload with a non-shortest integer (N7)", () => {
    // Field 1 (data epoch 0) as 0x18 0x00: after the map head, key 0 and the 32-byte resource ID.
    expect(payload[36]).toBe(0x01);
    expect(payload[37]).toBe(0x00);
    const loose = Uint8Array.from([...payload.subarray(0, 37), 0x18, ...payload.subarray(37)]);
    expect(codeOf(() => parseSignedObject(build([prot, unprot, loose, signature])))).toBe(
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
    expect(codeOf(() => parseSignedObject(Uint8Array.from([...DATA_UNIT.bytes, 0])))).toBe(
      "CBOR_TRAILING_BYTES",
    );
    expect(codeOf(() => parseSignedObject(encode(cborMap([]))))).toBe("COSE_MALFORMED");
  });

  it("keeps the exact received bytes", () => {
    const input = Uint8Array.from(DATA_UNIT.bytes);
    const parsed = parseSignedObject(input);
    input.fill(0);
    expect(toHex(parsed.bytes)).toBe(toHex(DATA_UNIT.bytes));
  });
});

describe("signObject guards", () => {
  it("refuses a key that does not belong to the descriptor", () => {
    expect(
      codeOf(() => signObject(DATA_UNIT_PAYLOAD, { key: ALICE.key, descriptor: BRUNO.descriptor })),
    ).toBe("COSE_SIGNER_MISMATCH");
  });

  it("refuses payload bytes that are not deterministic CBOR, without re-encoding them", () => {
    expect(codeOf(() => signObject(Uint8Array.from([0x18, 0x01]), ALICE))).toBe(
      "CBOR_NON_CANONICAL",
    );
    expect(codeOf(() => signObject(Uint8Array.from([0xff]), ALICE))).toBe("CBOR_NON_CANONICAL");
  });

  it("signs fresh keys and round-trips", () => {
    const key = generateSigningKeyPair();
    const fresh: Signer = {
      key,
      descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(7))),
    };
    const signed = signObject(encode(cborMap([[0, "x"]])), fresh);
    expect(verifySignedObject(parseSignedObject(signed.bytes), fresh.descriptor)).toEqual({
      valid: true,
    });
  });

  it("never puts secret key bytes into errors", () => {
    const secret = toHex(exportSecretKeyBytes(ALICE.key));
    const forms = [secret, toBase64url(fromHex(secret))];
    const errors: unknown[] = [];
    for (const attempt of [
      () => signObject(DATA_UNIT_PAYLOAD, { key: ALICE.key, descriptor: BRUNO.descriptor }),
      () => signObject(Uint8Array.from([0x18, 0x01]), ALICE),
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
