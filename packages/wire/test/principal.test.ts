import { LfcpError, toHex } from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateSigningKeyPair,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  decodePrincipalDescriptor,
  derivePrincipalId,
  encodePrincipalDescriptor,
  principalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorFromKeys,
  principalDescriptorToCbor,
} from "../src/index.js";

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

const signing = generateSigningKeyPair();
const agreement = generateAgreementKeyPair();
const descriptor = principalDescriptorFromKeys(signing, agreement);
const bytes = encodePrincipalDescriptor(descriptor);

describe("Principal Descriptor (LFCP-WIRE-01 §7)", () => {
  it("derives the ID from both public keys and round-trips", () => {
    expect(toHex(descriptor.principalId)).toBe(
      toHex(derivePrincipalId(signing.publicKey, agreement.publicKey)),
    );
    const decoded = decodePrincipalDescriptor(bytes);
    expect(toHex(decoded.principalId)).toBe(toHex(descriptor.principalId));
    expect(toHex(decoded.ed25519PublicKey)).toBe(toHex(signing.publicKey));
    expect(toHex(decoded.x25519PublicKey)).toBe(toHex(agreement.publicKey));
  });

  it("encodes as the three-field map {0: id, 1: ed25519, 2: x25519}", () => {
    expect(toHex(bytes).slice(0, 8)).toBe("a3005820");
    expect(toHex(bytes)).toBe(
      `a3005820${toHex(descriptor.principalId)}015820${toHex(signing.publicKey)}025820${toHex(agreement.publicKey)}`,
    );
  });

  it("contains no private key material", () => {
    const text = toHex(bytes);
    expect(text).not.toContain(toHex(exportSecretKeyBytes(signing)));
    expect(text).not.toContain(toHex(exportSecretKeyBytes(agreement)));
    expect(Object.keys(descriptor).sort()).toEqual([
      "ed25519PublicKey",
      "principalId",
      "x25519PublicKey",
    ]);
  });

  it("rejects a descriptor whose ID does not match its keys", () => {
    const other = principalDescriptorFromKeys(generateSigningKeyPair(), agreement);
    const forged = cborMap([
      [0, other.principalId],
      [1, signing.publicKey],
      [2, agreement.publicKey],
    ]);
    expect(codeOf(() => principalDescriptorFromCbor(forged))).toBe("PRINCIPAL_ID_MISMATCH");
    expect(codeOf(() => decodePrincipalDescriptor(encode(forged)))).toBe("PRINCIPAL_ID_MISMATCH");
  });

  it.each([
    ["a 31-byte Ed25519 key", [1, 31]],
    ["a 33-byte X25519 key", [2, 33]],
    ["a 31-byte Principal ID", [0, 31]],
  ] as const)("rejects %s", (_name, [field, length]) => {
    const entries = principalDescriptorToCbor(descriptor).entries.map(([k, v]) =>
      k === field ? ([k, new Uint8Array(length)] as const) : ([k, v] as const),
    );
    expect(codeOf(() => principalDescriptorFromCbor(cborMap(entries)))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
    expect(codeOf(() => principalDescriptor(new Uint8Array(31), agreement.publicKey))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
  });

  it("rejects missing, extra and wrongly typed fields", () => {
    const base = principalDescriptorToCbor(descriptor).entries;
    expect(codeOf(() => principalDescriptorFromCbor(cborMap(base.slice(0, 2))))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
    expect(
      codeOf(() => principalDescriptorFromCbor(cborMap([...base, [3, new Uint8Array(1)]]))),
    ).toBe("INVALID_PRINCIPAL_DESCRIPTOR");
    expect(
      codeOf(() =>
        principalDescriptorFromCbor(cborMap([...base.slice(0, 2), ["2", agreement.publicKey]])),
      ),
    ).toBe("INVALID_PRINCIPAL_DESCRIPTOR");
    expect(codeOf(() => principalDescriptorFromCbor([...base.map(([, v]) => v)]))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
    expect(codeOf(() => principalDescriptorFromCbor(cborMap([[0, "x"], ...base.slice(1)])))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
  });

  it("rejects descriptor bytes that are not deterministic CBOR (§5.2)", () => {
    // Same map with keys 1, 0, 2: valid CBOR, wrong key order.
    const reordered = Uint8Array.from([
      0xa3,
      ...bytes.subarray(36, 71),
      ...bytes.subarray(1, 36),
      ...bytes.subarray(71),
    ]);
    expect(codeOf(() => decodeStrict(reordered))).toBe("CBOR_NON_CANONICAL");
    expect(codeOf(() => decodePrincipalDescriptor(reordered))).toBe("CBOR_NON_CANONICAL");
    expect(codeOf(() => decodePrincipalDescriptor(Uint8Array.from([...bytes, 0])))).toBe(
      "CBOR_TRAILING_BYTES",
    );
  });
});
