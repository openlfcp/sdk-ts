import {
  actorSequence,
  dataEpoch,
  LfcpError,
  principalId,
  resourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  decryptDataUnit,
  deriveActorDataKey,
  encryptDataUnit,
  exportSecretKeyBytes,
  importResourceDEK,
} from "../src/index.js";

// Synthetic values; the published D1-D4 ciphertexts are checked byte for
// byte by the conformance runner (LFCP-025).

const bytes = (from: number, length = 32) =>
  Uint8Array.from({ length }, (_, i) => (from + i) & 0xff);
const R = resourceId(bytes(1));
const A = principalId(bytes(40));
const B = principalId(bytes(80));
const dek = importResourceDEK(bytes(120));
const keyA = deriveActorDataKey(dek, R, dataEpoch(0n), A);
const keyB = deriveActorDataKey(dek, R, dataEpoch(0n), B);
const aad = Uint8Array.of(1, 2, 3);
const plaintext = Uint8Array.from("opaque profile plaintext", (c) => c.charCodeAt(0));
const seq1 = actorSequence(1n);

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

describe("Data Unit ChaCha20-Poly1305 (§12, §26)", () => {
  it("11. encrypts to ciphertext || 16-byte tag and decrypts back", () => {
    const ct = encryptDataUnit(keyA, seq1, aad, plaintext);
    expect(ct).toHaveLength(plaintext.length + 16);
    expect(toHex(decryptDataUnit(keyA, seq1, aad, ct))).toBe(toHex(plaintext));
  });

  it("is deterministic per (key, sequence): the nonce is the sequence, never random", () => {
    expect(toHex(encryptDataUnit(keyA, seq1, aad, plaintext))).toBe(
      toHex(encryptDataUnit(keyA, seq1, aad, plaintext)),
    );
    expect(toHex(encryptDataUnit(keyA, actorSequence(2n), aad, plaintext))).not.toBe(
      toHex(encryptDataUnit(keyA, seq1, aad, plaintext)),
    );
  });

  it("12, 13, 14. a changed AAD, sequence, tampered ciphertext or another actor's key fails authentication", () => {
    const ct = encryptDataUnit(keyA, seq1, aad, plaintext);
    const flipped = Uint8Array.from(ct);
    flipped[0] = (flipped[0] as number) ^ 1;
    for (const fn of [
      () => decryptDataUnit(keyA, seq1, Uint8Array.of(1, 2, 4), ct),
      () => decryptDataUnit(keyA, actorSequence(2n), aad, ct),
      () => decryptDataUnit(keyA, seq1, aad, flipped),
      () => decryptDataUnit(keyB, seq1, aad, ct),
      () => decryptDataUnit(keyA, seq1, aad, ct.subarray(0, 15)),
    ])
      expect(codeOf(fn)).toBe("AEAD_AUTHENTICATION_FAILED");
  });

  it("18. refuses a sequence outside 1..2^64-1", () => {
    for (const s of [0n, 2n ** 64n])
      expect(codeOf(() => encryptDataUnit(keyA, s as never, aad, plaintext))).toBe("OUT_OF_RANGE");
  });

  it("takes only an ActorDataKey and keeps key bytes out of errors", () => {
    expect(codeOf(() => encryptDataUnit(dek as never, seq1, aad, plaintext))).toBe(
      "CRYPTO_FAILURE",
    );
    let error: unknown;
    try {
      decryptDataUnit(keyA, seq1, aad, new Uint8Array(40));
    } catch (e) {
      error = e;
    }
    const text = [String(error), (error as Error).stack ?? "", JSON.stringify(error)].join("\n");
    const key = exportSecretKeyBytes(keyA);
    expect(text).not.toContain(toHex(key));
    expect(text).not.toContain(toBase64url(key));
  });
});
