import { fromHex, LfcpError, toBase64url, toHex } from "@openlfcp/core";
import {
  AEAD_ChaCha20Poly1305,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from "@panva/hpke-noble";
import { CipherSuite, type KEMFactory } from "hpke";
import { describe, expect, it } from "vitest";
import {
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateResourceDEK,
  importAgreementKey,
  importResourceDEK,
  openDek,
  sealDek,
} from "../src/index.js";

// RFC 9180 Appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// ChaCha20Poly1305, Base mode (an external standard vector).
const A21 = {
  info: "4f6465206f6e2061204772656369616e2055726e",
  ikmE: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
  pkRm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  skRm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
  enc: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  sharedSecret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
  key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
  baseNonce: "5c4d98150661b848853b547f",
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad0: "436f756e742d30",
  ct0: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

/**
 * TEST ONLY: the library's X25519 KEM with its ephemeral key derived from a
 * fixed ikmE (RFC 9180 DeriveKeyPair), so Encap is reproducible. Only
 * GenerateKeyPair is replaced; Encap, the key schedule and the AEAD stay the
 * library's.
 */
const fixedEphemeral =
  (ikmE: Uint8Array): KEMFactory =>
  () => {
    const kem = KEM_DHKEM_X25519_HKDF_SHA256();
    return {
      ...kem,
      GenerateKeyPair: (extractable: boolean) => kem.DeriveKeyPair(ikmE, extractable),
    };
  };

const codeOf = async (fn: () => Promise<unknown>): Promise<string | undefined> => {
  try {
    await fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

describe("RFC 9180 A.2.1 self-test through the library (0x0020 / 0x0001 / 0x0003, Base)", () => {
  it("reproduces enc, shared_secret and the first ciphertext; key and base_nonce produce it", async () => {
    const kemFactory = fixedEphemeral(fromHex(A21.ikmE));
    const suite = new CipherSuite(kemFactory, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305);
    const pkR = await suite.DeserializePublicKey(fromHex(A21.pkRm));
    const kem = kemFactory();
    const encap = await kem.Encap(pkR);
    expect(toHex(encap.enc)).toBe(A21.enc);
    expect(toHex(encap.shared_secret)).toBe(A21.sharedSecret);

    const sealed = await suite.Seal(pkR, fromHex(A21.pt), {
      info: fromHex(A21.info),
      aad: fromHex(A21.aad0),
    });
    expect(toHex(sealed.encapsulatedSecret)).toBe(A21.enc);
    expect(toHex(sealed.ciphertext)).toBe(A21.ct0);

    // The published key and base_nonce give the same ciphertext through the AEAD (sequence 0).
    const aead = AEAD_ChaCha20Poly1305();
    const ct = await aead.Seal(
      fromHex(A21.key),
      fromHex(A21.baseNonce),
      fromHex(A21.aad0),
      fromHex(A21.pt),
    );
    expect(toHex(ct)).toBe(A21.ct0);
  });

  it("opens the published ciphertext with skRm through openDek's suite", async () => {
    const suite = new CipherSuite(
      KEM_DHKEM_X25519_HKDF_SHA256,
      KDF_HKDF_SHA256,
      AEAD_ChaCha20Poly1305,
    );
    const skR = await suite.DeserializePrivateKey(fromHex(A21.skRm), false);
    const pt = await suite.Open(skR, fromHex(A21.enc), fromHex(A21.ct0), {
      info: fromHex(A21.info),
      aad: fromHex(A21.aad0),
    });
    expect(toHex(pt)).toBe(A21.pt);
  });
});

describe("sealDek / openDek", () => {
  const info = Uint8Array.of(1, 2, 3);
  const aad = Uint8Array.of(4, 5, 6);

  it("the recipient opens the DEK it was sealed", async () => {
    const recipient = generateAgreementKeyPair();
    const dek = generateResourceDEK();
    const sealed = await sealDek(recipient.publicKey, dek, info, aad);
    expect(sealed.enc).toHaveLength(32);
    expect(sealed.ciphertext).toHaveLength(32 + 16);
    const opened = await openDek(recipient, sealed.enc, sealed.ciphertext, info, aad);
    expect(toHex(exportSecretKeyBytes(opened))).toBe(toHex(exportSecretKeyBytes(dek)));
  });

  it("17. production sealing draws a fresh ephemeral key every time", async () => {
    const recipient = generateAgreementKeyPair();
    const dek = importResourceDEK(new Uint8Array(32).fill(7));
    const a = await sealDek(recipient.publicKey, dek, info, aad);
    const b = await sealDek(recipient.publicKey, dek, info, aad);
    expect(toHex(a.enc)).not.toBe(toHex(b.enc));
    expect(toHex(a.ciphertext)).not.toBe(toHex(b.ciphertext));
  });

  it("6, 7, 8. a wrong key or tampered enc, ciphertext, info or AAD does not open", async () => {
    const recipient = generateAgreementKeyPair();
    const sealed = await sealDek(recipient.publicKey, generateResourceDEK(), info, aad);
    const flip = (b: Uint8Array) => {
      const c = Uint8Array.from(b);
      c[0] = (c[0] as number) ^ 1;
      return c;
    };
    const fails = (fn: () => Promise<unknown>) =>
      codeOf(fn).then((c) => expect(c).toBe("KEY_PACKAGE_OPEN_FAILED"));
    await fails(() =>
      openDek(generateAgreementKeyPair(), sealed.enc, sealed.ciphertext, info, aad),
    );
    await fails(() => openDek(recipient, flip(sealed.enc), sealed.ciphertext, info, aad));
    await fails(() => openDek(recipient, sealed.enc, flip(sealed.ciphertext), info, aad));
    await fails(() => openDek(recipient, sealed.enc, sealed.ciphertext, flip(info), aad));
    await fails(() => openDek(recipient, sealed.enc, sealed.ciphertext, info, flip(aad)));
  });

  it("refuses a malformed recipient public key", async () => {
    expect(await codeOf(() => sealDek(new Uint8Array(31), generateResourceDEK(), info, aad))).toBe(
      "INVALID_LENGTH",
    );
  });

  it("keeps the DEK and recipient secret out of errors", async () => {
    const secret = new Uint8Array(32).fill(0x5a);
    const recipient = importAgreementKey(secret);
    const dekBytes = new Uint8Array(32).fill(0x3c);
    const sealed = await sealDek(recipient.publicKey, importResourceDEK(dekBytes), info, aad);
    let error: unknown;
    try {
      await openDek(recipient, sealed.enc, sealed.ciphertext, info, Uint8Array.of(9));
    } catch (e) {
      error = e;
    }
    const text = [String(error), (error as Error).stack ?? "", JSON.stringify(error)].join("\n");
    for (const s of [secret, dekBytes]) {
      expect(text).not.toContain(toHex(s));
      expect(text).not.toContain(toBase64url(s));
    }
  });
});
