// TEST ONLY: reproduces a published Key Package seal from its raw ephemeral
// private key (LFCP-024). It is never part of @openlfcp/* and is never
// reachable from sealKeyPackage, which always draws a fresh ephemeral key.
//
// The baseline.2 vectors publish the raw skE, not the RFC 9180 ikmE. The
// library's X25519 DHKEM gets its ephemeral key pair from
// this.GenerateKeyPair(), so replacing only that method makes Encap use the
// published skE; Encap itself, the key schedule and the AEAD stay the
// library's. With baseline.3 (decision G-KP2: vectors publish ikmE), switch
// to the public DeriveKeyPair(ikmE) and delete this wrapper.

import { importAgreementKey } from "@openlfcp/crypto";
import {
  AEAD_ChaCha20Poly1305,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from "@panva/hpke-noble";
import { CipherSuite, type KEMFactory } from "hpke";

function fixedEphemeral(skE: Uint8Array): KEMFactory {
  return () => {
    const kem = KEM_DHKEM_X25519_HKDF_SHA256();
    return {
      ...kem,
      GenerateKeyPair: async (extractable: boolean) => ({
        privateKey: await kem.DeserializePrivateKey(skE, extractable),
        publicKey: await kem.DeserializePublicKey(importAgreementKey(skE).publicKey),
      }),
    };
  };
}

export interface RawSkESeal {
  readonly enc: Uint8Array;
  readonly sharedSecret: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** HPKE Base seal of `plaintext` to `recipientPublicKey` with the given ephemeral secret. */
export async function sealWithRawSkE(
  skE: Uint8Array,
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<RawSkESeal> {
  const kemFactory = fixedEphemeral(skE);
  const suite = new CipherSuite(kemFactory, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305);
  const pkR = await suite.DeserializePublicKey(recipientPublicKey);
  const { shared_secret } = await kemFactory().Encap(pkR);
  const sealed = await suite.Seal(pkR, plaintext, { info, aad });
  return {
    enc: sealed.encapsulatedSecret,
    sharedSecret: shared_secret,
    ciphertext: sealed.ciphertext,
  };
}

/** The suite's AEAD with an explicit key and nonce (sequence 0), to check a published key and base_nonce. */
export const aeadSeal = (
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
) => AEAD_ChaCha20Poly1305().Seal(key, nonce, aad, plaintext);
