import { LfcpError } from "@openlfcp/core";
import {
  AEAD_ChaCha20Poly1305,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from "@panva/hpke-noble";
import { CipherSuite } from "hpke";
import { importResourceDEK, type ResourceDEK, symmetricSecretBytes } from "./epoch.js";
import { type AgreementKeyPair, agreementSecretBytes } from "./keys.js";

/**
 * RFC 9180 HPKE for LFCP Key Packages (LFCP-WIRE-01 §9, §25): Base mode
 * with DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001 and
 * ChaCha20-Poly1305 0x0003. The protocol is the `hpke` library's; the
 * primitives are the audited noble packages through @panva/hpke-noble.
 *
 * The plaintext is exactly the 32-byte DEK. Sealing always draws a fresh
 * ephemeral key from the platform CSPRNG; there is no way to pass one in.
 * Secrets (the DEK, the recipient key, the ephemeral key, the shared
 * secret) never appear in errors.
 */

const SUITE = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305);
const KEY_LENGTH = 32;

/** HPKE output: the encapsulated key (enc) and the ciphertext of the DEK. */
export interface SealedDek {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** Seals `dek` to the recipient's X25519 public key with `info` and `aad` (§25.1). */
export async function sealDek(
  recipientPublicKey: Uint8Array,
  dek: ResourceDEK,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<SealedDek> {
  if (!(recipientPublicKey instanceof Uint8Array) || recipientPublicKey.length !== KEY_LENGTH)
    throw new LfcpError("INVALID_LENGTH", "an X25519 public key must be exactly 32 bytes");
  const plaintext = Uint8Array.from(symmetricSecretBytes(dek));
  try {
    const pk = await SUITE.DeserializePublicKey(Uint8Array.from(recipientPublicKey));
    const sealed = await SUITE.Seal(pk, plaintext, { info, aad });
    return Object.freeze({ enc: sealed.encapsulatedSecret, ciphertext: sealed.ciphertext });
  } catch {
    throw new LfcpError("CRYPTO_FAILURE", "HPKE seal failed");
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Opens an HPKE-sealed DEK with the recipient's X25519 key pair. Any
 * failure (wrong key, tampered enc, ciphertext, info or AAD, or a
 * plaintext that is not 32 bytes) is KEY_PACKAGE_OPEN_FAILED, client-local
 * (ADR 0001 N5).
 */
export async function openDek(
  recipient: AgreementKeyPair,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<ResourceDEK> {
  let plaintext: Uint8Array;
  try {
    const sk = await SUITE.DeserializePrivateKey(
      Uint8Array.from(agreementSecretBytes(recipient)),
      false,
    );
    plaintext = await SUITE.Open(sk, enc, ciphertext, { info, aad });
  } catch {
    throw new LfcpError(
      "KEY_PACKAGE_OPEN_FAILED",
      "the Key Package does not open with this recipient key",
    );
  }
  try {
    if (plaintext.length !== KEY_LENGTH)
      throw new LfcpError(
        "KEY_PACKAGE_OPEN_FAILED",
        "the Key Package plaintext is not a 32-byte DEK",
      );
    return importResourceDEK(plaintext);
  } finally {
    plaintext.fill(0);
  }
}
