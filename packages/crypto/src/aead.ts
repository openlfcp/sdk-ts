import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { type ActorSequence, LfcpError } from "@openlfcp/core";
import { ActorDataKey, dataUnitNonce, symmetricSecretBytes } from "./epoch.js";

/**
 * ChaCha20-Poly1305 for Data Units (LFCP-WIRE-01 §9, §12, §26), from
 * @noble/ciphers. The functions take the ActorDataKey itself, so the key
 * bytes never leave this package, and derive the nonce from the actor
 * sequence (0x00000000 || uint64_be(seq), §12): there is no random nonce
 * and no way to pass another one.
 *
 * The sequence must come from the writer's ActorSequenceReservation
 * (@openlfcp/storage, §8): a sequence used twice under one actor key reuses
 * a nonce. Use createDataUnit (@openlfcp/client) rather than these
 * building blocks.
 *
 * Errors never include key, plaintext or ciphertext bytes.
 */

const TAG_LENGTH = 16;

function keyBytes(key: ActorDataKey): Uint8Array {
  if (!(key instanceof ActorDataKey))
    throw new LfcpError("CRYPTO_FAILURE", "expected an ActorDataKey");
  return symmetricSecretBytes(key);
}

/** ciphertext || 16-byte tag of `plaintext` under the actor key, the sequence nonce and `aad` (§26). */
export function encryptDataUnit(
  key: ActorDataKey,
  seq: ActorSequence,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = dataUnitNonce(seq);
  const k = Uint8Array.from(keyBytes(key));
  try {
    return chacha20poly1305(k, nonce, aad).encrypt(plaintext);
  } catch {
    throw new LfcpError("CRYPTO_FAILURE", "ChaCha20-Poly1305 encryption failed");
  } finally {
    k.fill(0);
  }
}

/**
 * The plaintext of `ciphertext` (ciphertext || tag). Any authentication
 * failure (wrong key, sequence, AAD or tampered bytes) is
 * AEAD_AUTHENTICATION_FAILED: client-local, no wire code (§26.3, ADR 0001 N3).
 */
export function decryptDataUnit(
  key: ActorDataKey,
  seq: ActorSequence,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const nonce = dataUnitNonce(seq);
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < TAG_LENGTH)
    throw new LfcpError("AEAD_AUTHENTICATION_FAILED", "the ciphertext is shorter than the tag");
  const k = Uint8Array.from(keyBytes(key));
  try {
    return chacha20poly1305(k, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new LfcpError(
      "AEAD_AUTHENTICATION_FAILED",
      "the Data Unit does not authenticate under this key, sequence and AAD",
    );
  } finally {
    k.fill(0);
  }
}
