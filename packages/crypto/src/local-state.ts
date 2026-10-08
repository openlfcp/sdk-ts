import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { LfcpError } from "@openlfcp/core";

/**
 * Local state encrypted at rest (LFCP-02-098; .github
 * docs/devel/design/local-state-encryption.md §3, §4).
 *
 * A device keeps one local state key per install, in its SecretStore, and
 * seals the records that hold profile text (checkpoints, section journals)
 * before they reach the disk. An envelope is
 *
 *   "lse1" || generation (uint32 BE) || nonce (24 bytes) || ciphertext || tag (16 bytes)
 *
 * under XChaCha20-Poly1305 with a random nonce per write, safe at any write
 * count: local rows need no nonce counter. The AEAD's associated data is the
 * envelope's first 8 bytes (magic and generation) followed by the caller's
 * AAD, which binds the row to its install, store and key, so a row cannot be
 * swapped with another one or moved to another install, and its generation
 * cannot be altered.
 *
 * Like every key in this package, the key keeps its bytes in a private field
 * and prints as "[redacted]"; the only way out is `exportLocalStateKey`, for
 * the SecretStore. Errors never include key, plaintext or envelope bytes.
 */

const MAGIC = Uint8Array.from([0x6c, 0x73, 0x65, 0x31]); // "lse1"
const HEADER_LENGTH = 8;
const NONCE_LENGTH = 24;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const REDACTED = "[redacted]";
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

let readKey: (key: LocalStateKey) => Uint8Array;

/** The 32-byte local state key of one install and generation. */
export class LocalStateKey {
  readonly #bytes: Uint8Array;

  static {
    readKey = (key) => key.#bytes;
  }

  private constructor(bytes: Uint8Array) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_LENGTH)
      throw new LfcpError("INVALID_LENGTH", `a local state key is exactly ${KEY_LENGTH} bytes`);
    this.#bytes = Uint8Array.from(bytes);
  }

  /** A fresh key from the platform CSPRNG. */
  static generate(): LocalStateKey {
    const bytes = randomBytes(KEY_LENGTH);
    try {
      return new LocalStateKey(bytes);
    } finally {
      bytes.fill(0);
    }
  }

  /** The key stored in a SecretStore. */
  static import(bytes: Uint8Array): LocalStateKey {
    return new LocalStateKey(bytes);
  }

  toJSON(): string {
    return REDACTED;
  }

  toString(): string {
    return REDACTED;
  }

  [INSPECT](): string {
    return REDACTED;
  }
}

/** A copy of the key bytes, for the SecretStore only. */
export function exportLocalStateKey(key: LocalStateKey): Uint8Array {
  if (!(key instanceof LocalStateKey))
    throw new LfcpError("CRYPTO_FAILURE", "expected a LocalStateKey");
  return Uint8Array.from(readKey(key));
}

/** Whether `bytes` is an envelope: the magic, and room for its header, nonce and tag. */
export function isSealedLocal(bytes: Uint8Array): boolean {
  return (
    bytes instanceof Uint8Array &&
    bytes.length >= HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH &&
    MAGIC.every((b, i) => bytes[i] === b)
  );
}

/** The generation an envelope was sealed with, or undefined when `bytes` is not one. */
export function localEnvelopeGeneration(bytes: Uint8Array): number | undefined {
  if (!isSealedLocal(bytes)) return undefined;
  return new DataView(bytes.buffer, bytes.byteOffset, HEADER_LENGTH).getUint32(4);
}

const header = (generation: number): Uint8Array => {
  if (!Number.isInteger(generation) || generation < 1 || generation > 0xffffffff)
    throw new LfcpError("UNSUPPORTED_VALUE", "a local state generation is an integer in [1, 2^32)");
  const out = new Uint8Array(HEADER_LENGTH);
  out.set(MAGIC);
  new DataView(out.buffer).setUint32(4, generation);
  return out;
};

const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

/** The envelope of `plaintext` under `key` of `generation`, bound to `aad`. */
export function sealLocal(
  key: LocalStateKey,
  generation: number,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const head = header(generation);
  const nonce = randomBytes(NONCE_LENGTH);
  const k = Uint8Array.from(exportLocalStateKey(key));
  try {
    const sealed = xchacha20poly1305(k, nonce, concat(head, aad)).encrypt(plaintext);
    const out = new Uint8Array(HEADER_LENGTH + NONCE_LENGTH + sealed.length);
    out.set(head);
    out.set(nonce, HEADER_LENGTH);
    out.set(sealed, HEADER_LENGTH + NONCE_LENGTH);
    return out;
  } catch {
    throw new LfcpError("CRYPTO_FAILURE", "XChaCha20-Poly1305 encryption failed");
  } finally {
    k.fill(0);
  }
}

/**
 * The plaintext of `envelope`, sealed under `key` and bound to `aad`. A wrong
 * key, AAD or generation, or tampered bytes, is AEAD_AUTHENTICATION_FAILED.
 */
export function openLocal(key: LocalStateKey, aad: Uint8Array, envelope: Uint8Array): Uint8Array {
  if (!isSealedLocal(envelope))
    throw new LfcpError("AEAD_AUTHENTICATION_FAILED", "not a local state envelope");
  const head = envelope.subarray(0, HEADER_LENGTH);
  const nonce = envelope.subarray(HEADER_LENGTH, HEADER_LENGTH + NONCE_LENGTH);
  const k = Uint8Array.from(exportLocalStateKey(key));
  try {
    return xchacha20poly1305(k, nonce, concat(head, aad)).decrypt(
      envelope.subarray(HEADER_LENGTH + NONCE_LENGTH),
    );
  } catch {
    throw new LfcpError(
      "AEAD_AUTHENTICATION_FAILED",
      "the local state envelope does not authenticate under this key and AAD",
    );
  } finally {
    k.fill(0);
  }
}

/**
 * The local state cipher for @openlfcp/storage's LocalStateKeyring
 * (`LocalStateCipher`): storage adapters take it from the application, so
 * the storage packages do no cryptography and the key bytes stay here.
 */
export const localStateCipher = Object.freeze({
  generateKey: (): LocalStateKey => LocalStateKey.generate(),
  importKey: (bytes: Uint8Array): LocalStateKey => LocalStateKey.import(bytes),
  exportKey: (key: LocalStateKey): Uint8Array => exportLocalStateKey(key),
  seal: sealLocal,
  open: openLocal,
  isSealed: isSealedLocal,
  generationOf: localEnvelopeGeneration,
});
