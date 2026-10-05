import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, concatBytes } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { LfcpError } from "@openlfcp/core";
import {
  type ActorDataKey,
  isSymmetricSecret,
  type ResourceDEK,
  type SnapshotKey,
  symmetricSecretBytes,
} from "./epoch.js";

/**
 * Key material for an LFCP Principal (LFCP-WIRE-01 §7): an Ed25519 signing
 * key and an independent X25519 key-agreement key. Neither is derived from
 * the other.
 *
 * Private bytes live only in a private class field. `toJSON`, `toString`
 * and Node's inspect hook all print "[redacted]", no enumerable property
 * holds secret bytes, and errors never include key bytes. The only way to
 * read the bytes is `exportSecretKeyBytes`.
 */

const REDACTED = "[redacted]";
const INSPECT = Symbol.for("nodejs.util.inspect.custom");
const KEY_LENGTH = 32;

function requireKeyBytes(kind: string, bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_LENGTH) {
    throw new LfcpError("INVALID_LENGTH", `${kind} must be exactly ${KEY_LENGTH} bytes`);
  }
  return Uint8Array.from(bytes);
}

/** Runs a primitive and replaces any error with one that cannot carry key material. */
function guarded<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch {
    throw new LfcpError("CRYPTO_FAILURE", `${what} failed`);
  }
}

// Module-private access, assigned in the class static blocks, so the only
// public ways in and out are the import/export functions below.
let makeSigningKeyPair: (secret: Uint8Array) => SigningKeyPair;
let readSigningSecret: (key: SigningKeyPair) => Uint8Array;
let makeAgreementKeyPair: (secret: Uint8Array) => AgreementKeyPair;
let readAgreementSecret: (key: AgreementKeyPair) => Uint8Array;

/** An Ed25519 key pair. The secret is the 32-byte RFC 8032 seed. */
export class SigningKeyPair {
  readonly #secret: Uint8Array;
  /** The 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;

  static {
    makeSigningKeyPair = (secret) =>
      new SigningKeyPair(requireKeyBytes("an Ed25519 secret key", secret));
    readSigningSecret = (key) => key.#secret;
  }

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
    this.publicKey = guarded("Ed25519 public key derivation", () => ed25519.getPublicKey(secret));
  }

  /** Ed25519 signature (64 bytes) over `message`. */
  sign(message: Uint8Array): Uint8Array {
    return guarded("Ed25519 signing", () => ed25519.sign(message, this.#secret));
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

/** An X25519 key pair. The secret is the 32-byte RFC 7748 scalar. */
export class AgreementKeyPair {
  readonly #secret: Uint8Array;
  /** The 32-byte X25519 public key. */
  readonly publicKey: Uint8Array;

  static {
    makeAgreementKeyPair = (secret) =>
      new AgreementKeyPair(requireKeyBytes("an X25519 secret key", secret));
    readAgreementSecret = (key) => key.#secret;
  }

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
    this.publicKey = guarded("X25519 public key derivation", () => x25519.getPublicKey(secret));
  }

  /**
   * X25519 shared secret with `peerPublicKey` (RFC 7748). The result is
   * secret material: treat it like a private key.
   */
  sharedSecret(peerPublicKey: Uint8Array): Uint8Array {
    if (!(peerPublicKey instanceof Uint8Array) || peerPublicKey.length !== KEY_LENGTH) {
      throw new LfcpError(
        "INVALID_LENGTH",
        `an X25519 public key must be exactly ${KEY_LENGTH} bytes`,
      );
    }
    return guarded("X25519 agreement", () => x25519.getSharedSecret(this.#secret, peerPublicKey));
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

/** A fresh Ed25519 key pair from the platform CSPRNG. */
export function generateSigningKeyPair(): SigningKeyPair {
  return makeSigningKeyPair(
    guarded("Ed25519 key generation", () => ed25519.utils.randomSecretKey()),
  );
}

/** A fresh X25519 key pair from the platform CSPRNG, independent of any signing key. */
export function generateAgreementKeyPair(): AgreementKeyPair {
  return makeAgreementKeyPair(
    guarded("X25519 key generation", () => x25519.utils.randomSecretKey()),
  );
}

/** Restores an Ed25519 key pair from its 32-byte seed. The input is copied. */
export function importSigningKey(secret: Uint8Array): SigningKeyPair {
  return makeSigningKeyPair(secret);
}

/** Restores an X25519 key pair from its 32-byte secret scalar. The input is copied. */
export function importAgreementKey(secret: Uint8Array): AgreementKeyPair {
  return makeAgreementKeyPair(secret);
}

/**
 * Returns a copy of the secret bytes of a key pair or a Data Epoch key, for
 * persistence (or, for a DEK, HPKE delivery to a recipient) only.
 *
 * WARNING: the result is secret. Never log it, put it in errors or
 * diagnostics, or send it anywhere except an encrypted local secret store.
 */
export function exportSecretKeyBytes(
  key: SigningKeyPair | AgreementKeyPair | ResourceDEK | ActorDataKey | SnapshotKey,
): Uint8Array {
  if (key instanceof SigningKeyPair) return Uint8Array.from(readSigningSecret(key));
  if (key instanceof AgreementKeyPair) return Uint8Array.from(readAgreementSecret(key));
  if (isSymmetricSecret(key)) return Uint8Array.from(symmetricSecretBytes(key));
  throw new LfcpError("CRYPTO_FAILURE", "not a secret key of this package");
}

/**
 * The X25519 secret of a key pair, for this package's HPKE module only. It
 * is not re-exported from the package index.
 */
export const agreementSecretBytes = (key: AgreementKeyPair): Uint8Array => readAgreementSecret(key);

const POINT = ed25519.Point;
/** The Ed25519 group order L. */
const L = POINT.Fn.ORDER;

/**
 * Decodes an Ed25519 point under §10.5.1 rule 2: y < p, and x = 0 with the
 * sign bit set is refused. Returns undefined for a non-canonical or
 * off-curve encoding.
 */
function decodePoint(bytes: Uint8Array): InstanceType<typeof POINT> | undefined {
  try {
    return POINT.fromBytes(bytes, false);
  } catch {
    return undefined;
  }
}

/**
 * Whether `publicKey` is a canonical Ed25519 point encoding that is not of
 * small order (LFCP-WIRE-01 §7, §10.5.1 rules 2 and 3), as required of every
 * descriptor's Ed25519 key at receipt.
 */
export function isValidEd25519PublicKey(publicKey: Uint8Array): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== KEY_LENGTH) return false;
  const a = decodePoint(publicKey);
  return a !== undefined && !a.isSmallOrder();
}

/**
 * Strict Ed25519 verification, LFCP-WIRE-01 §10.5.1. Returns false (never
 * throws) for any malformed or invalid input. The checks run in this order:
 *
 * 1. decode: A and R are canonical point encodings (y < p; x = 0 with the
 *    sign bit set is refused) — rule 2;
 * 2. S < L — rule 1;
 * 3. neither A nor R is of small order — rule 3;
 * 4. the cofactorless equation [S]B = R + [k]A, where k = SHA-512 of the
 *    exact received R bytes, the exact A bytes and M, reduced mod L — rule 4.
 *
 * noble's `ed25519.verify` is not used: it checks the cofactored equation
 * ([8][S]B = [8]R + [8][k]A) and does not refuse a small-order R, so it
 * accepts signatures §10.5.1 rejects (a mixed-order A or R, a small-order
 * R). The rules are composed here from noble's point decoding and
 * arithmetic, and R and A are never re-encoded.
 */
export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (
      !(publicKey instanceof Uint8Array) ||
      !(message instanceof Uint8Array) ||
      !(signature instanceof Uint8Array) ||
      publicKey.length !== KEY_LENGTH ||
      signature.length !== 2 * KEY_LENGTH
    )
      return false;
    const rBytes = signature.subarray(0, KEY_LENGTH);
    const a = decodePoint(publicKey);
    const r = decodePoint(rBytes);
    if (a === undefined || r === undefined) return false;
    const s = bytesToNumberLE(signature.subarray(KEY_LENGTH));
    if (s >= L) return false;
    if (a.isSmallOrder() || r.isSmallOrder()) return false;
    const k = bytesToNumberLE(sha512(concatBytes(rBytes, publicKey, message))) % L;
    return POINT.BASE.multiplyUnsafe(s).equals(r.add(a.multiplyUnsafe(k)));
  } catch {
    return false;
  }
}
