import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { LfcpError } from "@openlfcp/core";

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
 * Returns a copy of the private key bytes, for persistence only.
 *
 * WARNING: the result is secret. Never log it, put it in errors or
 * diagnostics, or send it anywhere except an encrypted local secret store.
 */
export function exportSecretKeyBytes(key: SigningKeyPair | AgreementKeyPair): Uint8Array {
  return Uint8Array.from(
    key instanceof SigningKeyPair ? readSigningSecret(key) : readAgreementSecret(key),
  );
}

/** Verifies an Ed25519 signature. Returns false (never throws) for malformed input. */
export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
