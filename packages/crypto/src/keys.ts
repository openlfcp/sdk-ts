import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, concatBytes } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesEqual, fromHex, LfcpError } from "@openlfcp/core";
import {
  type AsyncEd25519Verify,
  detectNativeEd25519,
  detectWebCryptoEd25519,
  type NativeEd25519Verify,
} from "./ed25519-native.js";
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

/** p = 2^255 − 19, the field modulus. */
const P_FIELD = POINT.Fp.ORDER;
const Y_MASK = (1n << 255n) - 1n;
/**
 * The y-coordinates of the eight small-order points (orders 1, 2, 4, 8).
 * A canonical encoding is of small order iff its y (sign bit cleared) is
 * one of these; x = 0 occurs only for y = ±1, which are in the set.
 */
const SMALL_ORDER_Y: ReadonlySet<bigint> = (() => {
  /** A point of order 8. */
  const t8 = POINT.fromBytes(
    fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    false,
  );
  const ys = new Set<bigint>();
  for (let i = 0n, q = POINT.ZERO; i < 8n; i++, q = q.add(t8)) {
    ys.add(bytesToNumberLE(q.toBytes()) & Y_MASK);
  }
  return ys;
})();

/**
 * Rules 2 and 3 on the encoding alone, without decompressing the point:
 * y < p, and y is not that of a small-order point (which also covers x = 0
 * with the sign bit set). An off-curve encoding passes here; the native
 * equation check refuses it (A does not decode; R cannot match [S]B − [k]A).
 */
function passesEncodingRules(bytes: Uint8Array): boolean {
  const y = bytesToNumberLE(bytes) & Y_MASK;
  return y < P_FIELD && !SMALL_ORDER_Y.has(y);
}

/** Rules 1–3 on the bytes of A and of the signature (R ‖ S). */
function passesRules1to3(publicKey: Uint8Array, signature: Uint8Array): boolean {
  return (
    passesEncodingRules(publicKey) &&
    passesEncodingRules(signature.subarray(0, KEY_LENGTH)) &&
    bytesToNumberLE(signature.subarray(KEY_LENGTH)) < L
  );
}

/** undefined: not detected yet; null: no trustworthy native backend. */
let nativeVerify: NativeEd25519Verify | null | undefined;

function nativeBackend(): NativeEd25519Verify | null {
  if (nativeVerify === undefined) nativeVerify = detectNativeEd25519();
  return nativeVerify;
}

/** The WebCrypto backend: undefined until detection starts, then its result. */
let webVerify: Promise<AsyncEd25519Verify | null> | undefined;
/** Whether WebCrypto detection found a trustworthy backend; undefined until it settles. */
let webDetected: boolean | undefined;

function webBackend(): Promise<AsyncEd25519Verify | null> {
  if (webVerify === undefined) {
    webVerify = detectWebCryptoEd25519().then((verify) => {
      webDetected = verify !== null;
      return verify;
    });
  }
  return webVerify;
}

/** Bound on pre-verified answers; the map is cleared when it is full. */
const PREPARED_LIMIT = 4096;
/** WebCrypto answers by A ‖ R ‖ S, with the message they were given for. */
const prepared = new Map<string, { readonly message: Uint8Array; readonly valid: boolean }>();
const preparedId = (publicKey: Uint8Array, signature: Uint8Array) =>
  String.fromCharCode(...publicKey, ...signature);

/**
 * Test hook (not exported from the package index): replaces the native
 * backend. null forces the noble path; undefined re-runs detection.
 */
export function setNativeEd25519ForTesting(verify: NativeEd25519Verify | null | undefined): void {
  nativeVerify = verify;
}

/**
 * Test hook (not exported from the package index): replaces the WebCrypto
 * backend. null disables it; undefined re-runs detection. Clears the
 * pre-verified answers.
 */
export function setWebCryptoEd25519ForTesting(verify: AsyncEd25519Verify | null | undefined): void {
  webVerify = verify === undefined ? undefined : Promise.resolve(verify);
  webDetected = verify === undefined ? undefined : verify !== null;
  prepared.clear();
}

/**
 * Which backend `verifyEd25519` currently uses (detecting the synchronous
 * native one if needed): "webcrypto" once WebCrypto detection has found one
 * (see `detectEd25519Backend`) and there is no synchronous native backend.
 */
export function ed25519Backend(): "native" | "webcrypto" | "noble" {
  if (nativeBackend() !== null) return "native";
  return webDetected === true ? "webcrypto" : "noble";
}

/** Like `ed25519Backend`, after running WebCrypto detection if it is needed. */
export async function detectEd25519Backend(): Promise<"native" | "webcrypto" | "noble"> {
  if (nativeBackend() === null) await webBackend();
  return ed25519Backend();
}

/**
 * Pre-verifies a signature with WebCrypto's Ed25519, for runtimes without a
 * synchronous native backend (browsers, mobile WebViews). WebCrypto is
 * asynchronous only, so the async receive steps call this before the
 * synchronous `verifyEd25519`, which then uses the answer once instead of
 * the noble equation. Rules 1–3 are checked here first, exactly as on the
 * native path, and WebCrypto is trusted only after it reproduced the
 * known-answer probes (detected once). Never throws; when there is a
 * synchronous native backend, no trustworthy WebCrypto, or WebCrypto
 * rejects (e.g. "unsupported"), it records nothing and noble decides.
 */
export async function prepareEd25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  try {
    if (
      !(publicKey instanceof Uint8Array) ||
      !(message instanceof Uint8Array) ||
      !(signature instanceof Uint8Array) ||
      publicKey.length !== KEY_LENGTH ||
      signature.length !== 2 * KEY_LENGTH ||
      nativeBackend() !== null ||
      !passesRules1to3(publicKey, signature)
    )
      return;
    const web = await webBackend();
    if (web === null) return;
    const a = Uint8Array.from(publicKey);
    const m = Uint8Array.from(message);
    const sig = Uint8Array.from(signature);
    const valid = (await web(a, m, sig)) === true;
    if (prepared.size >= PREPARED_LIMIT) prepared.clear();
    prepared.set(preparedId(a, sig), { message: m, valid });
  } catch {
    // e.g. an "unsupported" rejection: nothing recorded, noble decides.
  }
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
 * Where the platform has a native Ed25519 that passes the known-answer
 * probes of ed25519-native.ts (Node's crypto), rules 1–3 are checked here
 * on the encodings and rule 4 is delegated to it; if it throws, the noble
 * path decides. Without it, an answer `prepareEd25519Verify` obtained from
 * WebCrypto for these exact bytes is used (once). All paths give the same
 * answer for every input.
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
    const native = nativeBackend();
    if (native !== null) {
      if (!passesRules1to3(publicKey, signature)) return false;
      try {
        return native(publicKey, message, signature) === true;
      } catch {
        // e.g. an "unsupported" error from the platform: let noble decide.
      }
    } else if (prepared.size > 0) {
      const id = preparedId(publicKey, signature);
      const answer = prepared.get(id);
      if (answer !== undefined && bytesEqual(answer.message, message)) {
        prepared.delete(id);
        return answer.valid;
      }
    }
    return verifyEd25519Noble(publicKey, message, signature);
  } catch {
    return false;
  }
}

/**
 * The strict verification on @noble/curves alone (inputs already of the
 * right type and length).
 *
 * noble's `ed25519.verify` is not used: it checks the cofactored equation
 * ([8][S]B = [8]R + [8][k]A) and does not refuse a small-order R, so it
 * accepts signatures §10.5.1 rejects (a mixed-order A or R, a small-order
 * R). The rules are composed here from noble's point decoding and
 * arithmetic, and R and A are never re-encoded.
 */
export function verifyEd25519Noble(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
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
