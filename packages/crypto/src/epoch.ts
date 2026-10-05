import { randomBytes } from "@noble/hashes/utils.js";
import {
  type ActorSequence,
  actorSequence,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  hash32,
  ID32_LENGTH,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  uint64BE,
} from "@openlfcp/core";
import { sha256 } from "./hash.js";
import { hkdfExpand, hkdfExtract } from "./hkdf.js";

/**
 * Data Epoch key material (LFCP-WIRE-01 §11, §12, §29.1.1, §29.1.2).
 *
 * - The Resource DEK is 32 random bytes per (Resource, Data Epoch), from the
 *   platform CSPRNG; it is never derived from IDs, identities or time.
 * - Its public commitment is SHA-256("LFCP-DEK-v1" || R || uint64_be(E) || DEK).
 * - Each writer encrypts with its own actor key,
 *   HKDF-Expand(HKDF-Extract(R || uint64_be(E), DEK), "LFCP-DATA-KEY-v1" || A, 32),
 *   and nonce 0x00000000 || uint64_be(seq). The same sequence is safe for
 *   different Principals because their keys differ; reusing a sequence for
 *   one (Resource, Principal) is forbidden (§8, §12), across epochs too.
 * - A Snapshot publisher uses the same construction with the label
 *   "LFCP-SNAPSHOT-KEY-v1" and its Snapshot Sequence.
 *
 * All IDs are the raw 32 bytes, never text forms. Secrets (ResourceDEK,
 * ActorDataKey, SnapshotKey) keep their bytes in a private field and print
 * as "[redacted]" through toJSON, toString and inspect; the only way out is
 * `exportSecretKeyBytes`. Errors never include key bytes.
 */

const REDACTED = "[redacted]";
const INSPECT = Symbol.for("nodejs.util.inspect.custom");
const KEY_LENGTH = 32;
const ascii = (text: string): Uint8Array => Uint8Array.from(text, (c) => c.charCodeAt(0));
const DEK_LABEL = ascii("LFCP-DEK-v1");
const DATA_KEY_LABEL = ascii("LFCP-DATA-KEY-v1");
const SNAPSHOT_KEY_LABEL = ascii("LFCP-SNAPSHOT-KEY-v1");
const NONCE_PREFIX = new Uint8Array(4);

let readSecret: (secret: SymmetricSecret) => Uint8Array;

/** 32 secret bytes with redacted diagnostics. */
abstract class SymmetricSecret {
  readonly #bytes: Uint8Array;

  static {
    readSecret = (secret) => secret.#bytes;
  }

  protected constructor(kind: string, bytes: Uint8Array) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_LENGTH)
      throw new LfcpError("INVALID_LENGTH", `${kind} must be exactly ${KEY_LENGTH} bytes`);
    this.#bytes = Uint8Array.from(bytes);
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

let makeDek: (bytes: Uint8Array) => ResourceDEK;
let makeActorKey: (bytes: Uint8Array) => ActorDataKey;
let makeSnapshotKey: (bytes: Uint8Array) => SnapshotKey;

/** A Resource Data Encryption Key for one Data Epoch (§11). */
export class ResourceDEK extends SymmetricSecret {
  readonly kind = "ResourceDEK";
  static {
    makeDek = (bytes) => new ResourceDEK(bytes);
  }
  private constructor(bytes: Uint8Array) {
    super("a Resource DEK", bytes);
  }
}

/** A writer's ChaCha20-Poly1305 key for one (Resource, Data Epoch) (§12). */
export class ActorDataKey extends SymmetricSecret {
  readonly kind = "ActorDataKey";
  static {
    makeActorKey = (bytes) => new ActorDataKey(bytes);
  }
  private constructor(bytes: Uint8Array) {
    super("an actor data key", bytes);
  }
}

/** A Snapshot publisher's ChaCha20-Poly1305 key for one (Resource, Data Epoch) (§29.1.1). */
export class SnapshotKey extends SymmetricSecret {
  readonly kind = "SnapshotKey";
  static {
    makeSnapshotKey = (bytes) => new SnapshotKey(bytes);
  }
  private constructor(bytes: Uint8Array) {
    super("a Snapshot key", bytes);
  }
}

/** True for the symmetric secrets of this module. */
export const isSymmetricSecret = (value: unknown): value is SymmetricSecret =>
  value instanceof SymmetricSecret;

/** The secret bytes (for exportSecretKeyBytes only). */
export const symmetricSecretBytes = (secret: SymmetricSecret): Uint8Array => readSecret(secret);

function id32(what: string, id: Uint8Array): Uint8Array {
  if (!(id instanceof Uint8Array) || id.length !== ID32_LENGTH)
    throw new LfcpError("INVALID_LENGTH", `${what} must be the raw ${ID32_LENGTH}-byte ID`);
  return id;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function dekOf(dek: ResourceDEK): Uint8Array {
  if (!(dek instanceof ResourceDEK))
    throw new LfcpError("CRYPTO_FAILURE", "expected a ResourceDEK");
  return readSecret(dek);
}

/** A fresh DEK: 32 bytes from the platform CSPRNG (§11 "MUST be generated randomly"). */
export function generateResourceDEK(): ResourceDEK {
  let bytes: Uint8Array;
  try {
    bytes = randomBytes(KEY_LENGTH);
  } catch {
    throw new LfcpError("NO_SECURE_RANDOM", "no CSPRNG (crypto.getRandomValues) is available");
  }
  return makeDek(bytes);
}

/** Restores a DEK from its 32 bytes (a received Key Package, local secret storage). The input is copied. */
export function importResourceDEK(bytes: Uint8Array): ResourceDEK {
  return makeDek(bytes);
}

/** dek_commitment = SHA-256(ASCII("LFCP-DEK-v1") || resource_id || uint64_be(E) || DEK) (§11). */
export function dekCommitment(resource: ResourceId, epoch: DataEpoch, dek: ResourceDEK): Hash32 {
  return hash32(
    sha256(
      concat(DEK_LABEL, id32("the Resource ID", resource), uint64BE(dataEpoch(epoch)), dekOf(dek)),
    ),
  );
}

function epochKey(
  dek: ResourceDEK,
  resource: ResourceId,
  epoch: DataEpoch,
  label: Uint8Array,
  principal: PrincipalId,
): Uint8Array {
  const salt = concat(id32("the Resource ID", resource), uint64BE(dataEpoch(epoch)));
  const prk = hkdfExtract(salt, dekOf(dek));
  try {
    return hkdfExpand(prk, concat(label, id32("the Principal ID", principal)), KEY_LENGTH);
  } finally {
    prk.fill(0);
  }
}

/**
 * actor_key = HKDF-Expand(HKDF-Extract(R || uint64_be(E), DEK),
 *                         ASCII("LFCP-DATA-KEY-v1") || A, 32)   (§12)
 */
export function deriveActorDataKey(
  dek: ResourceDEK,
  resource: ResourceId,
  epoch: DataEpoch,
  actor: PrincipalId,
): ActorDataKey {
  const bytes = epochKey(dek, resource, epoch, DATA_KEY_LABEL, actor);
  try {
    return makeActorKey(bytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * snapshot_key = HKDF-Expand(HKDF-Extract(resource_id || uint64_be(E), DEK),
 *                            ASCII("LFCP-SNAPSHOT-KEY-v1") || publisher, 32)   (§29.1.1)
 */
export function deriveSnapshotKey(
  dek: ResourceDEK,
  resource: ResourceId,
  epoch: DataEpoch,
  publisher: PrincipalId,
): SnapshotKey {
  const bytes = epochKey(dek, resource, epoch, SNAPSHOT_KEY_LABEL, publisher);
  try {
    return makeSnapshotKey(bytes);
  } finally {
    bytes.fill(0);
  }
}

/** nonce = 0x00000000 || uint64_be(seq), 12 bytes, for actor sequence 1..2^64-1 (§8, §12). */
export function dataUnitNonce(seq: ActorSequence): Uint8Array {
  return concat(NONCE_PREFIX, uint64BE(actorSequence(seq)));
}

/**
 * snapshot_nonce = 0x00000000 || uint64_be(snapshot_sequence), 12 bytes
 * (§29.1.2). The sequence must fit in uint64; §29 sets no lower bound.
 */
export function snapshotNonce(snapshotSequence: bigint): Uint8Array {
  return concat(NONCE_PREFIX, uint64BE(snapshotSequence));
}
