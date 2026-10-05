import {
  bytesEqual,
  type ControlRecordId,
  compareCanonicalFrontierOrder,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  hash32,
  LfcpError,
  type PrincipalId,
  toHex,
} from "@openlfcp/core";
import {
  decryptSnapshot,
  dekCommitment,
  deriveSnapshotKey,
  encryptSnapshot,
  type ResourceDEK,
} from "@openlfcp/crypto";
import { ABILITY, hasAbility } from "./capability.js";
import { cborMap, decodeStrict, encode } from "./cbor/index.js";
import { type Signer, signObject, verifySignedObject } from "./cose.js";
import type { DataProfileCodec } from "./data-unit.js";
import type { ControlView } from "./epoch.js";
import { type ActorHave, canonicalFrontierToCbor, missingFrom } from "./have.js";
import {
  type Parsed,
  parseSnapshot,
  type SnapshotPayload,
  snapshotPayloadFromCbor,
} from "./objects.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Encrypted, signed Snapshots (LFCP-WIRE-01 §29, §29.1, §29.2): a
 * materialization of profile state at a canonical Data frontier. The
 * plaintext is opaque here; its framing belongs to the Data Profile.
 *
 * Creation: canonical frontier → Snapshot key (§29.1.1) → nonce from the
 * Snapshot Sequence (§29.1.2) → the exact seven-element AAD (§29.1.3) →
 * ChaCha20-Poly1305 (§29.1.4) → deterministic payload → COSE_Sign1 by the
 * publisher → exact bytes → SHA-256 = Snapshot ID. The public creation API
 * is createSnapshot (@openlfcp/client), which takes the sequence from a
 * SnapshotSequenceReservation; sealSnapshot is its building block.
 *
 * Receipt (checkSnapshot without a DEK, receiveSnapshot with one):
 *  1. structure: canonical COSE_Sign1, deterministic payload, Snapshot
 *     Sequence ≥ 1 and a canonical frontier, as received (never
 *     re-normalized) → MALFORMED_MESSAGE;
 *  2. the Resource is the chain's → MALFORMED_MESSAGE;
 *  3. the publisher resolves to a descriptor → MISSING_DEPENDENCY;
 *  4. kid = publisher and a strict signature → INVALID_SIGNATURE;
 *  5. the Control Head is on the valid chain → MISSING_DEPENDENCY;
 *  6. the publisher held snapshot/publish at that head (§29.2) →
 *     AUTHORIZATION_FAILED;
 *  7. the epoch is known at that head → MISSING_DEPENDENCY;
 *  8. when the epoch has since been closed, the frontier covers no unit
 *     beyond its final frontier → STALE_DATA_EPOCH (§29, G-EP4);
 *  9. the DEK, the exact AAD rebuilt from the received fields, AEAD
 *     (one layout only, §29.1.4) → client-local failure, no wire code;
 * 10. the Data Profile's Snapshot codec accepts the plaintext.
 */

const SNAPSHOT_LABEL = "LFCP-SNAPSHOT-v1";

/** The fields of a Snapshot that its AAD binds (§29.1.3): payload fields 0-5. */
export type SnapshotAadFields = Pick<
  SnapshotPayload,
  "resourceId" | "dataEpoch" | "publisher" | "snapshotSeq" | "controlHead" | "frontier"
>;

/**
 * §29.1.3: deterministic CBOR of ["LFCP-SNAPSHOT-v1", resource_id,
 * data_epoch, publisher, snapshot_sequence, control_head,
 * canonical_frontier]. The frontier must already be canonical: it is
 * encoded as given and refused otherwise, never re-ordered.
 */
export function snapshotAad(fields: SnapshotAadFields): Uint8Array {
  if (fields.snapshotSeq < 1n)
    throw new LfcpError("OUT_OF_RANGE", "a Snapshot Sequence starts at 1 (§29)");
  return encode([
    SNAPSHOT_LABEL,
    fields.resourceId,
    dataEpoch(fields.dataEpoch),
    fields.publisher,
    fields.snapshotSeq,
    fields.controlHead,
    canonicalFrontierExact(fields.frontier),
  ]);
}

/**
 * The frontier's canonical CBOR (§28.1, §28.2). The frontier must already
 * be canonical: entries in strictly ascending raw Principal ID order (one
 * per actor) and each entry canonical. It is never re-ordered.
 */
function canonicalFrontierExact(frontier: readonly ActorHave[]) {
  for (let i = 1; i < frontier.length; i++)
    if (
      compareCanonicalFrontierOrder(
        (frontier[i - 1] as ActorHave).principalId,
        (frontier[i] as ActorHave).principalId,
      ) >= 0
    )
      throw new LfcpError(
        "INVALID_STRUCTURE",
        "the frontier must be sorted by raw Principal ID with one entry per actor (§28.2)",
      );
  return canonicalFrontierToCbor(frontier);
}

/** The deterministic §29 payload, keys 0-6; checked by the receiver rules before it is returned. */
export function encodeSnapshotPayload(
  fields: SnapshotAadFields & { readonly ciphertext: Uint8Array },
): Uint8Array {
  const bytes = encode(
    cborMap([
      [0, fields.resourceId],
      [1, dataEpoch(fields.dataEpoch)],
      [2, fields.publisher],
      [3, fields.snapshotSeq],
      [4, fields.controlHead],
      [5, canonicalFrontierExact(fields.frontier)],
      [6, fields.ciphertext],
    ]),
  );
  snapshotPayloadFromCbor(decodeStrict(bytes));
  return bytes;
}

export interface SealedSnapshot {
  readonly bytes: Uint8Array;
  /** §29: SHA-256 of the exact COSE_Sign1 bytes. */
  readonly snapshotId: Hash32;
}

/**
 * Encrypts `plaintext` and signs the Snapshot as `publisher` (the publisher
 * field is the signer's Principal).
 *
 * BUILDING BLOCK: the sequence must come from a SnapshotSequenceReservation
 * and never be reused for one (resource, epoch, publisher) (§29.1.2). Use
 * createSnapshot (@openlfcp/client), which enforces that.
 */
export function sealSnapshot(
  fields: Omit<SnapshotAadFields, "publisher">,
  plaintext: Uint8Array,
  dek: ResourceDEK,
  publisher: Signer,
): SealedSnapshot {
  const full: SnapshotAadFields = { ...fields, publisher: publisher.descriptor.principalId };
  const key = deriveSnapshotKey(dek, full.resourceId, full.dataEpoch, full.publisher);
  const ciphertext = encryptSnapshot(key, full.snapshotSeq, snapshotAad(full), plaintext);
  const signed = signObject(encodeSnapshotPayload({ ...full, ciphertext }), publisher);
  return Object.freeze({ bytes: signed.bytes, snapshotId: hash32(signed.id) });
}

export type SnapshotRejectReason =
  | "MALFORMED"
  | "OTHER_RESOURCE"
  | "UNKNOWN_PUBLISHER"
  | "SIGNATURE"
  | "UNKNOWN_CONTROL_HEAD"
  | "UNAUTHORIZED"
  | "UNKNOWN_EPOCH"
  | "BEYOND_CUTOFF";

export interface SnapshotRejected {
  readonly kind: "rejected";
  readonly reason: SnapshotRejectReason;
  readonly wireCode:
    | "MALFORMED_MESSAGE"
    | "MISSING_DEPENDENCY"
    | "INVALID_SIGNATURE"
    | "AUTHORIZATION_FAILED"
    | "STALE_DATA_EPOCH";
  readonly message: string;
}

export type SnapshotCheck =
  | {
      readonly kind: "valid";
      readonly parsed: Parsed<SnapshotPayload>;
      readonly snapshotId: Hash32;
    }
  | SnapshotRejected;

export interface SnapshotCheckOptions {
  /** Resolves a publisher that no record of the chain describes. */
  readonly resolvePrincipal?: (id: PrincipalId) => PrincipalDescriptor | undefined;
}

const rejected = (
  reason: SnapshotRejectReason,
  wireCode: SnapshotRejected["wireCode"],
  message: string,
): SnapshotRejected => Object.freeze({ kind: "rejected", reason, wireCode, message });

/** Steps 1-8: everything that needs no DEK, for servers and clients. */
export function checkSnapshot(
  view: ControlView,
  bytes: Uint8Array,
  options: SnapshotCheckOptions = {},
): SnapshotCheck {
  let parsed: Parsed<SnapshotPayload>;
  try {
    parsed = parseSnapshot(bytes);
  } catch (e) {
    return rejected("MALFORMED", "MALFORMED_MESSAGE", e instanceof Error ? e.message : String(e));
  }
  const p = parsed.payload;
  if (!bytesEqual(p.resourceId, view.state.resourceId))
    return rejected("OTHER_RESOURCE", "MALFORMED_MESSAGE", "the Snapshot is for another Resource");
  const publisher =
    view.state.principals.get(toHex(p.publisher)) ?? options.resolvePrincipal?.(p.publisher);
  if (publisher === undefined || !bytesEqual(publisher.principalId, p.publisher))
    return rejected(
      "UNKNOWN_PUBLISHER",
      "MISSING_DEPENDENCY",
      "no Principal Descriptor is known for the publisher",
    );
  const signature = verifySignedObject(parsed.signed, publisher);
  if (!signature.valid)
    return rejected(
      "SIGNATURE",
      "INVALID_SIGNATURE",
      `the Snapshot is not signed by its publisher (${signature.reason})`,
    );
  const atHead = view.stateAt(p.controlHead);
  if (atHead === undefined)
    return rejected(
      "UNKNOWN_CONTROL_HEAD",
      "MISSING_DEPENDENCY",
      `Control Head ${toHex(p.controlHead)} is not on the chain`,
    );
  if (!hasAbility(atHead, p.publisher, ABILITY.SNAPSHOT_PUBLISH))
    return rejected(
      "UNAUTHORIZED",
      "AUTHORIZATION_FAILED",
      "the publisher did not hold snapshot/publish at the referenced Control Head (§29.2)",
    );
  if (!atHead.epochs.has(String(p.dataEpoch)))
    return rejected(
      "UNKNOWN_EPOCH",
      "MISSING_DEPENDENCY",
      `epoch ${p.dataEpoch} is not known at the referenced Control Head`,
    );
  const beyond = beyondCutoff(view, p.dataEpoch, p.frontier);
  if (beyond !== undefined) return rejected("BEYOND_CUTOFF", "STALE_DATA_EPOCH", beyond);
  return Object.freeze({ kind: "valid", parsed, snapshotId: hash32(parsed.signed.id) });
}

/**
 * §29 (G-EP4): once a Key Epoch closes the Snapshot's epoch, the Snapshot
 * may cover only units within that epoch's final frontier; units beyond it
 * are quarantined (§19.1), so a Snapshot that includes them would merge
 * stale work. Evaluated against the latest known state, as §19.1 does for
 * Data Units. Returns why, or undefined when within.
 */
export function beyondCutoff(
  view: ControlView,
  epoch: DataEpoch,
  frontier: readonly ActorHave[],
): string | undefined {
  const history = view.state.epochs.get(String(epoch));
  if (history?.finalFrontier === null || history?.finalFrontier === undefined) return undefined;
  const extra = missingFrom(history.finalFrontier, frontier);
  if (extra.length === 0) return undefined;
  const first = extra[0] as { actor: Uint8Array; start: bigint; end: bigint };
  return `the frontier covers units beyond epoch ${epoch}'s final frontier (actor ${toHex(first.actor).slice(0, 16)}… ${first.start}..${first.end}; G-EP4)`;
}

export type ReceivedSnapshot<T> =
  | {
      readonly kind: "accepted";
      readonly snapshotId: Hash32;
      readonly publisher: PrincipalId;
      readonly seq: bigint;
      readonly epoch: DataEpoch;
      readonly controlHead: ControlRecordId;
      readonly frontier: readonly ActorHave[];
      readonly value: T;
    }
  | SnapshotRejected
  /** Client-local: no wire code (§29.1.4); surface it to the application. */
  | {
      readonly kind: "local-failure";
      readonly reason: "NO_DEK" | "DEK_COMMITMENT_MISMATCH" | "AEAD" | "PROFILE_REJECTED";
      readonly snapshotId: Hash32;
      readonly message: string;
    };

export interface ReceiveSnapshotOptions<T> extends SnapshotCheckOptions {
  readonly dek: (epoch: DataEpoch) => ResourceDEK | undefined | Promise<ResourceDEK | undefined>;
  /** The Data Profile's Snapshot codec: decodes and validates the Snapshot plaintext. */
  readonly profile: DataProfileCodec<T>;
}

/** A received Snapshot end to end (steps 1-10). Only "accepted" may be loaded. */
export async function receiveSnapshot<T>(
  view: ControlView,
  bytes: Uint8Array,
  options: ReceiveSnapshotOptions<T>,
): Promise<ReceivedSnapshot<T>> {
  if (options.profile.dataProfile !== view.state.dataProfile)
    throw new LfcpError(
      "DATA_PROFILE_MISMATCH",
      `the profile codec is for ${options.profile.dataProfile}, the Resource uses ${view.state.dataProfile}`,
    );
  const c = checkSnapshot(view, bytes, options);
  if (c.kind !== "valid") return c;
  const p = c.parsed.payload;
  const local = (
    reason: "NO_DEK" | "DEK_COMMITMENT_MISMATCH" | "AEAD" | "PROFILE_REJECTED",
    message: string,
  ): ReceivedSnapshot<T> =>
    Object.freeze({ kind: "local-failure", reason, snapshotId: c.snapshotId, message });
  const dek = await options.dek(p.dataEpoch);
  if (dek === undefined) return local("NO_DEK", `no DEK is held for epoch ${p.dataEpoch}`);
  const commitment = view.state.epochs.get(String(p.dataEpoch))?.dekCommitment;
  if (
    commitment === undefined ||
    !bytesEqual(dekCommitment(p.resourceId, p.dataEpoch, dek), commitment)
  )
    return local("DEK_COMMITMENT_MISMATCH", "the DEK does not match the epoch's commitment");
  let plaintext: Uint8Array;
  try {
    const key = deriveSnapshotKey(dek, p.resourceId, p.dataEpoch, p.publisher);
    plaintext = decryptSnapshot(key, p.snapshotSeq, snapshotAad(p), p.ciphertext);
  } catch (e) {
    if (e instanceof LfcpError && e.code === "AEAD_AUTHENTICATION_FAILED")
      return local("AEAD", e.message);
    throw e;
  }
  let value: T;
  try {
    value = options.profile.decode(plaintext);
  } catch (e) {
    return local(
      "PROFILE_REJECTED",
      `the Data Profile rejects the Snapshot plaintext: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  return Object.freeze({
    kind: "accepted",
    snapshotId: c.snapshotId,
    publisher: p.publisher,
    seq: p.snapshotSeq,
    epoch: p.dataEpoch,
    controlHead: p.controlHead,
    frontier: p.frontier,
    value,
  });
}
