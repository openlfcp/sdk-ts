import {
  type ActorSequence,
  actorSequence,
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
  dataUnitId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  decryptDataUnit,
  dekCommitment,
  deriveActorDataKey,
  encryptDataUnit,
  type ResourceDEK,
} from "@openlfcp/crypto";
import { ABILITY, hasAbility } from "./capability.js";
import { cborMap, decodeStrict, encode } from "./cbor/index.js";
import type { ControlState } from "./chain.js";
import { type Signer, signObject, verifySignedObject } from "./cose.js";
import { type ControlView, classifyDataUnit } from "./epoch.js";
import {
  type DataUnitPayload,
  dataUnitPayloadFromCbor,
  type Parsed,
  parseDataUnit,
} from "./objects.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Data Units (LFCP-WIRE-01 §12, §26): the encrypted, signed unit of
 * application replication. There is no plaintext network mode: the Data
 * Profile produces plaintext locally, and only the encrypted, signed bytes
 * leave the client.
 *
 * Creation: profile plaintext → actor key (§12) → exact AAD (§26.1) →
 * ChaCha20-Poly1305 with the sequence nonce → deterministic payload (§26)
 * → canonical COSE_Sign1 by the actor (§10) → exact bytes → SHA-256 = the
 * Data Unit ID. The public creation API is createDataUnit
 * (@openlfcp/client), which takes the sequence only from an
 * ActorSequenceReservation; sealDataUnit here is its building block.
 *
 * Receipt, in this order (§26.2, §26.3):
 *  1. structure: canonical COSE_Sign1, deterministic payload, exact bytes
 *     kept (parseDataUnit) → MALFORMED_MESSAGE;
 *  2. the actor resolves to a Principal Descriptor on the chain →
 *     otherwise MISSING_DEPENDENCY;
 *  3, 4. kid = actor and a strict Ed25519 signature (§10.5, §10.5.1) →
 *     INVALID_SIGNATURE;
 *     then equivocation: another signature-valid unit for the same
 *     (resource, actor, seq) → ACTOR_EQUIVOCATION, whatever its
 *     authorization or decryptability (§26.2);
 *  5. the referenced Control Head is on the valid chain → MISSING_DEPENDENCY;
 *  6. the actor held data/write at that head (not at the latest one, so
 *     offline work on an older head stays valid) → AUTHORIZATION_FAILED;
 *  7, 8. the epoch is recognized at that head, and a closed epoch's unit
 *     is within the final frontier (classifyDataUnit, LFCP-023) →
 *     MISSING_DEPENDENCY or quarantine (STALE_DATA_EPOCH);
 *  9. AEAD authentication → client-local failure, no wire code (N3);
 * 10. the Data Profile accepts the plaintext → client-local failure.
 * Steps 1-8 need no DEK and no plaintext, so servers run them too
 * (checkDataUnit). After step 10 the actor hash chain decides between
 * accepted and held (§26.2, G-DP1): a cryptographically valid unit whose
 * chain context is incomplete is held, not merged, until it links.
 */

const DATA_LABEL = "LFCP-DATA-v1";

/** The fields of a Data Unit that its AAD binds (§26.1). */
export type DataUnitAadFields = Pick<
  DataUnitPayload,
  "resourceId" | "dataEpoch" | "actor" | "actorSeq" | "prevDataUnitId" | "controlHead"
>;

/**
 * §26.1: the AAD is the deterministic CBOR array ["LFCP-DATA-v1",
 * resource_id, data_epoch, actor, actor_sequence, previous unit or null,
 * control_head]; nothing else.
 */
export function dataUnitAad(header: DataUnitAadFields): Uint8Array {
  return encode([
    DATA_LABEL,
    header.resourceId,
    dataEpoch(header.dataEpoch),
    header.actor,
    actorSequence(header.actorSeq),
    header.prevDataUnitId,
    header.controlHead,
  ]);
}

/** The deterministic §26 payload: keys 0-6 exactly. Checked by the receiver rules before it is returned. */
export function encodeDataUnitPayload(
  header: DataUnitAadFields & { readonly ciphertext: Uint8Array },
): Uint8Array {
  const bytes = encode(
    cborMap([
      [0, header.resourceId],
      [1, dataEpoch(header.dataEpoch)],
      [2, header.actor],
      [3, actorSequence(header.actorSeq)],
      [4, header.prevDataUnitId],
      [5, header.controlHead],
      [6, header.ciphertext],
    ]),
  );
  dataUnitPayloadFromCbor(decodeStrict(bytes));
  return bytes;
}

/** A newly sealed Data Unit: its exact bytes and its ID, SHA-256 of those bytes (§26, §10.6). */
export interface SealedDataUnit {
  readonly bytes: Uint8Array;
  readonly unitId: DataUnitId;
}

/**
 * Encrypts `plaintext` and signs the Data Unit as `actor` (the actor field
 * is the signer's Principal, so actor and signer cannot differ).
 *
 * BUILDING BLOCK: the sequence must come from an ActorSequenceReservation
 * and never be used twice for one (Resource, actor) (§8, §12: nonce
 * reuse). Use createDataUnit (@openlfcp/client), which enforces that.
 */
export function sealDataUnit(
  header: Omit<DataUnitAadFields, "actor">,
  plaintext: Uint8Array,
  dek: ResourceDEK,
  actor: Signer,
): SealedDataUnit {
  const seq = actorSequence(header.actorSeq);
  if (seq === 1n && header.prevDataUnitId !== null)
    throw new LfcpError("INVALID_STRUCTURE", "sequence 1 must have a null previous unit (§26.2)");
  const full: DataUnitAadFields = { ...header, actor: actor.descriptor.principalId };
  const key = deriveActorDataKey(dek, full.resourceId, full.dataEpoch, full.actor);
  const ciphertext = encryptDataUnit(key, seq, dataUnitAad(full), plaintext);
  const signed = signObject(encodeDataUnitPayload({ ...full, ciphertext }), actor);
  return Object.freeze({ bytes: signed.bytes, unitId: dataUnitId(signed.id) });
}

/**
 * The Data Profile boundary (§27). LFCP never interprets plaintext: the
 * profile turns application values into plaintext bytes and validates and
 * decodes received plaintext. Servers never need one.
 */
export interface DataProfileCodec<T> {
  /** The Genesis data_profile this codec implements (§15, §27). */
  readonly dataProfile: string;
  /** The plaintext of `value`. */
  encode(value: T): Uint8Array;
  /** Validates and decodes received plaintext; throws to reject it. */
  decode(plaintext: Uint8Array): T;
}

/**
 * What a receiver remembers of Data Units, per (resource, actor, seq), to
 * detect equivocation and replays and to follow actor hash chains (§26.2).
 * Durable implementations belong to the storage tasks (LFCP-034 to
 * LFCP-036).
 */
export interface SeenUnits {
  /**
   * Records a signature-valid unit. Resolves to every Data Unit ID recorded
   * for its (resource, actor, seq), this one included, sorted by bytes
   * (more than one is equivocation), and whether this ID is new.
   */
  recordSignatureValid(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<SeenRecord>;
  /** The ID of the actor's accepted (merged) unit at `seq`, if any. */
  acceptedAt(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
  ): Promise<DataUnitId | undefined>;
  /** Records that a unit was accepted (merged). */
  markAccepted(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<void>;
}

/** The result of SeenUnits.recordSignatureValid. */
export interface SeenRecord {
  readonly unitIds: readonly DataUnitId[];
  readonly firstSeen: boolean;
}

const tupleKey = (resource: Uint8Array, actor: Uint8Array, seq: bigint): string =>
  `${toHex(resource)}:${toHex(actor)}:${seq}`;

/**
 * FOR TESTS AND DEVELOPMENT ONLY: memory is lost on restart, so a restarted
 * receiver forgets which units it saw and accepted and cannot detect an
 * equivocation against them. Production receivers need a durable SeenUnits
 * (LFCP-034 to LFCP-036).
 */
export class InMemorySeenUnits implements SeenUnits {
  readonly #seen = new Map<string, Map<string, DataUnitId>>();
  readonly #accepted = new Map<string, DataUnitId>();

  recordSignatureValid(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<SeenRecord> {
    const key = tupleKey(resource, actor, seq);
    let ids = this.#seen.get(key);
    if (ids === undefined) {
      ids = new Map();
      this.#seen.set(key, ids);
    }
    const firstSeen = !ids.has(toHex(unitId));
    ids.set(toHex(unitId), dataUnitId(unitId));
    const unitIds = [...ids.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, id]) => id);
    return Promise.resolve(Object.freeze({ unitIds: Object.freeze(unitIds), firstSeen }));
  }

  acceptedAt(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
  ): Promise<DataUnitId | undefined> {
    return Promise.resolve(this.#accepted.get(tupleKey(resource, actor, seq)));
  }

  markAccepted(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<void> {
    this.#accepted.set(tupleKey(resource, actor, seq), dataUnitId(unitId));
    return Promise.resolve();
  }
}

export type DataUnitRejectReason =
  | "MALFORMED"
  | "UNKNOWN_ACTOR"
  | "SIGNATURE"
  | "OTHER_RESOURCE"
  | "UNKNOWN_CONTROL_HEAD"
  | "UNAUTHORIZED"
  | "UNKNOWN_EPOCH";

/** A unit refused with a wire code (steps 1-7). */
export interface DataUnitRejected {
  readonly kind: "rejected";
  readonly reason: DataUnitRejectReason;
  readonly wireCode:
    | "MALFORMED_MESSAGE"
    | "MISSING_DEPENDENCY"
    | "INVALID_SIGNATURE"
    | "AUTHORIZATION_FAILED";
  readonly message: string;
}

/**
 * Two or more signature-valid units for one (resource, actor, seq) (§26.2).
 * No winner is chosen: every ID is listed, sorted by bytes only for
 * reproducible output. `accepted` is the one already merged, if any, so
 * the application can review it.
 */
export interface DataUnitEquivocation {
  readonly kind: "equivocation";
  readonly wireCode: "ACTOR_EQUIVOCATION";
  readonly resourceId: ResourceId;
  readonly actor: PrincipalId;
  readonly seq: ActorSequence;
  readonly unitIds: readonly DataUnitId[];
  readonly accepted?: DataUnitId;
}

/** Stale offline work (§19.1, LFCP-023): never merged automatically, never dropped silently. */
export interface DataUnitQuarantined {
  readonly kind: "quarantined";
  readonly code: "STALE_DATA_EPOCH";
  readonly reason: "BEYOND_CUTOFF" | "ACTOR_ABSENT";
  readonly unitId: DataUnitId;
  readonly epoch: DataEpoch;
  readonly closedBy: ControlRecordId;
}

/** The DEK-free checks (steps 1-8) that a server runs as well as a client. */
export type DataUnitCheck =
  | {
      readonly kind: "valid";
      readonly parsed: Parsed<DataUnitPayload>;
      readonly unitId: DataUnitId;
      /** False when this exact unit was recorded before: a replay, harmless. */
      readonly firstSeen: boolean;
    }
  | DataUnitRejected
  | DataUnitEquivocation
  | DataUnitQuarantined;

export interface DataUnitCheckOptions {
  /** Resolves an actor that no record of the chain describes. */
  readonly resolvePrincipal?: (id: PrincipalId) => PrincipalDescriptor | undefined;
}

const rejected = (
  reason: DataUnitRejectReason,
  wireCode: DataUnitRejected["wireCode"],
  message: string,
): DataUnitRejected => Object.freeze({ kind: "rejected", reason, wireCode, message });

type Verified =
  | {
      readonly kind: "verified";
      readonly parsed: Parsed<DataUnitPayload>;
      readonly unitId: DataUnitId;
      readonly firstSeen: boolean;
    }
  | DataUnitRejected
  | DataUnitEquivocation;

/** Steps 1-4 and the equivocation check. */
async function verifyUnit(
  view: ControlView,
  bytes: Uint8Array,
  seen: SeenUnits,
  options: DataUnitCheckOptions,
): Promise<Verified> {
  let parsed: Parsed<DataUnitPayload>;
  try {
    parsed = parseDataUnit(bytes);
  } catch (e) {
    return rejected("MALFORMED", "MALFORMED_MESSAGE", e instanceof Error ? e.message : String(e));
  }
  const p = parsed.payload;
  const actor =
    view.state.principals.get(toHex(p.actor)) ?? options.resolvePrincipal?.(p.actor) ?? undefined;
  if (actor === undefined || !bytesEqual(actor.principalId, p.actor))
    return rejected(
      "UNKNOWN_ACTOR",
      "MISSING_DEPENDENCY",
      "no Principal Descriptor is known for the actor (§13.1)",
    );
  const signature = verifySignedObject(parsed.signed, actor);
  if (!signature.valid)
    return rejected(
      "SIGNATURE",
      "INVALID_SIGNATURE",
      `the unit is not signed by its actor (${signature.reason}, §10.5, §26.3)`,
    );
  const unitId = dataUnitId(parsed.signed.id);
  const record = await seen.recordSignatureValid(p.resourceId, p.actor, p.actorSeq, unitId);
  if (record.unitIds.length > 1) {
    const accepted = await seen.acceptedAt(p.resourceId, p.actor, p.actorSeq);
    return Object.freeze({
      kind: "equivocation",
      wireCode: "ACTOR_EQUIVOCATION",
      resourceId: p.resourceId,
      actor: p.actor,
      seq: p.actorSeq,
      unitIds: record.unitIds,
      ...(accepted === undefined ? {} : { accepted }),
    });
  }
  return { kind: "verified", parsed, unitId, firstSeen: record.firstSeen };
}

/** Steps 5-8. */
function eligibility(
  view: ControlView,
  parsed: Parsed<DataUnitPayload>,
  unitId: DataUnitId,
):
  | { readonly kind: "eligible"; readonly atHead: ControlState }
  | DataUnitRejected
  | DataUnitQuarantined {
  const p = parsed.payload;
  if (!bytesEqual(p.resourceId, view.state.resourceId))
    return rejected("OTHER_RESOURCE", "MALFORMED_MESSAGE", "the unit is for another Resource");
  const atHead = view.stateAt(p.controlHead);
  if (atHead === undefined)
    return rejected(
      "UNKNOWN_CONTROL_HEAD",
      "MISSING_DEPENDENCY",
      `Control Head ${toHex(p.controlHead)} is not on the chain (§13.1, §26.3 rule 3)`,
    );
  if (!hasAbility(atHead, p.actor, ABILITY.DATA_WRITE))
    return rejected(
      "UNAUTHORIZED",
      "AUTHORIZATION_FAILED",
      "the actor did not hold data/write at the referenced Control Head (§26.3 rule 2)",
    );
  const c = classifyDataUnit(view, p);
  if (c.kind === "reject") return rejected(c.reason, c.wireCode, `${c.reason} (§26.3 rule 4)`);
  if (c.kind === "quarantine")
    return Object.freeze({
      kind: "quarantined",
      code: c.code,
      reason: c.reason,
      unitId,
      epoch: c.epoch,
      closedBy: c.closedBy,
    });
  return { kind: "eligible", atHead };
}

/**
 * The DEK-free Data Unit checks (steps 1-8), for servers and clients:
 * structure, the actor's signature, equivocation, the referenced head,
 * data/write at that head, and the epoch rules. Records the unit in
 * `seen` once its signature verifies.
 */
export async function checkDataUnit(
  view: ControlView,
  bytes: Uint8Array,
  seen: SeenUnits,
  options: DataUnitCheckOptions = {},
): Promise<DataUnitCheck> {
  const v = await verifyUnit(view, bytes, seen, options);
  if (v.kind !== "verified") return v;
  const e = eligibility(view, v.parsed, v.unitId);
  if (e.kind !== "eligible") return e;
  return Object.freeze({
    kind: "valid",
    parsed: v.parsed,
    unitId: v.unitId,
    firstSeen: v.firstSeen,
  });
}

/** Why a cryptographically valid unit is held, not merged (§26.2, G-DP1). */
export type DataUnitHoldReason =
  /** The receiver has not accepted the actor's unit at seq - 1. */
  | "GAP"
  /** `previous` names a unit other than the accepted one at seq - 1. */
  | "PREV_MISMATCH"
  /** `previous` is not null at sequence 1. */
  | "PREV_AT_SEQ1"
  /** `previous` is null at a sequence above 1. */
  | "NULL_PREV_AFTER_1";

export type ReceivedDataUnit<T> =
  | {
      readonly kind: "accepted";
      readonly unitId: DataUnitId;
      readonly actor: PrincipalId;
      readonly seq: ActorSequence;
      readonly epoch: DataEpoch;
      readonly value: T;
    }
  /** The same unit was accepted before: an exact replay, harmless. */
  | { readonly kind: "duplicate"; readonly unitId: DataUnitId }
  | DataUnitEquivocation
  /**
   * Cryptographically valid and authorized, but its actor-chain context is
   * incomplete: report it to the sync engine and retry when the unit at
   * seq - 1 arrives and links (§26.2, G-DP1).
   */
  | {
      readonly kind: "held";
      readonly reason: DataUnitHoldReason;
      readonly unitId: DataUnitId;
      readonly actor: PrincipalId;
      readonly seq: ActorSequence;
      readonly previous: DataUnitId | null;
    }
  | DataUnitQuarantined
  | DataUnitRejected
  /** Client-local: no wire code (§26.3, ADR 0001 N3); surface it to the application. */
  | {
      readonly kind: "local-failure";
      readonly reason: "NO_DEK" | "DEK_COMMITMENT_MISMATCH" | "AEAD" | "PROFILE_REJECTED";
      readonly unitId: DataUnitId;
      readonly message: string;
    };

export interface ReceiveDataUnitOptions<T> extends DataUnitCheckOptions {
  readonly seen: SeenUnits;
  /** The DEK of a Data Epoch, if this client holds it (from a Key Package, LFCP-024). */
  readonly dek: (epoch: DataEpoch) => ResourceDEK | undefined | Promise<ResourceDEK | undefined>;
  readonly profile: DataProfileCodec<T>;
}

/**
 * A received Data Unit end to end (steps 1-10, then the actor hash chain).
 * Only an "accepted" result may be merged; it is recorded in `seen` as
 * accepted. A held unit is retried by calling this again later.
 */
export async function receiveDataUnit<T>(
  view: ControlView,
  bytes: Uint8Array,
  options: ReceiveDataUnitOptions<T>,
): Promise<ReceivedDataUnit<T>> {
  if (options.profile.dataProfile !== view.state.dataProfile)
    throw new LfcpError(
      "DATA_PROFILE_MISMATCH",
      `the profile codec is for ${options.profile.dataProfile}, the Resource uses ${view.state.dataProfile}`,
    );
  const v = await verifyUnit(view, bytes, options.seen, options);
  if (v.kind !== "verified") return v;
  const p = v.parsed.payload;
  const unitId = v.unitId;
  const accepted = await options.seen.acceptedAt(p.resourceId, p.actor, p.actorSeq);
  if (accepted !== undefined && bytesEqual(accepted, unitId))
    return Object.freeze({ kind: "duplicate", unitId });

  const e = eligibility(view, v.parsed, unitId);
  if (e.kind !== "eligible") return e;

  const local = (
    reason: "NO_DEK" | "DEK_COMMITMENT_MISMATCH" | "AEAD" | "PROFILE_REJECTED",
    message: string,
  ): ReceivedDataUnit<T> => Object.freeze({ kind: "local-failure", reason, unitId, message });
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
    const key = deriveActorDataKey(dek, p.resourceId, p.dataEpoch, p.actor);
    plaintext = decryptDataUnit(key, p.actorSeq, dataUnitAad(p), p.ciphertext);
  } catch (err) {
    if (err instanceof LfcpError && err.code === "AEAD_AUTHENTICATION_FAILED")
      return local("AEAD", err.message);
    throw err;
  }
  let value: T;
  try {
    value = options.profile.decode(plaintext);
  } catch (err) {
    return local(
      "PROFILE_REJECTED",
      `the Data Profile rejects the plaintext: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const hold = await holdReason(options.seen, p);
  if (hold !== undefined)
    return Object.freeze({
      kind: "held",
      reason: hold,
      unitId,
      actor: p.actor,
      seq: p.actorSeq,
      previous: p.prevDataUnitId,
    });
  await options.seen.markAccepted(p.resourceId, p.actor, p.actorSeq, unitId);
  return Object.freeze({
    kind: "accepted",
    unitId,
    actor: p.actor,
    seq: p.actorSeq,
    epoch: p.dataEpoch,
    value,
  });
}

/** §26.2: why the unit cannot link to the actor's accepted unit at seq - 1, or undefined when it links. */
async function holdReason(
  seen: SeenUnits,
  p: DataUnitPayload,
): Promise<DataUnitHoldReason | undefined> {
  if (p.actorSeq === 1n) return p.prevDataUnitId === null ? undefined : "PREV_AT_SEQ1";
  if (p.prevDataUnitId === null) return "NULL_PREV_AFTER_1";
  const before = await seen.acceptedAt(p.resourceId, p.actor, actorSequence(p.actorSeq - 1n));
  if (before === undefined) return "GAP";
  return bytesEqual(before, p.prevDataUnitId) ? undefined : "PREV_MISMATCH";
}
