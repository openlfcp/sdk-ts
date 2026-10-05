import {
  type ActorSequence,
  actorSequence,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
  dataUnitId,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
} from "@openlfcp/core";
import { type CborValue, decodeDeterministic, decodeStrict } from "./cbor/index.js";
import { parseSignedObject, type SignedObject } from "./cose.js";
import { Fields, invalid } from "./fields.js";
import { type ActorHave, canonicalFrontierFromCbor } from "./have.js";

/**
 * Typed payloads of the persistent LFCP signed objects (LFCP-WIRE-01 §13,
 * §25, §26, §29), on top of the canonical COSE_Sign1 layer in cose.ts.
 *
 * `parseX(bytes)` returns `{ signed, payload }`: `signed` is the
 * `parseSignedObject` result and `payload` is decoded from
 * `signed.payloadBytes`. The decoders check structure only: the field set,
 * field types and byte lengths, and the structural rules named on each
 * payload. Signer authority, chain linkage, epochs, cutoff frontiers, AEAD
 * and HPKE belong to LFCP-020 to LFCP-025.
 *
 * Exact bytes: hashing and signature verification always use the received
 * bytes. The object ID is SHA-256 of `signed.bytes` and the signature is
 * checked over `signed.protectedBytes` and `signed.payloadBytes`, exactly as
 * received. The N7 rule (§5.2, §10.3: decode, re-encode and compare) is only a
 * rejection test. Its re-encoding is compared and then thrown away; it never
 * becomes an object's bytes, and no ID or signature input is ever rebuilt
 * from a parsed payload.
 *
 * Errors and their wire mapping (ADR 0001):
 * - COSE_MALFORMED, CBOR_* and INVALID_STRUCTURE → MALFORMED_MESSAGE;
 * - UNSUPPORTED_VALUE (reserved core Control Record type) →
 *   INVALID_CONTROL_CHAIN (§14);
 * - INVALID_CONTROL_CHAIN (a Genesis not at control_seq 0 with a null
 *   link, §13.1) → INVALID_CONTROL_CHAIN;
 * - a failed `verifySignedObject` against the expected signer → INVALID_SIGNATURE.
 */

/** A parsed signed object: the exact received object and its typed payload. */
export interface Parsed<P> {
  readonly signed: SignedObject;
  readonly payload: P;
}

/** §14 Control Record types defined by LFCP-WIRE-01. 9–31 are reserved; 32 and up are extensions. */
export const CONTROL_TYPE = Object.freeze({
  GENESIS: 0n,
  CAPABILITY_GRANT: 1n,
  CAPABILITY_REVOKE: 2n,
  CAPABILITY_CLAIM: 3n,
  KEY_EPOCH: 4n,
  ROUTE_UPDATE: 5n,
  OWNER_TRANSFER_COMMIT: 6n,
  COORDINATOR_RECOVERY: 7n,
  RESOURCE_TOMBSTONE: 8n,
});
const FIRST_RESERVED_CONTROL_TYPE = 9n;
const FIRST_EXTENSION_CONTROL_TYPE = 32n;

/**
 * `control-record-payload` (§13). The body is the decoded `any` value. It is
 * deterministic CBOR (checked with the payload) but not typed here; typed
 * bodies are LFCP-019.
 */
export interface ControlRecordPayload {
  readonly kind: "control-record";
  readonly resourceId: ResourceId;
  readonly controlSeq: bigint;
  readonly prevControlId: ControlRecordId | null;
  readonly controlType: bigint;
  /** True for extension types (32 and up), which §14 lets a receiver keep without interpreting. */
  readonly extension: boolean;
  /**
   * The payload's issuer field. Whether the issuer may issue this record
   * (and who must have signed it) is decided by LFCP-019 to LFCP-021.
   */
  readonly issuer: PrincipalId;
  readonly body: CborValue;
}

/** `data-unit-payload` (§26). */
export interface DataUnitPayload {
  readonly kind: "data-unit";
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly actor: PrincipalId;
  readonly actorSeq: ActorSequence;
  readonly prevDataUnitId: DataUnitId | null;
  readonly controlHead: ControlRecordId;
  readonly ciphertext: Uint8Array;
}

/** `key-package-payload` (§25). */
export interface KeyPackagePayload {
  readonly kind: "key-package";
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly recipient: PrincipalId;
  readonly controlHead: ControlRecordId;
  readonly sender: PrincipalId;
  readonly hpkeEnc: Uint8Array;
  readonly hpkeCiphertext: Uint8Array;
}

/** `snapshot-payload` (§29). */
export interface SnapshotPayload {
  readonly kind: "snapshot";
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly publisher: PrincipalId;
  readonly snapshotSeq: bigint;
  readonly controlHead: ControlRecordId;
  readonly frontier: readonly ActorHave[];
  readonly ciphertext: Uint8Array;
}

const ALL_FIELDS = [0, 1, 2, 3, 4, 5, 6];

/**
 * Structural rules: the §13 field set, a §14 type that is not reserved
 * (UNSUPPORTED_VALUE otherwise), and a Genesis record (type 0) at
 * control_seq 0 with a null link (§13.1: INVALID_CONTROL_CHAIN otherwise).
 * Sequence continuity and prev_control_id linkage are chain validation
 * (LFCP-020).
 */
export function controlRecordPayloadFromCbor(value: CborValue): ControlRecordPayload {
  const f = new Fields(value, "control-record-payload", ALL_FIELDS.slice(0, 6));
  const rid = resourceId(f.bytes(0, 32));
  const controlSeq = f.uint(1);
  const prev = f.bytesOrNull(2, 32);
  const controlType = f.uint(3);
  const issuer = principalId(f.bytes(4, 32));
  if (controlType >= FIRST_RESERVED_CONTROL_TYPE && controlType < FIRST_EXTENSION_CONTROL_TYPE) {
    throw new LfcpError(
      "UNSUPPORTED_VALUE",
      `Control Record type ${controlType} is reserved for LFCP core (§14)`,
    );
  }
  if (controlType === CONTROL_TYPE.GENESIS && (controlSeq !== 0n || prev !== null))
    throw new LfcpError(
      "INVALID_CONTROL_CHAIN",
      "a Genesis record must have control_seq 0 and a null prev_control_id (§13.1)",
    );
  return Object.freeze({
    kind: "control-record",
    resourceId: rid,
    controlSeq,
    prevControlId: prev === null ? null : controlRecordId(prev),
    controlType,
    extension: controlType >= FIRST_EXTENSION_CONTROL_TYPE,
    issuer,
    body: f.any(5),
  });
}

/**
 * Structural rules: the §26 field set and actor sequence >= 1 (§8, N4).
 * A non-null previous unit at sequence 1 is not rejected here: §26.2 asks
 * for it to be reported to the sync engine, and the actor_seq1_prev_not_null_D1
 * vector's disposition is "report", not reject (LFCP-025, LFCP-028).
 */
export function dataUnitPayloadFromCbor(value: CborValue): DataUnitPayload {
  const f = new Fields(value, "data-unit-payload", ALL_FIELDS);
  const prev = f.bytesOrNull(4, 32);
  const actorSeq = f.uint(3);
  if (actorSeq === 0n) f.fail(3, "(actor sequence) must be at least 1 (§8)");
  return Object.freeze({
    kind: "data-unit",
    resourceId: resourceId(f.bytes(0, 32)),
    dataEpoch: dataEpoch(f.uint(1)),
    actor: principalId(f.bytes(2, 32)),
    actorSeq: actorSequence(actorSeq),
    prevDataUnitId: prev === null ? null : dataUnitId(prev),
    controlHead: controlRecordId(f.bytes(5, 32)),
    ciphertext: f.bytes(6),
  });
}

/**
 * Structural rules: the §25 field set, with `5 => bstr .size 32` (HPKE
 * enc) and `6 => bstr .size 48` (the 32-byte DEK and the 16-byte tag).
 * HPKE and authority checks are key-package.ts.
 */
export function keyPackagePayloadFromCbor(value: CborValue): KeyPackagePayload {
  const f = new Fields(value, "key-package-payload", ALL_FIELDS);
  return Object.freeze({
    kind: "key-package",
    resourceId: resourceId(f.bytes(0, 32)),
    dataEpoch: dataEpoch(f.uint(1)),
    recipient: principalId(f.bytes(2, 32)),
    controlHead: controlRecordId(f.bytes(3, 32)),
    sender: principalId(f.bytes(4, 32)),
    hpkeEnc: f.bytes(5, 32),
    hpkeCiphertext: f.bytes(6, 48),
  });
}

/**
 * Structural rules: the §29 field set, a Snapshot Sequence of at least 1
 * (§29: "Snapshot Sequences begin at 1"; §29 names no code, so this is
 * INVALID_STRUCTURE like actor sequence 0) and a canonical frontier
 * (§28.1, §28.2, N6).
 */
export function snapshotPayloadFromCbor(value: CborValue): SnapshotPayload {
  const f = new Fields(value, "snapshot-payload", ALL_FIELDS);
  const snapshotSeq = f.uint(3);
  if (snapshotSeq === 0n) f.fail(3, "(Snapshot Sequence) must be at least 1 (§29)");
  return Object.freeze({
    kind: "snapshot",
    resourceId: resourceId(f.bytes(0, 32)),
    dataEpoch: dataEpoch(f.uint(1)),
    publisher: principalId(f.bytes(2, 32)),
    snapshotSeq,
    controlHead: controlRecordId(f.bytes(4, 32)),
    frontier: canonicalFrontierFromCbor(f.any(5)),
    ciphertext: f.bytes(6),
  });
}

function decodePayload<P>(payloadBytes: Uint8Array, from: (value: CborValue) => P): P {
  if (!(payloadBytes instanceof Uint8Array)) invalid("payload", "not a byte string");
  return from(decodeDeterministic(payloadBytes));
}

function parseWith<P>(bytes: Uint8Array, from: (value: CborValue) => P): Parsed<P> {
  const signed = parseSignedObject(bytes); // also applies N7 to the payload
  return Object.freeze({ signed, payload: from(decodeStrict(signed.payloadBytes)) });
}

/** Decodes standalone payload bytes; they must be deterministic CBOR (N7). */
export const decodeControlRecordPayload = (payloadBytes: Uint8Array): ControlRecordPayload =>
  decodePayload(payloadBytes, controlRecordPayloadFromCbor);
export const decodeDataUnitPayload = (payloadBytes: Uint8Array): DataUnitPayload =>
  decodePayload(payloadBytes, dataUnitPayloadFromCbor);
export const decodeKeyPackagePayload = (payloadBytes: Uint8Array): KeyPackagePayload =>
  decodePayload(payloadBytes, keyPackagePayloadFromCbor);
export const decodeSnapshotPayload = (payloadBytes: Uint8Array): SnapshotPayload =>
  decodePayload(payloadBytes, snapshotPayloadFromCbor);

/** Parses a received Control Record (§13) without verifying its signature. */
export const parseControlRecord = (bytes: Uint8Array): Parsed<ControlRecordPayload> =>
  parseWith(bytes, controlRecordPayloadFromCbor);
/** Parses a received Data Unit (§26) without verifying its signature. */
export const parseDataUnit = (bytes: Uint8Array): Parsed<DataUnitPayload> =>
  parseWith(bytes, dataUnitPayloadFromCbor);
/** Parses a received Key Package (§25) without verifying its signature. */
export const parseKeyPackage = (bytes: Uint8Array): Parsed<KeyPackagePayload> =>
  parseWith(bytes, keyPackagePayloadFromCbor);
/** Parses a received Snapshot (§29) without verifying its signature. */
export const parseSnapshot = (bytes: Uint8Array): Parsed<SnapshotPayload> =>
  parseWith(bytes, snapshotPayloadFromCbor);

/**
 * The Principal that must have signed a data-plane object, read from its
 * payload: the actor of a Data Unit (§26), the sender of a Key Package
 * (§25) and the publisher of a Snapshot (§29). The caller resolves this ID to
 * a Principal Descriptor and passes it to `verifySignedObject`; a `kid` that
 * names anyone else fails as KID_MISMATCH (INVALID_SIGNATURE, G1/N2).
 *
 * Control Records have no hook: who must sign one depends on its type and on
 * the chain (LFCP-019 to LFCP-021). Their payload's `issuer` is exposed as is.
 */
export function expectedSignerOf(
  payload: DataUnitPayload | KeyPackagePayload | SnapshotPayload,
): PrincipalId {
  switch (payload.kind) {
    case "data-unit":
      return payload.actor;
    case "key-package":
      return payload.sender;
    case "snapshot":
      return payload.publisher;
  }
}
