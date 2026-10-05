import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  hash32,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
} from "@openlfcp/core";
import { type CborValue, cborMap, decodeStrict, encode } from "./cbor/index.js";
import {
  parseSignedObject,
  type SignedBytes,
  type Signer,
  signObject,
  type VerifyResult,
  verifySignedObject,
} from "./cose.js";
import { checkWriterUrl, type Endpoint, endpointFromCbor, endpointToCbor } from "./endpoint.js";
import { Fields } from "./fields.js";
import { type ActorHave, canonicalFrontierFromCbor, canonicalFrontierToCbor } from "./have.js";
import {
  CONTROL_TYPE,
  type ControlRecordPayload,
  controlRecordPayloadFromCbor,
  type Parsed,
  parseControlRecord,
} from "./objects.js";
import {
  type PrincipalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorToCbor,
} from "./principal.js";

/**
 * Typed Control Record bodies (LFCP-WIRE-01 §13-§24) and the Control
 * Record codec on top of the generic envelope (objects.ts, LFCP-016) and
 * canonical COSE_Sign1 (cose.ts, LFCP-015).
 *
 * Structure only: every body is a closed map with its CDDL field types.
 * Authority, chain linkage, claim limits, epoch succession and route
 * version monotonicity belong to LFCP-020 to LFCP-023. Decoding never
 * applies a record; `mvpSupported` tells those layers whether MVP 0.1
 * implements the type (.github docs/MVP-0.1-PROTOCOL-SCOPE.md §4 defers
 * coordinator recovery and Resource tombstones; ownership transfer is
 * verified and applied, its UI/flow deferred).
 *
 * Writers apply rules the prose states for creators but not as receiver
 * checks: wss:// URLs (loopback ws:// allowed), no reserved endpoint flag
 * bits, at most 256 UTF-8 bytes of reason or note text, a non-empty
 * ability list, and the Genesis invariants. Receivers check structure.
 */

export type ControlBody =
  | {
      readonly type: "GENESIS";
      readonly dataProfile: string;
      readonly owner: PrincipalDescriptor;
      readonly dekCommitment: Hash32;
      readonly endpoints: readonly Endpoint[];
      readonly coordinatorUrl: string;
    }
  | {
      readonly type: "CAPABILITY_GRANT";
      readonly subject: PrincipalDescriptor;
      readonly abilities: readonly bigint[];
      readonly delegable: readonly bigint[];
      readonly parentGrantId?: ControlRecordId;
      readonly claimLimit?: bigint;
    }
  | { readonly type: "CAPABILITY_REVOKE"; readonly grantId: ControlRecordId }
  | {
      readonly type: "CAPABILITY_CLAIM";
      readonly invitationGrantId: ControlRecordId;
      readonly claimant: PrincipalDescriptor;
      readonly abilities: readonly bigint[];
    }
  | {
      readonly type: "KEY_EPOCH";
      readonly epoch: DataEpoch;
      readonly dekCommitment: Hash32;
      /** Accepted final frontier of the previous epoch: canonical entries, one per Principal. */
      readonly finalFrontier: readonly ActorHave[];
      readonly reason: bigint;
    }
  | {
      readonly type: "ROUTE_UPDATE";
      readonly routeVersion: bigint;
      readonly endpoints: readonly Endpoint[];
      readonly coordinatorUrl: string;
    }
  | {
      readonly type: "OWNER_TRANSFER_COMMIT";
      /** Exact COSE bytes of the transfer offer and accept (§23.3); see parseOwnerTransferOffer/Accept. */
      readonly offer: Uint8Array;
      readonly accept: Uint8Array;
    }
  | {
      readonly type: "COORDINATOR_RECOVERY";
      readonly routeVersion: bigint;
      readonly endpoints: readonly Endpoint[];
      readonly coordinatorUrl: string;
      readonly reason: string;
    }
  | { readonly type: "RESOURCE_TOMBSTONE"; readonly reason: bigint; readonly note?: string }
  /** A §14 extension type (32 and up): kept, never interpreted. */
  | { readonly type: "EXTENSION"; readonly code: bigint; readonly body: CborValue };

export type ControlBodyType = ControlBody["type"];

const CODE: Readonly<Record<Exclude<ControlBodyType, "EXTENSION">, bigint>> = CONTROL_TYPE;

/**
 * §14 core types MVP 0.1 implements; the others decode but are not
 * applied. OWNER_TRANSFER_COMMIT is verified and applied
 * (MVP-0.1-PROTOCOL-SCOPE §4: "ownership transfer verification is in MVP
 * 0.1"). A chain containing Coordinator Recovery or Resource Tombstone is
 * refused (DV1, chain.ts); extensions are kept unapplied.
 */
const MVP_SUPPORTED: ReadonlySet<ControlBodyType> = new Set([
  "GENESIS",
  "CAPABILITY_GRANT",
  "CAPABILITY_REVOKE",
  "CAPABILITY_CLAIM",
  "KEY_EPOCH",
  "ROUTE_UPDATE",
  "OWNER_TRANSFER_COMMIT",
]);

/** Whether MVP 0.1 implements a body type (false for deferred core types and extensions). */
export const isMvpSupported = (type: ControlBodyType): boolean => MVP_SUPPORTED.has(type);

/** The §14 code of a body. */
export const controlTypeOf = (body: ControlBody): bigint =>
  body.type === "EXTENSION" ? body.code : CODE[body.type];

const MAX_TEXT_BYTES = 256;
const TEXT = new (
  globalThis as unknown as { TextEncoder: new () => { encode(s: string): Uint8Array } }
).TextEncoder();

// ---------------------------------------------------------------------------
// Decoding (receivers: structure only)

const id32 = (f: Fields, key: number): ControlRecordId => controlRecordId(f.bytes(key, 32));

function endpoints(f: Fields, key: number): readonly Endpoint[] {
  const list = f.array(key);
  if (list.length === 0) f.fail(key, "must list at least one endpoint");
  return Object.freeze(list.map(endpointFromCbor));
}

/**
 * The Key Epoch final frontier. PROVISIONAL (G-CP1, approved for
 * baseline.3): a canonical frontier, §28.1 rules 1-9 and the §28.2 order by
 * raw Principal ID; anything else is MALFORMED_MESSAGE.
 */
function frontierList(f: Fields, key: number): readonly ActorHave[] {
  return canonicalFrontierFromCbor(f.array(key) as CborValue);
}

/**
 * An ability list (§17.1 codes). PROVISIONAL (gap A1 / G-CP6): a code
 * listed twice makes the record malformed (INVALID_STRUCTURE, wire
 * MALFORMED_MESSAGE). Unknown codes are structurally valid and kept; they
 * confer nothing (capability.ts).
 */
function abilityList(f: Fields, key: number, nonEmpty: boolean): readonly bigint[] {
  const list = f.uintArray(key, nonEmpty);
  if (new Set(list).size !== list.length) f.fail(key, "lists an ability twice");
  return list;
}

/**
 * Decodes the body of a Control Record of §14 type `type`. Core types 0-8
 * get their closed-map structure; 9-31 are UNSUPPORTED_VALUE (§14:
 * INVALID_CONTROL_CHAIN on the wire); 32 and up are kept as opaque
 * EXTENSION bodies.
 */
export function controlBodyFromCbor(type: bigint, value: CborValue): ControlBody {
  switch (type) {
    case CONTROL_TYPE.GENESIS: {
      const f = new Fields(value, "genesis-body", [0, 1, 2, 3, 4]);
      return Object.freeze({
        type: "GENESIS",
        dataProfile: f.text(0),
        owner: principalDescriptorFromCbor(f.any(1)),
        dekCommitment: hash32(f.bytes(2, 32)),
        endpoints: endpoints(f, 3),
        coordinatorUrl: f.text(4),
      });
    }
    case CONTROL_TYPE.CAPABILITY_GRANT: {
      const f = new Fields(value, "capability-grant-body", [0, 1, 2], [3, 4]);
      return Object.freeze({
        type: "CAPABILITY_GRANT",
        subject: principalDescriptorFromCbor(f.any(0)),
        abilities: abilityList(f, 1, true),
        delegable: abilityList(f, 2, false),
        ...(f.has(3) ? { parentGrantId: id32(f, 3) } : {}),
        ...(f.has(4) ? { claimLimit: f.uint(4) } : {}),
      });
    }
    case CONTROL_TYPE.CAPABILITY_REVOKE: {
      const f = new Fields(value, "capability-revoke-body", [0]);
      return Object.freeze({ type: "CAPABILITY_REVOKE", grantId: id32(f, 0) });
    }
    case CONTROL_TYPE.CAPABILITY_CLAIM: {
      const f = new Fields(value, "capability-claim-body", [0, 1, 2]);
      return Object.freeze({
        type: "CAPABILITY_CLAIM",
        invitationGrantId: id32(f, 0),
        claimant: principalDescriptorFromCbor(f.any(1)),
        abilities: abilityList(f, 2, true),
      });
    }
    case CONTROL_TYPE.KEY_EPOCH: {
      const f = new Fields(value, "key-epoch-body", [0, 1, 2, 3]);
      return Object.freeze({
        type: "KEY_EPOCH",
        epoch: dataEpoch(f.uint(0)),
        dekCommitment: hash32(f.bytes(1, 32)),
        finalFrontier: frontierList(f, 2),
        reason: f.uint(3),
      });
    }
    case CONTROL_TYPE.ROUTE_UPDATE: {
      const f = new Fields(value, "route-update-body", [0, 1, 2]);
      return Object.freeze({
        type: "ROUTE_UPDATE",
        routeVersion: f.uint(0),
        endpoints: endpoints(f, 1),
        coordinatorUrl: f.text(2),
      });
    }
    case CONTROL_TYPE.OWNER_TRANSFER_COMMIT: {
      const f = new Fields(value, "owner-transfer-commit-body", [0, 1]);
      return Object.freeze({
        type: "OWNER_TRANSFER_COMMIT",
        offer: f.bytes(0),
        accept: f.bytes(1),
      });
    }
    case CONTROL_TYPE.COORDINATOR_RECOVERY: {
      const f = new Fields(value, "coordinator-recovery-body", [0, 1, 2, 3]);
      return Object.freeze({
        type: "COORDINATOR_RECOVERY",
        routeVersion: f.uint(0),
        endpoints: endpoints(f, 1),
        coordinatorUrl: f.text(2),
        reason: f.text(3),
      });
    }
    case CONTROL_TYPE.RESOURCE_TOMBSTONE: {
      const f = new Fields(value, "resource-tombstone-body", [0], [1]);
      return Object.freeze({
        type: "RESOURCE_TOMBSTONE",
        reason: f.uint(0),
        ...(f.has(1) ? { note: f.text(1) } : {}),
      });
    }
    default:
      if (type >= 32n) return Object.freeze({ type: "EXTENSION", code: type, body: value });
      throw new LfcpError(
        "UNSUPPORTED_VALUE",
        `Control Record type ${type} is reserved for LFCP core (§14)`,
      );
  }
}

/** A received Control Record: the exact object, its envelope and its typed body. Nothing is applied. */
export interface ControlRecord extends Parsed<ControlRecordPayload> {
  readonly body: ControlBody;
  /** False for MVP-deferred core types and extensions: LFCP-020/021 must not apply them. */
  readonly mvpSupported: boolean;
}

/**
 * Parses a received Control Record: canonical COSE and the generic
 * envelope (parseControlRecord), then the typed body. The record ID is
 * `signed.id`, SHA-256 of the exact received bytes. The signature is not
 * checked here; see controlRecordSigner and verifyGenesis.
 */
export function decodeControlRecord(bytes: Uint8Array): ControlRecord {
  const parsed = parseControlRecord(bytes);
  const body = controlBodyFromCbor(parsed.payload.controlType, parsed.payload.body);
  return Object.freeze({ ...parsed, body, mvpSupported: isMvpSupported(body.type) });
}

/**
 * The Principal whose key must have signed a Control Record: its issuer
 * (payload field 4). §13: "the protected-header kid MUST equal field 4,
 * and a record whose kid is any other Principal is rejected with
 * INVALID_SIGNATURE." Resolving the issuer to a descriptor (and checking
 * its authority) is LFCP-020/021.
 */
export const controlRecordSigner = (record: Parsed<ControlRecordPayload>): PrincipalId =>
  record.payload.issuer;

/**
 * Verifies a Genesis record against the owner in its own body (§15:
 * "MUST be signed by the owner Principal contained in the body"): the
 * issuer and the kid must be the owner and the signature must verify with
 * the owner's key. A failure surfaces as INVALID_SIGNATURE.
 */
export function verifyGenesis(
  record: ControlRecord,
): VerifyResult | { readonly valid: false; readonly reason: "NOT_GENESIS" | "ISSUER_NOT_OWNER" } {
  if (record.body.type !== "GENESIS") return { valid: false, reason: "NOT_GENESIS" };
  if (!bytesEqual(record.payload.issuer, record.body.owner.principalId))
    return { valid: false, reason: "ISSUER_NOT_OWNER" };
  return verifySignedObject(record.signed, record.body.owner);
}

// ---------------------------------------------------------------------------
// Encoding (writers)

function refuse(why: string): never {
  throw new LfcpError("INVALID_STRUCTURE", `refusing to write a Control Record: ${why}`);
}

function text256(what: string, s: string): string {
  if (typeof s !== "string") refuse(`${what} must be text`);
  if (TEXT.encode(s).length > MAX_TEXT_BYTES)
    refuse(`${what} must be at most ${MAX_TEXT_BYTES} UTF-8 bytes`);
  return s;
}

function writerEndpoints(list: readonly Endpoint[]): CborValue[] {
  if (list.length === 0) refuse("at least one endpoint is required");
  return list.map(endpointToCbor);
}

function writerUrl(url: string): string {
  checkWriterUrl(url);
  return url;
}

function abilities(list: readonly bigint[], nonEmpty: boolean): bigint[] {
  if (nonEmpty && list.length === 0) refuse("the ability list must not be empty");
  // PROVISIONAL (gap A1 / G-CP6): no ability twice in one list.
  if (new Set(list).size !== list.length) refuse("an ability is listed twice");
  return [...list];
}

/** The CBOR of a typed body, applying the writer rules. */
export function controlBodyToCbor(body: ControlBody): CborValue {
  switch (body.type) {
    case "GENESIS":
      return cborMap([
        [0, body.dataProfile],
        [1, principalDescriptorToCbor(body.owner)],
        [2, hash32(body.dekCommitment)],
        [3, writerEndpoints(body.endpoints)],
        [4, writerUrl(body.coordinatorUrl)],
      ]);
    case "CAPABILITY_GRANT":
      return cborMap([
        [0, principalDescriptorToCbor(body.subject)],
        [1, abilities(body.abilities, true)],
        [2, abilities(body.delegable, false)],
        ...(body.parentGrantId !== undefined
          ? [[3, controlRecordId(body.parentGrantId)] as const]
          : []),
        ...(body.claimLimit !== undefined ? [[4, body.claimLimit] as const] : []),
      ]);
    case "CAPABILITY_REVOKE":
      return cborMap([[0, controlRecordId(body.grantId)]]);
    case "CAPABILITY_CLAIM":
      return cborMap([
        [0, controlRecordId(body.invitationGrantId)],
        [1, principalDescriptorToCbor(body.claimant)],
        [2, abilities(body.abilities, true)],
      ]);
    case "KEY_EPOCH":
      return cborMap([
        [0, dataEpoch(body.epoch)],
        [1, hash32(body.dekCommitment)],
        [2, canonicalFrontierToCbor(body.finalFrontier)],
        [3, body.reason],
      ]);
    case "ROUTE_UPDATE":
      return cborMap([
        [0, body.routeVersion],
        [1, writerEndpoints(body.endpoints)],
        [2, writerUrl(body.coordinatorUrl)],
      ]);
    case "OWNER_TRANSFER_COMMIT":
      return cborMap([
        [0, Uint8Array.from(body.offer)],
        [1, Uint8Array.from(body.accept)],
      ]);
    case "COORDINATOR_RECOVERY":
      return cborMap([
        [0, body.routeVersion],
        [1, writerEndpoints(body.endpoints)],
        [2, writerUrl(body.coordinatorUrl)],
        [3, text256("the recovery reason", body.reason)],
      ]);
    case "RESOURCE_TOMBSTONE":
      return cborMap([
        [0, body.reason],
        ...(body.note !== undefined
          ? [[1, text256("the tombstone note", body.note)] as const]
          : []),
      ]);
    case "EXTENSION":
      if (body.code < 32n) refuse("extension types start at 32 (§14)");
      return body.body;
  }
}

/** The envelope fields a writer chooses; the type comes from the body and the issuer from the signer. */
export interface ControlRecordHeader {
  readonly resourceId: ResourceId;
  readonly controlSeq: bigint;
  readonly prevControlId: ControlRecordId | null;
}

/**
 * Deterministic CBOR of control-record-payload (§13) for `issuer`. Writer
 * rules: Genesis is at control_seq 0 with a null link and is issued by the
 * owner in its body; every other record has control_seq >= 1 and a link
 * (§13.1). The result is checked with the receiver's decoder too.
 */
export function encodeControlRecordPayload(
  header: ControlRecordHeader,
  issuer: PrincipalId,
  body: ControlBody,
): Uint8Array {
  const genesis = body.type === "GENESIS";
  if (genesis) {
    if (header.controlSeq !== 0n || header.prevControlId !== null)
      refuse("Genesis must have control_seq 0 and a null previous record (§13.1)");
    if (!bytesEqual(issuer, body.owner.principalId))
      refuse("Genesis must be issued by the owner in its body (§15)");
  } else if (header.controlSeq < 1n || header.prevControlId === null) {
    refuse("a non-Genesis record needs control_seq >= 1 and the previous record ID (§13.1)");
  }
  const payload = cborMap([
    [0, header.resourceId],
    [1, header.controlSeq],
    [2, header.prevControlId],
    [3, controlTypeOf(body)],
    [4, issuer],
    [5, controlBodyToCbor(body)],
  ]);
  const bytes = encode(payload);
  const check = controlRecordPayloadFromCbor(decodeStrict(bytes));
  controlBodyFromCbor(check.controlType, check.body);
  return bytes;
}

/** A newly signed Control Record: its exact bytes and its ID, SHA-256 of those bytes (§13, §10.6). */
export interface SignedControlRecord extends SignedBytes {
  readonly recordId: ControlRecordId;
}

/**
 * Signs a Control Record: typed payload -> deterministic CBOR -> canonical
 * untagged COSE_Sign1 (signObject) -> exact bytes -> SHA-256 = record ID.
 * The issuer is the signer's Principal (§13: kid = issuer, see
 * controlRecordSigner).
 */
export function signControlRecord(
  header: ControlRecordHeader,
  body: ControlBody,
  signer: Signer,
): SignedControlRecord {
  const payload = encodeControlRecordPayload(header, signer.descriptor.principalId, body);
  const signed = signObject(payload, signer);
  return Object.freeze({ ...signed, recordId: controlRecordId(signed.id) });
}

// ---------------------------------------------------------------------------
// Ownership transfer objects (§23; deferred from MVP 0.1: structure only)

export interface OwnerTransferOfferPayload {
  readonly resourceId: ResourceId;
  readonly controlHead: ControlRecordId;
  readonly expectedControlSeq: bigint;
  readonly proposedOwner: PrincipalDescriptor;
  readonly nonce: Uint8Array;
}

export interface OwnerTransferAcceptPayload {
  readonly resourceId: ResourceId;
  readonly offerId: Hash32;
  readonly newOwner: PrincipalId;
}

/** owner-transfer-offer-payload (§23.1). */
export function ownerTransferOfferPayloadFromCbor(value: CborValue): OwnerTransferOfferPayload {
  const f = new Fields(value, "owner-transfer-offer-payload", [0, 1, 2, 3, 4]);
  return Object.freeze({
    resourceId: resourceId(f.bytes(0, 32)),
    controlHead: id32(f, 1),
    expectedControlSeq: f.uint(2),
    proposedOwner: principalDescriptorFromCbor(f.any(3)),
    nonce: f.bytes(4, 16),
  });
}

/** owner-transfer-accept-payload (§23.2). */
export function ownerTransferAcceptPayloadFromCbor(value: CborValue): OwnerTransferAcceptPayload {
  const f = new Fields(value, "owner-transfer-accept-payload", [0, 1, 2]);
  return Object.freeze({
    resourceId: resourceId(f.bytes(0, 32)),
    offerId: hash32(f.bytes(1, 32)),
    newOwner: principalId(f.bytes(2, 32)),
  });
}

/** Parses a received transfer offer (canonical COSE, typed payload). Deferred from MVP 0.1: never applied. */
export function parseOwnerTransferOffer(bytes: Uint8Array): Parsed<OwnerTransferOfferPayload> {
  const signed = parseSignedObject(bytes);
  return Object.freeze({
    signed,
    payload: ownerTransferOfferPayloadFromCbor(decodeStrict(signed.payloadBytes)),
  });
}

/** Parses a received transfer accept (canonical COSE, typed payload). Deferred from MVP 0.1: never applied. */
export function parseOwnerTransferAccept(bytes: Uint8Array): Parsed<OwnerTransferAcceptPayload> {
  const signed = parseSignedObject(bytes);
  return Object.freeze({
    signed,
    payload: ownerTransferAcceptPayloadFromCbor(decodeStrict(signed.payloadBytes)),
  });
}
