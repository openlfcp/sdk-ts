import {
  type ControlRecordId,
  controlRecordId,
  type Hash32,
  hash32,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  secureRandom,
} from "@openlfcp/core";
import {
  type CborMap,
  type CborValue,
  cborMap,
  decodeDeterministic,
  encode,
  isCborMap,
} from "./cbor/index.js";
import { Fields, invalid } from "./fields.js";
import type { SequenceRange } from "./have.js";
import {
  type PrincipalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorToCbor,
} from "./principal.js";
import { type ControlPutBody, controlPutBodyFromCbor } from "./transition.js";

/**
 * The LFCP message codec (LFCP-WIRE-01 §31-§62): the §32 envelope, the §33
 * registry and every body. Representation only: no sockets, no session
 * state and no server logic.
 *
 * Decoding is strict, in this order:
 *  1. the frame is binary (§31; a text frame is MALFORMED_MESSAGE and the
 *     connection closes, G-MSG7) and no larger than the limit in force
 *     (MESSAGE_TOO_LARGE, checked before any decoding);
 *  2. one deterministic CBOR map (§5.2, §32) → MALFORMED_MESSAGE;
 *  3. the envelope: keys 0, 1 and 4 present; 2 and 3 optional; any other
 *     key from 0 to 15 is MALFORMED_MESSAGE; keys above 15 are ignored and
 *     dropped (G-MSG2); 16-byte message and correlation IDs; flags are a
 *     uint and otherwise ignored (G-MSG3);
 *  4. the type is assigned in §33, or a negotiated extension (128+);
 *     anything else is PROTOCOL_UNSUPPORTED (G-MSG1);
 *  5. the body is the closed map its section defines → MALFORMED_MESSAGE.
 *
 * Persistent objects inside bodies (Genesis, Control Records, Data Units,
 * Key Packages, Snapshots, the AUTH proof) stay the exact received byte
 * strings: they are parsed lazily with parseControlRecord, parseDataUnit
 * and the like, and are never re-encoded. Live actor-haves are decoded as
 * received; normalizing them and refusing reversed ranges or sequence 0
 * (§48, G-HV1) is LFCP-028, through DecodeOptions.liveHave.
 */

/** §33 message type codes. */
export const MESSAGE_TYPE = Object.freeze({
  HELLO: 0n,
  CHALLENGE: 1n,
  AUTH: 2n,
  READY: 3n,
  ERROR: 4n,
  PING: 5n,
  PONG: 6n,
  RESOURCE_HOST: 10n,
  RESOURCE_HOSTED: 11n,
  RESOURCE_OPEN: 12n,
  RESOURCE_OPENED: 13n,
  RESOURCE_CLOSE: 14n,
  CONTROL_HAVE: 20n,
  CONTROL_GET: 21n,
  CONTROL_BATCH: 22n,
  CONTROL_PUT: 23n,
  DATA_HAVE: 30n,
  DATA_GET: 31n,
  DATA_BATCH: 32n,
  DATA_PUT: 33n,
  KEY_PACKAGE_GET: 40n,
  KEY_PACKAGE_BATCH: 41n,
  KEY_PACKAGE_PUT: 42n,
  SNAPSHOT_GET: 50n,
  SNAPSHOT: 51n,
  SNAPSHOT_PUT: 52n,
  PRESENCE: 60n,
  PRESENCE_LEAVE: 61n,
  ACK: 90n,
  NACK: 91n,
});

export type CoreMessageType = keyof typeof MESSAGE_TYPE;
const TYPE_NAMES: ReadonlyMap<bigint, CoreMessageType> = new Map(
  Object.entries(MESSAGE_TYPE).map(([name, code]) => [code, name as CoreMessageType]),
);
/** Codes 128 and up are extension message types; they must be negotiated (§33). */
export const FIRST_EXTENSION_MESSAGE_TYPE = 128n;

/** §62 error codes. */
export const ERROR_CODE = Object.freeze({
  PROTOCOL_UNSUPPORTED: 1n,
  MALFORMED_MESSAGE: 2n,
  AUTH_FAILED: 3n,
  AUTHORIZATION_FAILED: 4n,
  RESOURCE_NOT_FOUND: 5n,
  RESOURCE_NOT_HOSTED: 6n,
  INVALID_SIGNATURE: 7n,
  INVALID_CONTROL_CHAIN: 8n,
  CONTROL_CONFLICT: 9n,
  CONTROL_HEAD_MISMATCH: 10n,
  NOT_CONTROL_COORDINATOR: 11n,
  PROFILE_UNSUPPORTED: 12n,
  KEY_PACKAGE_UNAVAILABLE: 13n,
  STALE_DATA_EPOCH: 14n,
  MISSING_DEPENDENCY: 15n,
  ACTOR_EQUIVOCATION: 16n,
  RATE_LIMITED: 17n,
  QUOTA_EXCEEDED: 18n,
  MESSAGE_TOO_LARGE: 19n,
  HOSTING_DENIED: 20n,
  RESOURCE_TOMBSTONED: 21n,
  INTERNAL_ERROR: 22n,
});
export type WireErrorName = keyof typeof ERROR_CODE;

/** §31: the default maximum LFCP message size, unless READY advertises another. */
export const DEFAULT_MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

const ID16 = 16;

// ---------------------------------------------------------------------------
// Bodies

/** A §41 `control-head`. */
export interface ControlHeadRef {
  readonly seq: bigint;
  readonly recordId: ControlRecordId;
}

/**
 * A live `actor-have` as received (§48): ranges may be unsorted,
 * overlapping or even reversed here; LFCP-028 normalizes and validates
 * them. `ranges` is undefined when the CBOR omits key 2.
 */
export interface LiveActorHave {
  readonly principalId: PrincipalId;
  readonly contiguous: bigint;
  readonly ranges?: readonly SequenceRange[];
}

export interface HelloBody {
  readonly wireProfiles: readonly string[];
  readonly principal: PrincipalDescriptor;
  readonly clientNonce: Uint8Array;
  readonly dataProfiles?: readonly string[];
}
export interface ChallengeBody {
  readonly wireProfile: string;
  readonly serverNonce: Uint8Array;
  readonly sessionId: Uint8Array;
  readonly serverId: Uint8Array;
}
export interface AuthBody {
  /** The exact COSE_Sign1 auth proof bytes (§36), verified by LFCP-027. */
  readonly proof: Uint8Array;
  /** An opaque hosting/account credential: server policy, never Resource authority. */
  readonly credential?: Uint8Array;
}
export interface ReadyBody {
  readonly wireProfile: string;
  readonly serverId: Uint8Array;
  readonly maxMessageBytes: bigint;
  readonly durability: bigint;
  readonly heartbeatMs: bigint;
  readonly extensions?: readonly string[];
}
/** ERROR (§61) and NACK (§60). Diagnostics never carry secrets. */
export interface ErrorBody {
  readonly code: bigint;
  readonly diagnostic?: string;
  readonly details?: CborValue;
}
export interface PingBody {
  readonly payload: Uint8Array;
}
export interface ResourceHostBody {
  /** The exact Genesis COSE bytes. */
  readonly genesis: Uint8Array;
  readonly credential?: Uint8Array;
}
export interface ResourceHostedBody {
  readonly resourceId: ResourceId;
  readonly durability: bigint;
}
export interface ResourceOpenBody {
  readonly resourceId: ResourceId;
  readonly heads: readonly ControlHeadRef[];
  readonly haves: readonly LiveActorHave[];
  readonly grantIds?: readonly Hash32[];
  readonly flags?: bigint;
}
export interface SnapshotSummary {
  readonly snapshotId: Hash32;
  readonly dataEpoch: bigint;
  readonly frontier: readonly LiveActorHave[];
}
export interface ResourceOpenedBody {
  readonly resourceId: ResourceId;
  readonly heads: readonly ControlHeadRef[];
  readonly haves: readonly LiveActorHave[];
  readonly snapshot?: SnapshotSummary;
  readonly routeVersion?: bigint;
  readonly coordinatorUrl?: string;
}
export interface ResourceBody {
  readonly resourceId: ResourceId;
}
export interface ControlHaveBody {
  readonly resourceId: ResourceId;
  readonly heads: readonly ControlHeadRef[];
}
export interface ControlGetBody {
  readonly resourceId: ResourceId;
  readonly start: bigint;
  readonly end: bigint;
}
/** CONTROL_BATCH, DATA_BATCH/PUT, KEY_PACKAGE_BATCH/PUT: exact signed object bytes. */
export interface ObjectListBody {
  readonly resourceId: ResourceId;
  readonly objects: readonly Uint8Array[];
}
export interface DataHaveBody {
  readonly resourceId: ResourceId;
  readonly haves: readonly LiveActorHave[];
}
export interface DataRange {
  readonly actor: PrincipalId;
  readonly start: bigint;
  readonly end: bigint;
}
export interface DataGetBody {
  readonly resourceId: ResourceId;
  readonly ranges: readonly DataRange[];
}
export interface KeyPackageGetBody {
  readonly resourceId: ResourceId;
  readonly recipient: PrincipalId;
  readonly epochs: readonly bigint[];
}
export interface SnapshotGetBody {
  readonly resourceId: ResourceId;
  readonly snapshotId?: Hash32;
}
/** SNAPSHOT and SNAPSHOT_PUT: the exact signed Snapshot bytes. */
export interface SnapshotBody {
  readonly resourceId: ResourceId;
  readonly snapshot: Uint8Array;
}
export interface PresenceBody {
  readonly resourceId: ResourceId;
  readonly principalId: PrincipalId;
  readonly ttlMs: bigint;
  readonly payload: Uint8Array;
}
export interface PresenceLeaveBody {
  readonly resourceId: ResourceId;
  readonly principalId: PrincipalId;
}
export interface AckBody {
  /** The §33 type code of the acknowledged request (A1), e.g. 33 for DATA_PUT. */
  readonly requestType: bigint;
  readonly objectIds?: readonly Hash32[];
  /** Durable under the advertised server policy; never stronger than READY's level (§37). */
  readonly durable?: boolean;
}

/** The body of each §33 message type. */
export interface MessageBodies {
  HELLO: HelloBody;
  CHALLENGE: ChallengeBody;
  AUTH: AuthBody;
  READY: ReadyBody;
  ERROR: ErrorBody;
  PING: PingBody;
  PONG: PingBody;
  RESOURCE_HOST: ResourceHostBody;
  RESOURCE_HOSTED: ResourceHostedBody;
  RESOURCE_OPEN: ResourceOpenBody;
  RESOURCE_OPENED: ResourceOpenedBody;
  RESOURCE_CLOSE: ResourceBody;
  CONTROL_HAVE: ControlHaveBody;
  CONTROL_GET: ControlGetBody;
  CONTROL_BATCH: ObjectListBody;
  CONTROL_PUT: ControlPutBody;
  DATA_HAVE: DataHaveBody;
  DATA_GET: DataGetBody;
  DATA_BATCH: ObjectListBody;
  DATA_PUT: ObjectListBody;
  KEY_PACKAGE_GET: KeyPackageGetBody;
  KEY_PACKAGE_BATCH: ObjectListBody;
  KEY_PACKAGE_PUT: ObjectListBody;
  SNAPSHOT_GET: SnapshotGetBody;
  SNAPSHOT: SnapshotBody;
  SNAPSHOT_PUT: SnapshotBody;
  PRESENCE: PresenceBody;
  PRESENCE_LEAVE: PresenceLeaveBody;
  ACK: AckBody;
  NACK: ErrorBody;
}

interface Envelope {
  /** 16 random bytes: transport correlation only, not a security identifier (§32). */
  readonly messageId: Uint8Array;
  readonly correlationId?: Uint8Array;
  /** The flags as received; a receiver ignores them and a sender omits them (G-MSG3). */
  readonly flags?: bigint;
}

/** A typed LFCP message. */
export type LfcpMessage<T extends CoreMessageType = CoreMessageType> = {
  [K in T]: Envelope & { readonly type: K; readonly body: MessageBodies[K] };
}[T];

/** A negotiated extension message (128+): the body is opaque to this codec. */
export type ExtensionMessage = Envelope & {
  readonly type: "EXTENSION";
  readonly code: bigint;
  readonly body: CborValue;
};

export type AnyMessage = LfcpMessage | ExtensionMessage;

// ---------------------------------------------------------------------------
// Body codecs

interface BodyCodec<B> {
  decode(value: CborValue, options: DecodeOptions): B;
  encode(body: B): CborValue;
}

const rid = (f: Fields, k: number): ResourceId => resourceId(f.bytes(k, 32));
const textList = (f: Fields, k: number, nonEmpty: boolean): readonly string[] => {
  const list = f.array(k);
  if (nonEmpty && list.length === 0) f.fail(k, "must not be empty");
  return Object.freeze(
    list.map((v) => (typeof v === "string" ? v : f.fail(k, "must hold text strings only"))),
  );
};
const bytesList = (f: Fields, k: number, nonEmpty: boolean, length?: number): Uint8Array[] => {
  const list = f.array(k);
  if (nonEmpty && list.length === 0) f.fail(k, "must not be empty");
  return list.map((v) => {
    if (!(v instanceof Uint8Array)) f.fail(k, "must hold byte strings only");
    if (length !== undefined && v.length !== length) f.fail(k, `must hold ${length}-byte strings`);
    return Uint8Array.from(v);
  });
};
const maybe = <V>(present: boolean, entry: () => [number, V]): [number, V][] =>
  present ? [entry()] : [];
/** cborMap over entries whose optional members were left out. */
const map = (entries: [number, unknown][]): CborMap => cborMap(entries as never);

function uintValue(what: string, v: CborValue): bigint {
  if ((typeof v === "number" || typeof v === "bigint") && v >= 0) return BigInt(v);
  return invalid(what, "must be an unsigned integer");
}

function controlHeads(f: Fields, k: number): readonly ControlHeadRef[] {
  return Object.freeze(
    f.array(k).map((v) => {
      const h = new Fields(v, "control-head", [0, 1]);
      return Object.freeze({ seq: h.uint(0), recordId: controlRecordId(h.bytes(1, 32)) });
    }),
  );
}
const controlHeadsToCbor = (heads: readonly ControlHeadRef[]) =>
  heads.map((h) =>
    map([
      [0, h.seq],
      [1, h.recordId],
    ]),
  );

function liveHave(value: CborValue, options: DecodeOptions): LiveActorHave {
  const what = "actor-have";
  const f = new Fields(value, what, [0, 1], [2]);
  const have: LiveActorHave = Object.freeze({
    principalId: principalId(f.bytes(0, 32)),
    contiguous: f.uint(1),
    ...(f.has(2)
      ? {
          ranges: Object.freeze(
            f.array(2).map((r) => {
              if (!Array.isArray(r) || r.length !== 2)
                return invalid(what, "a sequence range must be [start, end]");
              return Object.freeze([
                uintValue(what, r[0] as CborValue),
                uintValue(what, r[1] as CborValue),
              ]) as SequenceRange;
            }),
          ),
        }
      : {}),
  });
  options.liveHave?.(have);
  return have;
}
const liveHaves = (f: Fields, k: number, options: DecodeOptions): readonly LiveActorHave[] =>
  Object.freeze(f.array(k).map((v) => liveHave(v, options)));
const liveHavesToCbor = (haves: readonly LiveActorHave[]) =>
  haves.map((h) =>
    map([
      [0, h.principalId],
      [1, h.contiguous],
      ...maybe(h.ranges !== undefined, () => [2, (h.ranges ?? []).map((r) => [r[0], r[1]])]),
    ]),
  );

const errorBody = (what: string): BodyCodec<ErrorBody> => ({
  decode(value) {
    const f = new Fields(value, what, [0], [1, 2]);
    return Object.freeze({
      code: f.uint(0),
      ...(f.has(1) ? { diagnostic: f.text(1) } : {}),
      ...(f.has(2) ? { details: f.any(2) } : {}),
    });
  },
  encode: (b) =>
    map([
      [0, b.code],
      ...maybe(b.diagnostic !== undefined, () => [1, b.diagnostic]),
      ...maybe(b.details !== undefined, () => [2, b.details]),
    ]),
});

const pingBody = (what: string): BodyCodec<PingBody> => ({
  decode(value) {
    const f = new Fields(value, what, [0]);
    return Object.freeze({ payload: f.bytes(0, 8) });
  },
  encode: (b) => map([[0, b.payload]]),
});

/** {0 resource-id, 1 [* bstr]} or, for puts, [1* bstr]. */
const objectList = (what: string, nonEmpty: boolean): BodyCodec<ObjectListBody> => ({
  decode(value) {
    const f = new Fields(value, what, [0, 1]);
    return Object.freeze({
      resourceId: rid(f, 0),
      objects: Object.freeze(bytesList(f, 1, nonEmpty)),
    });
  },
  encode: (b) =>
    map([
      [0, b.resourceId],
      [1, [...b.objects]],
    ]),
});

const snapshotBody = (what: string): BodyCodec<SnapshotBody> => ({
  decode(value) {
    const f = new Fields(value, what, [0, 1]);
    return Object.freeze({ resourceId: rid(f, 0), snapshot: f.bytes(1) });
  },
  encode: (b) =>
    map([
      [0, b.resourceId],
      [1, b.snapshot],
    ]),
});

const resourceOnly: BodyCodec<ResourceBody> = {
  decode(value) {
    return Object.freeze({ resourceId: rid(new Fields(value, "resource-close-body", [0]), 0) });
  },
  encode: (b) => map([[0, b.resourceId]]),
};

const CODECS: { readonly [K in CoreMessageType]: BodyCodec<MessageBodies[K]> } = {
  HELLO: {
    decode(value) {
      const f = new Fields(value, "hello-body", [0, 1, 2], [3]);
      return Object.freeze({
        wireProfiles: textList(f, 0, true),
        principal: principalDescriptorFromCbor(f.any(1)),
        clientNonce: f.bytes(2, ID16),
        ...(f.has(3) ? { dataProfiles: textList(f, 3, false) } : {}),
      });
    },
    encode: (b) =>
      map([
        [0, [...b.wireProfiles]],
        [1, principalDescriptorToCbor(b.principal)],
        [2, b.clientNonce],
        ...maybe(b.dataProfiles !== undefined, () => [3, [...(b.dataProfiles ?? [])]]),
      ]),
  },
  CHALLENGE: {
    decode(value) {
      const f = new Fields(value, "challenge-body", [0, 1, 2, 3]);
      return Object.freeze({
        wireProfile: f.text(0),
        serverNonce: f.bytes(1, ID16),
        sessionId: f.bytes(2, ID16),
        serverId: f.bytes(3, 32),
      });
    },
    encode: (b) =>
      map([
        [0, b.wireProfile],
        [1, b.serverNonce],
        [2, b.sessionId],
        [3, b.serverId],
      ]),
  },
  AUTH: {
    decode(value) {
      const f = new Fields(value, "auth-body", [0], [1]);
      return Object.freeze({ proof: f.bytes(0), ...(f.has(1) ? { credential: f.bytes(1) } : {}) });
    },
    encode: (b) =>
      map([[0, b.proof], ...maybe(b.credential !== undefined, () => [1, b.credential])]),
  },
  READY: {
    decode(value) {
      const f = new Fields(value, "ready-body", [0, 1, 2, 3, 4], [5]);
      return Object.freeze({
        wireProfile: f.text(0),
        serverId: f.bytes(1, 32),
        maxMessageBytes: f.uint(2),
        durability: f.uint(3),
        heartbeatMs: f.uint(4),
        ...(f.has(5) ? { extensions: textList(f, 5, false) } : {}),
      });
    },
    encode: (b) =>
      map([
        [0, b.wireProfile],
        [1, b.serverId],
        [2, b.maxMessageBytes],
        [3, b.durability],
        [4, b.heartbeatMs],
        ...maybe(b.extensions !== undefined, () => [5, [...(b.extensions ?? [])]]),
      ]),
  },
  ERROR: errorBody("error-body"),
  PING: pingBody("ping-body"),
  PONG: pingBody("pong-body"),
  RESOURCE_HOST: {
    decode(value) {
      const f = new Fields(value, "resource-host-body", [0], [1]);
      return Object.freeze({
        genesis: f.bytes(0),
        ...(f.has(1) ? { credential: f.bytes(1) } : {}),
      });
    },
    encode: (b) =>
      map([[0, b.genesis], ...maybe(b.credential !== undefined, () => [1, b.credential])]),
  },
  RESOURCE_HOSTED: {
    decode(value) {
      const f = new Fields(value, "resource-hosted-body", [0, 1]);
      return Object.freeze({ resourceId: rid(f, 0), durability: f.uint(1) });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.durability],
      ]),
  },
  RESOURCE_OPEN: {
    decode(value, options) {
      const f = new Fields(value, "resource-open-body", [0, 1, 2], [3, 4]);
      return Object.freeze({
        resourceId: rid(f, 0),
        heads: controlHeads(f, 1),
        haves: liveHaves(f, 2, options),
        ...(f.has(3) ? { grantIds: Object.freeze(bytesList(f, 3, false, 32).map(hash32)) } : {}),
        ...(f.has(4) ? { flags: f.uint(4) } : {}),
      });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, controlHeadsToCbor(b.heads)],
        [2, liveHavesToCbor(b.haves)],
        ...maybe(b.grantIds !== undefined, () => [3, [...(b.grantIds ?? [])]]),
        ...maybe(b.flags !== undefined, () => [4, b.flags]),
      ]),
  },
  RESOURCE_OPENED: {
    decode(value, options) {
      const f = new Fields(value, "resource-opened-body", [0, 1, 2], [3, 4, 5]);
      let snapshot: SnapshotSummary | undefined;
      if (f.has(3)) {
        const s = new Fields(f.any(3), "snapshot-summary", [0, 1, 2]);
        snapshot = Object.freeze({
          snapshotId: hash32(s.bytes(0, 32)),
          dataEpoch: s.uint(1),
          frontier: liveHaves(s, 2, options),
        });
      }
      return Object.freeze({
        resourceId: rid(f, 0),
        heads: controlHeads(f, 1),
        haves: liveHaves(f, 2, options),
        ...(snapshot !== undefined ? { snapshot } : {}),
        ...(f.has(4) ? { routeVersion: f.uint(4) } : {}),
        ...(f.has(5) ? { coordinatorUrl: f.text(5) } : {}),
      });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, controlHeadsToCbor(b.heads)],
        [2, liveHavesToCbor(b.haves)],
        ...maybe(b.snapshot !== undefined, () => [
          3,
          map([
            [0, b.snapshot?.snapshotId],
            [1, b.snapshot?.dataEpoch],
            [2, liveHavesToCbor(b.snapshot?.frontier ?? [])],
          ]),
        ]),
        ...maybe(b.routeVersion !== undefined, () => [4, b.routeVersion]),
        ...maybe(b.coordinatorUrl !== undefined, () => [5, b.coordinatorUrl]),
      ]),
  },
  RESOURCE_CLOSE: resourceOnly,
  CONTROL_HAVE: {
    decode(value) {
      const f = new Fields(value, "control-have-body", [0, 1]);
      return Object.freeze({ resourceId: rid(f, 0), heads: controlHeads(f, 1) });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, controlHeadsToCbor(b.heads)],
      ]),
  },
  CONTROL_GET: {
    decode(value) {
      const f = new Fields(value, "control-get-body", [0, 1, 2]);
      return Object.freeze({ resourceId: rid(f, 0), start: f.uint(1), end: f.uint(2) });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.start],
        [2, b.end],
      ]),
  },
  CONTROL_BATCH: objectList("control-batch-body", false),
  // §47 (G-MSG5): field 1 is hash32; a null expected head does not decode.
  CONTROL_PUT: {
    decode: (value) => controlPutBodyFromCbor(value),
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.expectedHead],
        [2, b.record],
      ]),
  },
  DATA_HAVE: {
    decode(value, options) {
      const f = new Fields(value, "data-have-body", [0, 1]);
      return Object.freeze({ resourceId: rid(f, 0), haves: liveHaves(f, 1, options) });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, liveHavesToCbor(b.haves)],
      ]),
  },
  DATA_GET: {
    decode(value) {
      const f = new Fields(value, "data-get-body", [0, 1]);
      const list = f.array(1);
      if (list.length === 0) f.fail(1, "must not be empty");
      return Object.freeze({
        resourceId: rid(f, 0),
        ranges: Object.freeze(
          list.map((v) => {
            const r = new Fields(v, "data-range", [0, 1, 2]);
            return Object.freeze({
              actor: principalId(r.bytes(0, 32)),
              start: r.uint(1),
              end: r.uint(2),
            });
          }),
        ),
      });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [
          1,
          b.ranges.map((r) =>
            map([
              [0, r.actor],
              [1, r.start],
              [2, r.end],
            ]),
          ),
        ],
      ]),
  },
  DATA_BATCH: objectList("data-batch-body", false),
  DATA_PUT: objectList("data-put-body", true),
  KEY_PACKAGE_GET: {
    decode(value) {
      const f = new Fields(value, "key-package-get-body", [0, 1, 2]);
      return Object.freeze({
        resourceId: rid(f, 0),
        recipient: principalId(f.bytes(1, 32)),
        epochs: f.uintArray(2, true),
      });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.recipient],
        [2, [...b.epochs]],
      ]),
  },
  KEY_PACKAGE_BATCH: objectList("key-package-batch-body", false),
  KEY_PACKAGE_PUT: objectList("key-package-put-body", true),
  SNAPSHOT_GET: {
    decode(value) {
      const f = new Fields(value, "snapshot-get-body", [0], [1]);
      return Object.freeze({
        resourceId: rid(f, 0),
        ...(f.has(1) ? { snapshotId: hash32(f.bytes(1, 32)) } : {}),
      });
    },
    encode: (b) =>
      map([[0, b.resourceId], ...maybe(b.snapshotId !== undefined, () => [1, b.snapshotId])]),
  },
  SNAPSHOT: snapshotBody("snapshot-body"),
  SNAPSHOT_PUT: snapshotBody("snapshot-put-body"),
  // Presence (§58) is optional and MVP-deferred: structure only.
  PRESENCE: {
    decode(value) {
      const f = new Fields(value, "presence-body", [0, 1, 2, 3]);
      return Object.freeze({
        resourceId: rid(f, 0),
        principalId: principalId(f.bytes(1, 32)),
        ttlMs: f.uint(2),
        payload: f.bytes(3),
      });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.principalId],
        [2, b.ttlMs],
        [3, b.payload],
      ]),
  },
  PRESENCE_LEAVE: {
    decode(value) {
      const f = new Fields(value, "presence-leave-body", [0, 1]);
      return Object.freeze({ resourceId: rid(f, 0), principalId: principalId(f.bytes(1, 32)) });
    },
    encode: (b) =>
      map([
        [0, b.resourceId],
        [1, b.principalId],
      ]),
  },
  ACK: {
    decode(value) {
      const f = new Fields(value, "ack-body", [0], [1, 2]);
      let durable: boolean | undefined;
      if (f.has(2)) {
        const v = f.any(2);
        durable = typeof v === "boolean" ? v : f.fail(2, "must be a boolean");
      }
      return Object.freeze({
        requestType: f.uint(0),
        ...(f.has(1) ? { objectIds: Object.freeze(bytesList(f, 1, false, 32).map(hash32)) } : {}),
        ...(durable !== undefined ? { durable } : {}),
      });
    },
    encode: (b) =>
      map([
        [0, b.requestType],
        ...maybe(b.objectIds !== undefined, () => [1, [...(b.objectIds ?? [])]]),
        ...maybe(b.durable !== undefined, () => [2, b.durable]),
      ]),
  },
  NACK: {
    decode(value, options) {
      const body = errorBody("nack-body").decode(value, options);
      // §47 (G-MSG5): NACK(CONTROL_HEAD_MISMATCH) carries the current head's record ID.
      if (body.code === ERROR_CODE.CONTROL_HEAD_MISMATCH) {
        const d = body.details;
        if (!(d instanceof Uint8Array) || d.length !== 32)
          invalid("nack-body", "CONTROL_HEAD_MISMATCH details must be the 32-byte current head");
      }
      return body;
    },
    encode: (b) => errorBody("nack-body").encode(b),
  },
};

// ---------------------------------------------------------------------------
// Envelope

export interface DecodeOptions {
  /** The maximum message size in force (§31): READY's advertised value, or the default 8 MiB. */
  readonly maxMessageBytes?: number;
  /** Extension message types (128+) negotiated for the session; others are PROTOCOL_UNSUPPORTED. */
  readonly extensions?: ReadonlySet<bigint>;
  /** Called for every live actor-have as decoded; throws to reject it (LFCP-028 hook, §48). */
  readonly liveHave?: (have: LiveActorHave) => void;
}

/** A fresh random 128-bit Message ID (§32). */
export const newMessageId = (): Uint8Array => secureRandom(ID16);

/**
 * Decodes one LFCP message: size, deterministic CBOR, envelope, registry
 * and body, in that order (see the module comment). Throws LfcpError:
 * MESSAGE_TOO_LARGE, PROTOCOL_UNSUPPORTED, or a structural code (CBOR_*,
 * INVALID_STRUCTURE, INVALID_PRINCIPAL_DESCRIPTOR, ...) that
 * messageErrorWireCode maps to its §62 code.
 */
export function decodeMessage(bytes: Uint8Array, options: DecodeOptions = {}): AnyMessage {
  const { code, body: bodyValue, ...envelope } = decodeEnvelope(bytes, options);
  const name = TYPE_NAMES.get(code);
  if (name === undefined) {
    if (code >= FIRST_EXTENSION_MESSAGE_TYPE && options.extensions?.has(code))
      return Object.freeze({ ...envelope, type: "EXTENSION", code, body: bodyValue });
    throw new LfcpError(
      "PROTOCOL_UNSUPPORTED",
      code >= FIRST_EXTENSION_MESSAGE_TYPE
        ? `extension message type ${code} was not negotiated (§33)`
        : `message type ${code} is not assigned (§33)`,
    );
  }
  const body = (CODECS[name] as BodyCodec<unknown>).decode(bodyValue, options);
  return Object.freeze({ ...envelope, type: name, body }) as LfcpMessage;
}

/** The §32 envelope of a message, with its type code and its body still untyped. */
export interface DecodedEnvelope extends Envelope {
  readonly code: bigint;
  readonly body: CborValue;
}

/**
 * Steps 1-3 of decodeMessage: the size limit (before any decoding), one
 * deterministic CBOR map, and the §32 envelope. Keys above 15 are dropped
 * (G-MSG2). The type is not checked against the registry and the body is
 * not decoded, so a router can read the type and IDs first.
 */
export function decodeEnvelope(bytes: Uint8Array, options: DecodeOptions = {}): DecodedEnvelope {
  const limit = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  if (!(bytes instanceof Uint8Array)) throw new LfcpError("INVALID_STRUCTURE", "not bytes");
  if (bytes.length > limit)
    throw new LfcpError(
      "MESSAGE_TOO_LARGE",
      `the message is ${bytes.length} bytes; the limit is ${limit} (§31)`,
    );
  const value = decodeDeterministic(bytes);
  if (!isCborMap(value)) invalid("lfcp-message", "not a map");
  const fields = new Map<number, CborValue>();
  for (const [key, field] of value.entries) {
    if (typeof key !== "number" && typeof key !== "bigint")
      invalid("lfcp-message", "keys must be unsigned integers");
    const k = BigInt(key);
    if (k > 15n) continue; // G-MSG2: ignored, not preserved
    if (k < 0n || k > 4n) invalid("lfcp-message", `envelope key ${k} is not defined (§32)`);
    fields.set(Number(k), field);
  }
  const f = new Fields(cborMap([...fields.entries()]), "lfcp-message", [0, 1, 4], [2, 3]);
  return Object.freeze({
    code: f.uint(0),
    messageId: f.bytes(1, ID16),
    ...(f.has(2) ? { correlationId: f.bytes(2, ID16) } : {}),
    ...(f.has(3) ? { flags: f.uint(3) } : {}),
    body: f.any(4),
  });
}

/**
 * Encodes a message as deterministic CBOR. Flags are written only when
 * given, and only as 0 (§32: a sender sets flags to 0 or omits them).
 * Persistent objects in the body are written as the exact bytes given.
 */
export function encodeMessage(message: AnyMessage): Uint8Array {
  const id = (what: string, v: unknown): Uint8Array => {
    if (!(v instanceof Uint8Array) || v.length !== ID16)
      throw new LfcpError("INVALID_STRUCTURE", `the ${what} must be ${ID16} bytes`);
    return v;
  };
  if (message.flags !== undefined && message.flags !== 0n)
    throw new LfcpError("INVALID_STRUCTURE", "a sender sets flags to 0 or omits them (§32)");
  let code: bigint;
  let body: CborValue;
  if (message.type === "EXTENSION") {
    if (message.code < FIRST_EXTENSION_MESSAGE_TYPE)
      throw new LfcpError("INVALID_STRUCTURE", "extension message types start at 128 (§33)");
    code = message.code;
    body = message.body;
  } else {
    code = MESSAGE_TYPE[message.type];
    body = (CODECS[message.type] as BodyCodec<unknown>).encode(message.body);
  }
  const bytes = encode(
    map([
      [0, code],
      [1, id("message id", message.messageId)],
      ...maybe(message.correlationId !== undefined, () => [
        2,
        id("correlation id", message.correlationId),
      ]),
      ...maybe(message.flags !== undefined, () => [3, 0n]),
      [4, body],
    ]),
  );
  if (message.type !== "EXTENSION") decodeMessage(bytes, { maxMessageBytes: Infinity });
  return bytes;
}

/** A new message of `type` with a fresh Message ID. */
export function createMessage<T extends CoreMessageType>(
  type: T,
  body: MessageBodies[T],
): LfcpMessage<T> {
  return Object.freeze({ type, messageId: newMessageId(), body }) as LfcpMessage<T>;
}

/** A response to `request`: a fresh Message ID, correlated to the request's (§32). */
export function replyTo<T extends CoreMessageType>(
  request: Pick<AnyMessage, "messageId">,
  type: T,
  body: MessageBodies[T],
): LfcpMessage<T> {
  return Object.freeze({
    type,
    messageId: newMessageId(),
    correlationId: Uint8Array.from(request.messageId),
    body,
  }) as LfcpMessage<T>;
}

/**
 * The §62 code for a message decoding failure: MESSAGE_TOO_LARGE and
 * PROTOCOL_UNSUPPORTED as such; an invalid Principal Descriptor in HELLO
 * is AUTH_FAILED (§7, P3); everything else is MALFORMED_MESSAGE.
 */
export function messageErrorWireCode(error: unknown, messageType?: bigint): WireErrorName {
  if (error instanceof LfcpError) {
    if (error.code === "MESSAGE_TOO_LARGE" || error.code === "PROTOCOL_UNSUPPORTED")
      return error.code;
    if (
      messageType === MESSAGE_TYPE.HELLO &&
      (error.code === "INVALID_PRINCIPAL_DESCRIPTOR" || error.code === "PRINCIPAL_ID_MISMATCH")
    )
      return "AUTH_FAILED";
  }
  return "MALFORMED_MESSAGE";
}

/** One received WebSocket message (§31). */
export type Frame =
  | { readonly kind: "binary"; readonly data: Uint8Array }
  | { readonly kind: "text"; readonly data: string };

export type FrameResult =
  | { readonly kind: "message"; readonly message: AnyMessage }
  | {
      readonly kind: "error";
      readonly wireCode: WireErrorName;
      readonly errorCode: bigint;
      /** True when the receiver must close the connection after sending ERROR (§31, G-MSG7). */
      readonly closesConnection: boolean;
      readonly reason: string;
    };

/**
 * The receive side of §31 for one WebSocket message, without I/O: a text
 * frame is MALFORMED_MESSAGE and closes the connection (G-MSG7); a binary
 * frame is decoded with decodeMessage. Whether to answer with NACK (a
 * correlated request) or ERROR is the session's decision (LFCP-027).
 */
export function decodeFrame(frame: Frame, options: DecodeOptions = {}): FrameResult {
  const fail = (wireCode: WireErrorName, reason: string, closesConnection: boolean) =>
    Object.freeze({
      kind: "error" as const,
      wireCode,
      errorCode: ERROR_CODE[wireCode],
      closesConnection,
      reason,
    });
  if (frame.kind === "text")
    return fail(
      "MALFORMED_MESSAGE",
      "LFCP messages are binary; a text frame is invalid (§31)",
      true,
    );
  try {
    return Object.freeze({ kind: "message", message: decodeMessage(frame.data, options) });
  } catch (e) {
    if (!(e instanceof LfcpError)) throw e;
    const descriptor =
      e.code === "INVALID_PRINCIPAL_DESCRIPTOR" || e.code === "PRINCIPAL_ID_MISMATCH";
    return fail(
      messageErrorWireCode(e, descriptor ? peekType(frame.data) : undefined),
      e.message,
      false,
    );
  }
}

/** The message type of undecodable bytes, if field 0 can be read at all (for the HELLO mapping). */
function peekType(bytes: Uint8Array): bigint | undefined {
  try {
    const v = decodeDeterministic(bytes);
    if (!isCborMap(v)) return undefined;
    const t = v.entries.find(([k]) => k === 0)?.[1];
    return typeof t === "number" || typeof t === "bigint" ? BigInt(t) : undefined;
  } catch {
    return undefined;
  }
}
