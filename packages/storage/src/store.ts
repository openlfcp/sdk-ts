import type {
  ActorSequence,
  ControlRecordId,
  DataEpoch,
  DataUnitId,
  Hash32,
  PrincipalId,
  ResourceId,
} from "@openlfcp/core";
import type { SecretRef } from "./secrets.js";
import type { ActorSequenceReservation } from "./sequence.js";
import type { SnapshotSequenceReservation } from "./snapshot-sequence.js";

/**
 * Local LFCP persistence (LFCP-034): the interfaces a client's durable
 * state goes through. Adapters implement them: InMemoryLfcpStorage for
 * tests, a Node adapter (LFCP-035), Obsidian later (LFCP-059). Nothing here
 * depends on a filesystem, Electron or Obsidian.
 *
 * Rules every adapter keeps:
 *
 * - EXACT BYTES ARE AUTHORITATIVE. Signed objects (Control Records, Data
 *   Units, Key Packages, Snapshots) are stored as their exact received or
 *   created bytes, under the ID that hashes them. Every other field of a
 *   row is a secondary index for lookups; nothing is ever re-encoded from
 *   it. Bytes are copied in and out: no caller buffer aliases a stored one.
 * - IMMUTABLE OBJECTS. A stored object's bytes never change; writing the
 *   same ID again with other bytes fails the batch.
 * - ATOMIC BATCHES. Everything that must persist together goes into one
 *   commit(), which applies every write or none, and checks its
 *   preconditions (the expected Control Head) first.
 * - SEQUENCE SAFETY. Actor and Snapshot sequences come only from their
 *   reservation contracts (durable before they resolve). A reserved
 *   sequence that a crash leaves unused is abandoned, never reissued, so
 *   reserving and then committing the sealed object plus its outbound entry
 *   in one batch is safe: no nonce can be used twice.
 * - SECRETS ARE ELSEWHERE. Rows hold SecretRefs only; values live in a
 *   SecretStore (secrets.ts).
 */

/** A Control Record: exact COSE bytes plus its chain position (§13). */
export interface ControlRecordRow {
  readonly recordId: ControlRecordId;
  readonly resourceId: ResourceId;
  readonly controlSeq: bigint;
  readonly prevControlId: ControlRecordId | null;
  readonly bytes: Uint8Array;
}

/** The Resource's current validated Control Head. */
export interface ControlHeadRow {
  readonly head: ControlRecordId;
  readonly controlSeq: bigint;
}

/** A detected Control Chain fork (CONTROL_CONFLICT, §13.2): the competing heads. */
export interface ControlConflictRow {
  readonly heads: readonly ControlRecordId[];
}

/** A Data Epoch as the chain defines it, plus where its DEK is kept. */
export interface EpochRow {
  readonly epoch: DataEpoch;
  readonly dekCommitment: Hash32;
  readonly openedBy: ControlRecordId;
  readonly closedBy: ControlRecordId | null;
  /** The SecretStore entry of this epoch's DEK, once this client holds it. */
  readonly dekRef: SecretRef | null;
}

/** A Data Unit: exact COSE bytes plus its header fields as indexes (§26). */
export interface DataUnitRow {
  readonly unitId: DataUnitId;
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly actor: PrincipalId;
  readonly actorSeq: ActorSequence;
  readonly prevDataUnitId: DataUnitId | null;
  readonly controlHead: ControlRecordId;
  readonly bytes: Uint8Array;
}

/**
 * Where a Data Unit stands for this client. Units are stored only once
 * their signature verified (or this client created them).
 */
export type DataUnitStatus =
  /** Signature-valid, still being processed. */
  | "seen"
  /** Merged into the Data Profile state (including this client's own units). */
  | "merged"
  /** LFCP-accepted; the profile waits for content it builds on. */
  | "profile-pending"
  /** The actor chain does not link yet (§26.2, G-DP1). */
  | "held"
  /** Beyond an epoch cutoff (STALE_DATA_EPOCH). */
  | "quarantined"
  /** Part of an equivocating pair, kept as evidence (§26.2). */
  | "equivocation"
  /** No DEK, DEK mismatch, AEAD failure or profile decode failure. */
  | "local-failure"
  /** LFCP-accepted, refused when merging. */
  | "profile-rejected"
  /** The Resource's profile is not implemented here. */
  | "profile-unsupported";

export interface StoredDataUnit extends DataUnitRow {
  readonly status: DataUnitStatus;
  readonly detail: string | null;
  /**
   * Accepted by LFCP (the wire SeenUnits "accepted" mark): replays are
   * duplicates and the actor chain links to it. Cleared by un-accept when
   * a merged unit is taken out again (G-EP7, G-DP5).
   */
  readonly accepted: boolean;
}

/** The signature-valid units recorded for one (resource, actor, seq). */
export interface SeenRecord {
  /** Sorted by bytes; more than one means equivocation. */
  readonly unitIds: readonly DataUnitId[];
  readonly firstSeen: boolean;
}

/** A Key Package (§25). Several may exist for one (resource, epoch, recipient). */
export interface KeyPackageRow {
  /** SHA-256 of the exact bytes. */
  readonly packageId: Hash32;
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly recipient: PrincipalId;
  readonly sender: PrincipalId;
  readonly bytes: Uint8Array;
}

/** A Snapshot (§29) and the metadata needed to pick one for catch-up. */
export interface SnapshotRow {
  /** SHA-256 of the exact bytes. */
  readonly snapshotId: Hash32;
  readonly resourceId: ResourceId;
  readonly dataEpoch: DataEpoch;
  readonly publisher: PrincipalId;
  readonly snapshotSeq: bigint;
  /** The canonical frontier the Snapshot covers, as its exact CBOR (§28.2). */
  readonly frontier: Uint8Array;
  readonly bytes: Uint8Array;
}

/** The Resource's route as the chain defines it (§16, §20). */
export interface RouteRow {
  readonly routeVersion: bigint;
  readonly endpoints: readonly {
    readonly url: string;
    readonly priority: bigint;
    /** §16 flag bits, when the record carries them. */
    readonly flags?: bigint;
  }[];
  readonly coordinatorUrl: string;
  /** The Control Record that set it. */
  readonly source: ControlRecordId;
}

/** Local metadata of a Resource this client follows. */
export interface ResourceRow {
  readonly resourceId: ResourceId;
  /** The Genesis data_profile (§15). */
  readonly dataProfile: string;
  /** The Principal this client writes as, and where its private keys are. */
  readonly localPrincipal: {
    readonly principalId: PrincipalId;
    readonly signingKeyRef: SecretRef;
    readonly agreementKeyRef: SecretRef;
  } | null;
  /** Application labels (display name, …): public, never secrets. */
  readonly labels: Readonly<Record<string, string>>;
}

export type OutboundKind = "control-record" | "data-unit" | "key-package" | "snapshot";

/**
 * Why an outbound item is no longer sent (LFCP-036). It stays queued and
 * visible until the application discards it.
 *
 * - stale-epoch: beyond a closed epoch's cutoff (§88 step 7, G-EP5); the
 *   intent must be applied again as a new unit;
 * - equivocation: the server holds another unit for its (actor, seq): a
 *   local-safety alarm;
 * - rejected: refused for good (e.g. AUTHORIZATION_FAILED at its head);
 * - repropose: a Control Record whose expected head moved
 *   (CONTROL_HEAD_MISMATCH); the caller builds a new record;
 * - too-large: larger than the server accepts in one message.
 */
export type OutboundBlock = "stale-epoch" | "equivocation" | "rejected" | "repropose" | "too-large";

/** An immutable object waiting to be sent (LFCP-036). Removed only when ACKed (or discarded). */
export interface OutboundItem {
  /** The object's ID (record, unit, package or snapshot ID). */
  readonly itemId: Hash32;
  readonly resourceId: ResourceId;
  readonly kind: OutboundKind;
  /** The exact bytes to send; a retry sends these again, never a re-created object. */
  readonly bytes: Uint8Array;
  readonly attempts: number;
  /** Set by the sender (caller's clock, RFC 3339); null until the first attempt. */
  readonly lastAttempt: string | null;
  /** Not to be sent before this time (caller's clock, RFC 3339); null: now. */
  readonly nextAttempt: string | null;
  /** Set once the item must not be sent again. */
  readonly blocked: { readonly reason: OutboundBlock; readonly detail: string | null } | null;
}

/** Per-Resource sync state that is not derivable from stored objects (LFCP-036). */
export interface SyncStateRow {
  readonly resourceId: ResourceId;
  /** The most recently ACKed object IDs, newest last (bounded by the writer). */
  readonly recentlyAcked: readonly Hash32[];
  /** The durability the last ACK established (§37 level), or null before any ACK. */
  readonly ackedDurability: bigint | null;
}

/**
 * A Data Profile's local state: enough to resume without replaying every
 * unit (e.g. an Automerge full save) and to continue as the same actor
 * (§9: actorSeq becomes the replica's minSeq). `units` maps merged units to
 * the profile's own change references, for a G-EP7 rebuild. The accepted
 * set itself is always reconstructable from the stored units with
 * accepted = true and their epochs' DEKs.
 */
export interface ProfileCheckpoint {
  readonly resourceId: ResourceId;
  readonly dataProfile: string;
  readonly state: Uint8Array;
  readonly actorSeq: number;
  readonly units: readonly { readonly unitId: DataUnitId; readonly ref: string }[];
}

/** One write of an atomic batch. */
export type StorageWrite =
  | { readonly op: "put-control-records"; readonly records: readonly ControlRecordRow[] }
  | {
      /** Compare-and-set: fails the batch unless the current head is `expected` (null: none yet). */
      readonly op: "set-control-head";
      readonly resourceId: ResourceId;
      readonly expected: ControlRecordId | null;
      readonly head: ControlHeadRow;
    }
  | {
      readonly op: "set-control-conflict";
      readonly resourceId: ResourceId;
      readonly conflict: ControlConflictRow | null;
    }
  | { readonly op: "put-epoch"; readonly resourceId: ResourceId; readonly epoch: EpochRow }
  | {
      /** Stores the unit if new (exact bytes) and sets its status. */
      readonly op: "put-data-unit";
      readonly unit: DataUnitRow;
      readonly status: DataUnitStatus;
      readonly detail?: string;
      readonly accepted?: boolean;
    }
  | {
      readonly op: "set-data-unit-status";
      readonly unitId: DataUnitId;
      readonly status: DataUnitStatus;
      readonly detail?: string;
    }
  /** Marks a unit accepted, or un-accepts it. */
  | { readonly op: "set-accepted"; readonly unitId: DataUnitId; readonly accepted: boolean }
  | { readonly op: "put-key-package"; readonly row: KeyPackageRow }
  | { readonly op: "put-snapshot"; readonly row: SnapshotRow }
  /** Forgets a stored Snapshot (e.g. Snapshot-derived state dropped, SNAP-EP). */
  | { readonly op: "delete-snapshot"; readonly snapshotId: Hash32 }
  | { readonly op: "put-resource"; readonly row: ResourceRow }
  | { readonly op: "put-route"; readonly resourceId: ResourceId; readonly route: RouteRow }
  | { readonly op: "enqueue"; readonly item: OutboundItem }
  | {
      /** Changes the given retry fields of a queued item (its bytes never change). */
      readonly op: "update-outbound";
      readonly itemId: Hash32;
      readonly attempts?: number;
      readonly lastAttempt?: string | null;
      readonly nextAttempt?: string | null;
      readonly blocked?: OutboundItem["blocked"];
    }
  | { readonly op: "dequeue"; readonly itemId: Hash32 }
  | { readonly op: "put-profile-checkpoint"; readonly checkpoint: ProfileCheckpoint }
  | { readonly op: "put-sync-state"; readonly row: SyncStateRow };

export type CommitResult =
  | { readonly ok: true }
  /** Nothing was written: a precondition failed. */
  | {
      readonly ok: false;
      readonly reason: "CONTROL_HEAD_MISMATCH";
      readonly resourceId: ResourceId;
      readonly current: ControlRecordId | null;
    };

export interface ControlReader {
  record(recordId: ControlRecordId): Promise<ControlRecordRow | undefined>;
  /** Every stored record of the Resource, by (controlSeq, recordId bytes). */
  records(resource: ResourceId): Promise<ControlRecordRow[]>;
  head(resource: ResourceId): Promise<ControlHeadRow | undefined>;
  conflict(resource: ResourceId): Promise<ControlConflictRow | undefined>;
  /** Epoch history, ascending. */
  epochs(resource: ResourceId): Promise<EpochRow[]>;
}

export interface DataUnitReader {
  get(unitId: DataUnitId): Promise<StoredDataUnit | undefined>;
  /** Every unit stored for one (resource, actor, seq): more than one is equivocation. */
  at(resource: ResourceId, actor: PrincipalId, seq: ActorSequence): Promise<StoredDataUnit[]>;
  /** Units of one actor with from <= seq <= to, ascending (anti-entropy). */
  range(
    resource: ResourceId,
    actor: PrincipalId,
    from: ActorSequence,
    to: ActorSequence,
  ): Promise<StoredDataUnit[]>;
  /** Units of the Resource with this status, by (actor, seq, unitId). */
  withStatus(resource: ResourceId, status: DataUnitStatus): Promise<StoredDataUnit[]>;
  /** The accepted unit at (resource, actor, seq), if any. */
  acceptedAt(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
  ): Promise<DataUnitId | undefined>;
  /**
   * Atomically stores a signature-valid unit (exact bytes, status "seen")
   * unless it is stored already, and returns every unit ID recorded for
   * its (resource, actor, seq). The durable form of the wire SeenUnits
   * recordSignatureValid.
   */
  recordSeen(unit: DataUnitRow): Promise<SeenRecord>;
}

export interface KeyPackageReader {
  get(packageId: Hash32): Promise<KeyPackageRow | undefined>;
  /** Packages of the Resource, optionally of one epoch and/or recipient, by (epoch, packageId). */
  list(
    resource: ResourceId,
    filter?: { readonly epoch?: DataEpoch; readonly recipient?: PrincipalId },
  ): Promise<KeyPackageRow[]>;
}

export interface SnapshotReader {
  get(snapshotId: Hash32): Promise<SnapshotRow | undefined>;
  /** Snapshots of the Resource, optionally of one epoch, by (epoch, publisher, snapshotSeq). */
  list(resource: ResourceId, filter?: { readonly epoch?: DataEpoch }): Promise<SnapshotRow[]>;
}

export interface ResourceReader {
  get(resource: ResourceId): Promise<ResourceRow | undefined>;
  list(): Promise<ResourceRow[]>;
  route(resource: ResourceId): Promise<RouteRow | undefined>;
}

export interface OutboundReader {
  /** Items in enqueue order, optionally of one Resource. */
  list(resource?: ResourceId): Promise<OutboundItem[]>;
  get(itemId: Hash32): Promise<OutboundItem | undefined>;
}

export interface ProfileStateReader {
  checkpoint(resource: ResourceId): Promise<ProfileCheckpoint | undefined>;
}

export interface SyncStateReader {
  get(resource: ResourceId): Promise<SyncStateRow | undefined>;
}

/** Everything a client persists, except secrets (SecretStore). */
export interface LfcpStorage {
  readonly control: ControlReader;
  readonly dataUnits: DataUnitReader;
  readonly keyPackages: KeyPackageReader;
  readonly snapshots: SnapshotReader;
  readonly resources: ResourceReader;
  readonly outbound: OutboundReader;
  readonly profileState: ProfileStateReader;
  readonly syncState: SyncStateReader;
  readonly actorSequences: ActorSequenceReservation;
  readonly snapshotSequences: SnapshotSequenceReservation;
  /** Applies every write or none; durable before it resolves. */
  commit(writes: readonly StorageWrite[]): Promise<CommitResult>;
}
