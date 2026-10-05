import {
  type ActorSequence,
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  type Hash32,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { type ActorSequenceReservation, InMemoryActorSequenceReservation } from "./sequence.js";
import {
  InMemorySnapshotSequenceReservation,
  type SnapshotSequenceReservation,
} from "./snapshot-sequence.js";
import type {
  CommitResult,
  ControlConflictRow,
  ControlHeadRow,
  ControlRecordRow,
  DataUnitRow,
  DataUnitStatus,
  EpochRow,
  KeyPackageRow,
  LfcpStorage,
  OutboundItem,
  ProfileCheckpoint,
  ResourceRow,
  RouteRow,
  SeenRecord,
  SnapshotRow,
  StorageWrite,
  StoredDataUnit,
  SyncStateRow,
} from "./store.js";

/** A deep copy: every Uint8Array copied, everything frozen. Nothing stored aliases a caller's buffer. */
function own<T>(value: T): T {
  if (value instanceof Uint8Array) return Uint8Array.from(value) as T;
  if (Array.isArray(value)) return Object.freeze(value.map(own)) as T;
  if (value !== null && typeof value === "object")
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([k, v]) => [k, own(v)])),
    ) as T;
  return value;
}

const hex = toHex;
const byBytes = (a: Uint8Array, b: Uint8Array): number => {
  const [x, y] = [hex(a), hex(b)];
  return x < y ? -1 : x > y ? 1 : 0;
};
const tuple = (resource: Uint8Array, actor: Uint8Array, seq: bigint): string =>
  `${hex(resource)}:${hex(actor)}:${seq}`;

interface State {
  readonly records: Map<string, ControlRecordRow>;
  readonly heads: Map<string, ControlHeadRow>;
  readonly conflicts: Map<string, ControlConflictRow>;
  /** resource hex -> epoch -> row */
  readonly epochs: Map<string, Map<bigint, EpochRow>>;
  readonly units: Map<string, StoredDataUnit>;
  readonly keyPackages: Map<string, KeyPackageRow>;
  readonly snapshots: Map<string, SnapshotRow>;
  readonly resources: Map<string, ResourceRow>;
  readonly routes: Map<string, RouteRow>;
  /** insertion order is enqueue order */
  readonly outbound: Map<string, OutboundItem>;
  readonly checkpoints: Map<string, ProfileCheckpoint>;
  readonly syncStates: Map<string, SyncStateRow>;
}

const emptyState = (): State => ({
  records: new Map(),
  heads: new Map(),
  conflicts: new Map(),
  epochs: new Map(),
  units: new Map(),
  keyPackages: new Map(),
  snapshots: new Map(),
  resources: new Map(),
  routes: new Map(),
  outbound: new Map(),
  checkpoints: new Map(),
  syncStates: new Map(),
});

/** Rows are immutable, so a staged copy of the maps is enough for all-or-nothing batches. */
const stage = (s: State): State => ({
  records: new Map(s.records),
  heads: new Map(s.heads),
  conflicts: new Map(s.conflicts),
  epochs: new Map([...s.epochs].map(([k, v]) => [k, new Map(v)])),
  units: new Map(s.units),
  keyPackages: new Map(s.keyPackages),
  snapshots: new Map(s.snapshots),
  resources: new Map(s.resources),
  routes: new Map(s.routes),
  outbound: new Map(s.outbound),
  checkpoints: new Map(s.checkpoints),
  syncStates: new Map(s.syncStates),
});

/** Stores an immutable object under its ID; the same ID with other bytes is refused. */
function putImmutable<T extends { readonly bytes: Uint8Array }>(
  map: Map<string, T>,
  id: Uint8Array,
  row: T,
  what: string,
): void {
  const old = map.get(hex(id));
  if (old !== undefined) {
    if (!bytesEqual(old.bytes, row.bytes))
      throw new LfcpError("INVALID_STRUCTURE", `${what} ${hex(id)} is stored with other bytes`);
    return;
  }
  map.set(hex(id), own(row));
}

function apply(s: State, w: StorageWrite): void {
  switch (w.op) {
    case "put-control-records":
      for (const r of w.records) putImmutable(s.records, r.recordId, r, "Control Record");
      return;
    case "set-control-head":
      s.heads.set(hex(w.resourceId), own(w.head));
      return;
    case "set-control-conflict":
      if (w.conflict === null) s.conflicts.delete(hex(w.resourceId));
      else s.conflicts.set(hex(w.resourceId), own(w.conflict));
      return;
    case "put-epoch": {
      const key = hex(w.resourceId);
      const epochs = s.epochs.get(key) ?? new Map<bigint, EpochRow>();
      const stored = epochs.get(BigInt(w.epoch.epoch));
      epochs.set(
        BigInt(w.epoch.epoch),
        own({
          ...w.epoch,
          closedBy: w.epoch.closedBy ?? stored?.closedBy ?? null,
          dekRef: w.epoch.dekRef ?? stored?.dekRef ?? null,
        }),
      );
      s.epochs.set(key, epochs);
      return;
    }
    case "expect-previous-unit":
      return; // a precondition, checked by commit()
    case "put-data-unit": {
      const old = s.units.get(hex(w.unit.unitId));
      if (old !== undefined && !bytesEqual(old.bytes, w.unit.bytes))
        throw new LfcpError(
          "INVALID_STRUCTURE",
          `Data Unit ${hex(w.unit.unitId)} is stored with other bytes`,
        );
      const base: DataUnitRow = old ?? w.unit;
      s.units.set(
        hex(w.unit.unitId),
        own({
          ...pickUnit(base),
          status: w.status,
          detail: w.detail ?? null,
          accepted: w.accepted ?? old?.accepted ?? false,
        }),
      );
      return;
    }
    case "set-data-unit-status": {
      const old = known(s, w.unitId);
      s.units.set(hex(w.unitId), own({ ...old, status: w.status, detail: w.detail ?? null }));
      return;
    }
    case "set-accepted": {
      const old = known(s, w.unitId);
      s.units.set(hex(w.unitId), own({ ...old, accepted: w.accepted }));
      return;
    }
    case "put-key-package":
      putImmutable(s.keyPackages, w.row.packageId, w.row, "Key Package");
      return;
    case "delete-snapshot":
      s.snapshots.delete(hex(w.snapshotId));
      return;
    case "put-snapshot":
      putImmutable(s.snapshots, w.row.snapshotId, w.row, "Snapshot");
      return;
    case "put-resource":
      s.resources.set(hex(w.row.resourceId), own(w.row));
      return;
    case "put-route":
      s.routes.set(hex(w.resourceId), own(w.route));
      return;
    case "enqueue":
      putImmutable(s.outbound, w.item.itemId, w.item, "outbound item");
      return;
    case "update-outbound": {
      const old = s.outbound.get(hex(w.itemId));
      if (old === undefined)
        throw new LfcpError("INVALID_STRUCTURE", `no outbound item ${hex(w.itemId)}`);
      s.outbound.set(
        hex(w.itemId),
        own({
          ...old,
          ...(w.attempts === undefined ? {} : { attempts: w.attempts }),
          ...(w.lastAttempt === undefined ? {} : { lastAttempt: w.lastAttempt }),
          ...(w.nextAttempt === undefined ? {} : { nextAttempt: w.nextAttempt }),
          ...(w.blocked === undefined ? {} : { blocked: w.blocked }),
        }),
      );
      return;
    }
    case "dequeue":
      s.outbound.delete(hex(w.itemId));
      return;
    case "put-profile-checkpoint":
      s.checkpoints.set(hex(w.checkpoint.resourceId), own(w.checkpoint));
      return;
    case "put-sync-state":
      s.syncStates.set(hex(w.row.resourceId), own(w.row));
      return;
  }
}

const pickUnit = (u: DataUnitRow): DataUnitRow => ({
  unitId: u.unitId,
  resourceId: u.resourceId,
  dataEpoch: u.dataEpoch,
  actor: u.actor,
  actorSeq: u.actorSeq,
  prevDataUnitId: u.prevDataUnitId,
  controlHead: u.controlHead,
  bytes: u.bytes,
});

function known(s: State, unitId: DataUnitId): StoredDataUnit {
  const u = s.units.get(hex(unitId));
  if (u === undefined) throw new LfcpError("INVALID_STRUCTURE", `no Data Unit ${hex(unitId)}`);
  return u;
}

const ACCEPTED_ORDER = (a: StoredDataUnit, b: StoredDataUnit): number =>
  byBytes(a.actor, b.actor) ||
  (a.actorSeq < b.actorSeq ? -1 : a.actorSeq > b.actorSeq ? 1 : 0) ||
  byBytes(a.unitId, b.unitId);

/**
 * FOR TESTS AND DEVELOPMENT ONLY: an LfcpStorage in process memory, lost on
 * restart, with the same semantic contracts as a durable adapter (exact
 * bytes copied in and out, immutable objects, all-or-nothing batches with
 * their preconditions). Deterministic: no clock, no randomness, ordered
 * results.
 */
export class InMemoryLfcpStorage implements LfcpStorage {
  #state: State = emptyState();
  readonly #actorCounter = new InMemoryActorSequenceReservation();
  readonly #snapshotCounter = new InMemorySnapshotSequenceReservation();

  /** Reservations fail closed when the counter is behind this Principal's own stored objects (§9, §29). */
  readonly actorSequences: ActorSequenceReservation = {
    reserveNext: async (resource, principal) => {
      const next = await this.#actorCounter.reserveNext(resource, principal);
      const max = [...this.#state.units.values()]
        .filter((u) => bytesEqual(u.resourceId, resource) && bytesEqual(u.actor, principal))
        .reduce((m, u) => (u.actorSeq > m ? BigInt(u.actorSeq) : m), 0n);
      if (next <= max)
        throw new LfcpError(
          "SEQUENCE_REUSE",
          `the actor sequence state is behind the stored units of this Principal (${max}); refusing to reserve (§9)`,
        );
      return next;
    },
  };

  readonly snapshotSequences: SnapshotSequenceReservation = {
    reserveNext: async (resource, epoch, publisher) => {
      const next = await this.#snapshotCounter.reserveNext(resource, epoch, publisher);
      const max = [...this.#state.snapshots.values()]
        .filter(
          (x) =>
            bytesEqual(x.resourceId, resource) &&
            x.dataEpoch === epoch &&
            bytesEqual(x.publisher, publisher),
        )
        .reduce((m, x) => (x.snapshotSeq > m ? x.snapshotSeq : m), 0n);
      if (next <= max)
        throw new LfcpError(
          "SEQUENCE_REUSE",
          `the Snapshot Sequence state is behind the stored Snapshots of this publisher (${max}); refusing to reserve (§29)`,
        );
      return next;
    },
  };

  commit(writes: readonly StorageWrite[]): Promise<CommitResult> {
    const next = stage(this.#state);
    for (const w of writes) {
      if (w.op !== "set-control-head") continue;
      const current = next.heads.get(hex(w.resourceId))?.head ?? null;
      const matches =
        current === null
          ? w.expected === null
          : w.expected !== null && bytesEqual(current, w.expected);
      if (!matches)
        return Promise.resolve(
          Object.freeze({
            ok: false,
            reason: "CONTROL_HEAD_MISMATCH",
            resourceId: own(w.resourceId),
            current: current === null ? null : own(current),
          }),
        );
    }
    for (const w of writes) {
      if (w.op !== "expect-previous-unit") continue;
      let latest: StoredDataUnit | undefined;
      for (const u of next.units.values())
        if (
          u.accepted &&
          bytesEqual(u.resourceId, w.resourceId) &&
          bytesEqual(u.actor, w.actor) &&
          (latest === undefined || u.actorSeq > latest.actorSeq)
        )
          latest = u;
      const current = latest?.unitId ?? null;
      const matches =
        current === null
          ? w.previous === null
          : w.previous !== null && bytesEqual(current, w.previous);
      if (!matches)
        return Promise.resolve(
          Object.freeze({
            ok: false,
            reason: "PREVIOUS_UNIT_MISMATCH",
            resourceId: own(w.resourceId),
            actor: own(w.actor),
            current: current === null ? null : own(current),
          }),
        );
    }
    try {
      for (const w of writes) apply(next, w);
    } catch (e) {
      return Promise.reject(e);
    }
    this.#state = next;
    return Promise.resolve(Object.freeze({ ok: true }));
  }

  readonly control = {
    record: (id: ControlRecordId) => Promise.resolve(copyOf(this.#state.records.get(hex(id)))),
    records: (resource: ResourceId) =>
      Promise.resolve(
        [...this.#state.records.values()]
          .filter((r) => bytesEqual(r.resourceId, resource))
          .sort((a, b) =>
            a.controlSeq < b.controlSeq
              ? -1
              : a.controlSeq > b.controlSeq
                ? 1
                : byBytes(a.recordId, b.recordId),
          )
          .map(own),
      ),
    head: (resource: ResourceId) => Promise.resolve(copyOf(this.#state.heads.get(hex(resource)))),
    conflict: (resource: ResourceId) =>
      Promise.resolve(copyOf(this.#state.conflicts.get(hex(resource)))),
    epochs: (resource: ResourceId) =>
      Promise.resolve(
        [...(this.#state.epochs.get(hex(resource))?.values() ?? [])]
          .sort((a, b) => (a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0))
          .map(own),
      ),
  };

  readonly dataUnits = {
    get: (id: DataUnitId) => Promise.resolve(copyOf(this.#state.units.get(hex(id)))),
    at: (resource: ResourceId, actor: PrincipalId, seq: ActorSequence) =>
      Promise.resolve(this.#at(resource, actor, seq).map(own)),
    range: (resource: ResourceId, actor: PrincipalId, from: ActorSequence, to: ActorSequence) =>
      Promise.resolve(
        this.#units(
          (u) =>
            bytesEqual(u.resourceId, resource) &&
            bytesEqual(u.actor, actor) &&
            u.actorSeq >= from &&
            u.actorSeq <= to,
        ),
      ),
    withStatus: (resource: ResourceId, status: DataUnitStatus) =>
      Promise.resolve(
        this.#units((u) => bytesEqual(u.resourceId, resource) && u.status === status),
      ),
    acceptedAt: (resource: ResourceId, actor: PrincipalId, seq: ActorSequence) =>
      Promise.resolve(copyOf(this.#at(resource, actor, seq).find((u) => u.accepted)?.unitId)),
    recordSeen: (unit: DataUnitRow): Promise<SeenRecord> => {
      const firstSeen = !this.#state.units.has(hex(unit.unitId));
      if (firstSeen) {
        const next = stage(this.#state);
        apply(next, { op: "put-data-unit", unit, status: "seen" });
        this.#state = next;
      } else if (
        !bytesEqual((this.#state.units.get(hex(unit.unitId)) as StoredDataUnit).bytes, unit.bytes)
      ) {
        return Promise.reject(
          new LfcpError(
            "INVALID_STRUCTURE",
            `Data Unit ${hex(unit.unitId)} is stored with other bytes`,
          ),
        );
      }
      const unitIds = this.#at(unit.resourceId, unit.actor, unit.actorSeq)
        .map((u) => own(u.unitId))
        .sort(byBytes);
      return Promise.resolve(Object.freeze({ unitIds: Object.freeze(unitIds), firstSeen }));
    },
  };

  #at(resource: ResourceId, actor: PrincipalId, seq: ActorSequence): StoredDataUnit[] {
    const key = tuple(resource, actor, seq);
    return [...this.#state.units.values()]
      .filter((u) => tuple(u.resourceId, u.actor, u.actorSeq) === key)
      .sort((a, b) => byBytes(a.unitId, b.unitId));
  }

  #units(keep: (u: StoredDataUnit) => boolean): StoredDataUnit[] {
    return [...this.#state.units.values()].filter(keep).sort(ACCEPTED_ORDER).map(own);
  }

  readonly keyPackages = {
    get: (id: Hash32) => Promise.resolve(copyOf(this.#state.keyPackages.get(hex(id)))),
    list: (
      resource: ResourceId,
      filter: { readonly epoch?: DataEpoch; readonly recipient?: PrincipalId } = {},
    ) =>
      Promise.resolve(
        [...this.#state.keyPackages.values()]
          .filter(
            (k) =>
              bytesEqual(k.resourceId, resource) &&
              (filter.epoch === undefined || k.dataEpoch === filter.epoch) &&
              (filter.recipient === undefined || bytesEqual(k.recipient, filter.recipient)),
          )
          .sort((a, b) =>
            a.dataEpoch < b.dataEpoch
              ? -1
              : a.dataEpoch > b.dataEpoch
                ? 1
                : byBytes(a.packageId, b.packageId),
          )
          .map(own),
      ),
  };

  readonly snapshots = {
    get: (id: Hash32) => Promise.resolve(copyOf(this.#state.snapshots.get(hex(id)))),
    list: (resource: ResourceId, filter: { readonly epoch?: DataEpoch } = {}) =>
      Promise.resolve(
        [...this.#state.snapshots.values()]
          .filter(
            (s) =>
              bytesEqual(s.resourceId, resource) &&
              (filter.epoch === undefined || s.dataEpoch === filter.epoch),
          )
          .sort(
            (a, b) =>
              (a.dataEpoch < b.dataEpoch ? -1 : a.dataEpoch > b.dataEpoch ? 1 : 0) ||
              byBytes(a.publisher, b.publisher) ||
              (a.snapshotSeq < b.snapshotSeq ? -1 : a.snapshotSeq > b.snapshotSeq ? 1 : 0),
          )
          .map(own),
      ),
  };

  readonly resources = {
    get: (resource: ResourceId) =>
      Promise.resolve(copyOf(this.#state.resources.get(hex(resource)))),
    list: () =>
      Promise.resolve(
        [...this.#state.resources.values()]
          .sort((a, b) => byBytes(a.resourceId, b.resourceId))
          .map(own),
      ),
    route: (resource: ResourceId) => Promise.resolve(copyOf(this.#state.routes.get(hex(resource)))),
  };

  readonly outbound = {
    list: (resource?: ResourceId) =>
      Promise.resolve(
        [...this.#state.outbound.values()]
          .filter((o) => resource === undefined || bytesEqual(o.resourceId, resource))
          .map(own),
      ),
    get: (id: Hash32) => Promise.resolve(copyOf(this.#state.outbound.get(hex(id)))),
  };

  readonly profileState = {
    checkpoint: (resource: ResourceId) =>
      Promise.resolve(copyOf(this.#state.checkpoints.get(hex(resource)))),
  };

  readonly syncState = {
    get: (resource: ResourceId) =>
      Promise.resolve(copyOf(this.#state.syncStates.get(hex(resource)))),
  };
}

const copyOf = <T>(value: T | undefined): T | undefined =>
  value === undefined ? undefined : own(value);
