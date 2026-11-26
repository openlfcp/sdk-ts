import {
  type ActorSequence,
  bytesEqual,
  type DataUnitId,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import type {
  CommitResult,
  DataUnitRow,
  DataUnitStatus,
  LfcpStorage,
  SeenRecord,
  StorageWrite,
  StoredDataUnit,
} from "@openlfcp/storage";

type Inner = Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit" | "localMarks">;

const byBytes = (a: Uint8Array, b: Uint8Array): number => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  return a.length - b.length;
};

/** The order of DataUnitReader.range and withStatus: (actor, seq, unitId). */
const unitOrder = (a: StoredDataUnit, b: StoredDataUnit): number =>
  byBytes(a.actor, b.actor) ||
  (a.actorSeq < b.actorSeq ? -1 : a.actorSeq > b.actorSeq ? 1 : 0) ||
  byBytes(a.unitId, b.unitId);

const rowOf = (u: DataUnitRow): DataUnitRow => ({
  unitId: u.unitId,
  resourceId: u.resourceId,
  dataEpoch: u.dataEpoch,
  actor: u.actor,
  actorSeq: u.actorSeq,
  prevDataUnitId: u.prevDataUnitId,
  controlHead: u.controlHead,
  bytes: u.bytes,
});

const tuple = (resource: Uint8Array, actor: Uint8Array, seq: bigint): string =>
  `${toHex(resource)}:${toHex(actor)}:${seq}`;

/** The Data Unit writes a receive batch defers: the rest go to storage as they come. */
const DEFERRED = new Set<StorageWrite["op"]>([
  "put-data-unit",
  "set-data-unit-status",
  "set-accepted",
]);

/**
 * The receive path's storage, with the Data Unit writes of one DATA_BATCH
 * held in memory and committed in one transaction (E-030l): the "seen"
 * record of each signature-valid unit, its accepted mark and its status
 * after the profile. Without it a unit costs three synced transactions.
 *
 * Inside a batch (begin() to end()), reads see the held writes, so each
 * unit's checks (equivocation, the actor chain of §26.2, duplicates) see
 * the units before it exactly as if they had been stored. end() commits
 * them, one write per unit with its final state; nothing of the batch is
 * stored before, so nothing built on storage (the Have Vector of DATA_HAVE,
 * relays of §68.1) can advertise a unit before it is durable (W §68 step
 * 10). A crash before end() loses the whole batch, which is then fetched
 * and received again (W §70: delivery is at-least-once).
 *
 * Any other write flushes the held ones first, then goes to storage as
 * given, so storage never sees writes out of order. Outside a batch every
 * call passes straight through.
 */
export class ReceiveBatchStorage implements Inner {
  readonly #inner: Inner;
  /** The batch's rows, by unit ID: their state as the held writes leave it. */
  #rows = new Map<string, StoredDataUnit>();
  /** The held rows' IDs by (resource, actor, seq). */
  #byTuple = new Map<string, Set<string>>();
  #depth = 0;

  constructor(inner: Inner) {
    this.#inner = inner;
  }

  get snapshots(): Inner["snapshots"] {
    return this.#inner.snapshots;
  }

  get localMarks(): Inner["localMarks"] {
    return this.#inner.localMarks;
  }

  /** Opens a batch, or joins the open one. */
  begin(): void {
    this.#depth += 1;
  }

  /** Leaves the batch; the outermost end() commits the held writes. */
  async end(): Promise<void> {
    this.#depth -= 1;
    if (this.#depth === 0) await this.#flush();
  }

  /** Runs `call` inside a batch, committing it at the end even when `call` throws. */
  async batch<T>(call: () => Promise<T>): Promise<T> {
    this.begin();
    let result: T;
    try {
      result = await call();
    } catch (e) {
      // The work done so far stays durable, as it was before writes were batched.
      await this.end().catch(() => undefined);
      throw e;
    }
    await this.end();
    return result;
  }

  async #flush(): Promise<void> {
    if (this.#rows.size === 0) return;
    const writes = [...this.#rows.values()].map(
      (u): StorageWrite => ({
        op: "put-data-unit",
        unit: rowOf(u),
        status: u.status,
        ...(u.detail === null ? {} : { detail: u.detail }),
        accepted: u.accepted,
      }),
    );
    this.#rows = new Map();
    this.#byTuple = new Map();
    const r = await this.#inner.commit(writes);
    if (!r.ok) throw new Error(`unexpected storage precondition failure: ${r.reason}`);
  }

  #hold(u: StoredDataUnit): void {
    const id = toHex(u.unitId);
    this.#rows.set(id, u);
    const key = tuple(u.resourceId, u.actor, u.actorSeq);
    let ids = this.#byTuple.get(key);
    if (ids === undefined) {
      ids = new Set();
      this.#byTuple.set(key, ids);
    }
    ids.add(id);
  }

  async #row(unitId: DataUnitId): Promise<StoredDataUnit | undefined> {
    return this.#rows.get(toHex(unitId)) ?? (await this.#inner.dataUnits.get(unitId));
  }

  /** Applies a deferred write to the held rows; false when its unit is not known (storage reports that). */
  async #apply(w: StorageWrite): Promise<boolean> {
    switch (w.op) {
      case "put-data-unit": {
        const old = await this.#row(w.unit.unitId);
        if (old !== undefined && !bytesEqual(old.bytes, w.unit.bytes)) return false;
        this.#hold({
          ...rowOf(old ?? w.unit),
          status: w.status,
          detail: w.detail ?? null,
          accepted: w.accepted ?? old?.accepted ?? false,
        });
        return true;
      }
      case "set-data-unit-status": {
        const old = await this.#row(w.unitId);
        if (old === undefined) return false;
        this.#hold({ ...old, status: w.status, detail: w.detail ?? null });
        return true;
      }
      case "set-accepted": {
        const old = await this.#row(w.unitId);
        if (old === undefined) return false;
        this.#hold({ ...old, accepted: w.accepted });
        return true;
      }
      default:
        return false;
    }
  }

  async commit(writes: readonly StorageWrite[]): Promise<CommitResult> {
    if (this.#depth === 0) return this.#inner.commit(writes);
    if (writes.every((w) => DEFERRED.has(w.op))) {
      // All or nothing, like a commit: check every write before holding any.
      const before = new Map(this.#rows);
      const tuples = new Map([...this.#byTuple].map(([k, v]) => [k, new Set(v)]));
      let held = true;
      for (const w of writes) if (!(await this.#apply(w))) held = false;
      if (held) return { ok: true };
      this.#rows = before;
      this.#byTuple = tuples;
    }
    // Not deferrable: what is held goes first, so storage sees the writes in order.
    await this.#flush();
    return this.#inner.commit(writes);
  }

  /** The inner rows with the held ones in their place, plus the held rows `keep` selects. */
  #merge(
    inner: readonly StoredDataUnit[],
    keep: (u: StoredDataUnit) => boolean,
    order: (a: StoredDataUnit, b: StoredDataUnit) => number,
  ): StoredDataUnit[] {
    if (this.#rows.size === 0) return [...inner];
    const out = inner.filter((u) => !this.#rows.has(toHex(u.unitId)));
    for (const u of this.#rows.values()) if (keep(u)) out.push(u);
    return out.sort(order);
  }

  readonly dataUnits: Inner["dataUnits"] = {
    get: (unitId) => this.#row(unitId),
    at: async (resource, actor, seq) => this.#at(resource, actor, seq),
    range: async (resource, actor, from, to) =>
      this.#merge(
        await this.#inner.dataUnits.range(resource, actor, from, to),
        (u) =>
          bytesEqual(u.resourceId, resource) &&
          bytesEqual(u.actor, actor) &&
          u.actorSeq >= from &&
          u.actorSeq <= to,
        unitOrder,
      ),
    withStatus: async (resource: ResourceId, status: DataUnitStatus) =>
      this.#merge(
        await this.#inner.dataUnits.withStatus(resource, status),
        (u) => bytesEqual(u.resourceId, resource) && u.status === status,
        unitOrder,
      ),
    acceptedAt: async (resource, actor, seq) => {
      if (!this.#byTuple.has(tuple(resource, actor, seq)))
        return this.#inner.dataUnits.acceptedAt(resource, actor, seq);
      return (await this.#at(resource, actor, seq)).find((u) => u.accepted)?.unitId;
    },
    recordSeen: (unit) => this.#recordSeen(unit),
  };

  async #at(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
  ): Promise<StoredDataUnit[]> {
    const inner = await this.#inner.dataUnits.at(resource, actor, seq);
    if (!this.#byTuple.has(tuple(resource, actor, seq))) return inner;
    return this.#merge(
      inner,
      (u) => bytesEqual(u.resourceId, resource) && bytesEqual(u.actor, actor) && u.actorSeq === seq,
      (a, b) => byBytes(a.unitId, b.unitId),
    );
  }

  async #recordSeen(unit: DataUnitRow): Promise<SeenRecord> {
    if (this.#depth === 0) return this.#inner.dataUnits.recordSeen(unit);
    const old = await this.#row(unit.unitId);
    if (old !== undefined && !bytesEqual(old.bytes, unit.bytes))
      throw new LfcpError(
        "INVALID_STRUCTURE",
        `Data Unit ${toHex(unit.unitId)} is stored with other bytes`,
      );
    if (old === undefined)
      this.#hold({ ...rowOf(unit), status: "seen", detail: null, accepted: false });
    const unitIds = (await this.#at(unit.resourceId, unit.actor, unit.actorSeq)).map(
      (u) => u.unitId as DataUnitId,
    );
    return { unitIds, firstSeen: old === undefined };
  }
}
