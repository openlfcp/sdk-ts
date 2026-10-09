/// <reference lib="dom" />
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
  UINT64_MAX,
} from "@openlfcp/core";
import {
  type ActorSequenceReservation,
  type CommitResult,
  type ControlConflictRow,
  type ControlHeadRow,
  type ControlRecordRow,
  type DataUnitRow,
  type DataUnitStatus,
  type EpochRow,
  type KeyPackageRow,
  type LfcpStorage,
  type LocalStateCipher,
  type LocalStateDiagnostics,
  LocalStateKeyring,
  type LocalStateMeta,
  nextActorSequence,
  type OutboundItem,
  type ProfileCheckpoint,
  type ResealRow,
  type ResourceRow,
  type RouteRow,
  reseal,
  type SecretStore,
  type SeenRecord,
  type SnapshotRow,
  type SnapshotSequenceReservation,
  type StorageWrite,
  type StoredDataUnit,
  type SyncStateRow,
} from "@openlfcp/storage";

/**
 * LfcpStorage on IndexedDB (LFCP-059): one database per client install,
 * named by the caller. Portable: browsers, Electron, mobile WebViews.
 *
 * - Atomicity: one commit() is one readwrite transaction over every object
 *   store; the Control Head compare-and-set is read inside it, and any
 *   failure aborts the whole transaction.
 * - Durability: every readwrite transaction asks for durability "strict"
 *   (Chromium's default is relaxed), and a promise resolves only on the
 *   transaction's complete event.
 * - Sequences: a reservation reads the counter, checks it against this
 *   Principal's own stored objects (fail closed, SEQUENCE_REUSE) and writes
 *   it in one strict transaction, then calls onReserved before returning.
 * - Exact bytes: signed objects are stored as their exact bytes; other
 *   fields are indexes. Values are structured clones, so nothing returned
 *   aliases a stored buffer or a caller's.
 *
 * A transaction only awaits IndexedDB requests (never other promises), so it
 * cannot auto-commit half way.
 */

const VERSION = 1;
const STORES = [
  "records",
  "heads",
  "conflicts",
  "epochs",
  "units",
  "keyPackages",
  "snapshots",
  "resources",
  "routes",
  "outbound",
  "checkpoints",
  "syncStates",
  "counters",
  "meta",
] as const;
type Store = (typeof STORES)[number];

/** A reservation that is durable and about to be returned. */
export interface ReservedSequence {
  readonly kind: "actor" | "snapshot";
  /** The counter's key, as counters() lists it. */
  readonly key: string;
  readonly value: bigint;
}

export interface IdbStorageOptions {
  /** The IndexedDB factory (default: globalThis.indexedDB). */
  readonly indexedDB?: IDBFactory;
  /**
   * Called after a reservation is durable and before it is returned (e.g.
   * to mirror a high-water mark elsewhere). If it throws, the reservation
   * fails and its value is abandoned, never reissued.
   */
  readonly onReserved?: (reserved: ReservedSequence) => void;
  /**
   * Local state encrypted at rest (LFCP-02-098): the SecretStore that holds
   * the install's local state key, and the cipher (`localStateCipher` of
   * @openlfcp/crypto). Profile checkpoints are then stored as `lse1`
   * envelopes. A database that seals its local state cannot be opened
   * without it.
   */
  readonly localState?: IdbLocalState;
}

export interface IdbLocalState {
  readonly secrets: SecretStore;
  readonly cipher: LocalStateCipher;
  /** The clock of the diagnostics' events (default: the system clock). */
  readonly now?: () => Date;
}

/** The meta key of the local state encryption metadata; the store name of checkpoints in their AAD. */
const LOCAL_STATE = "local-state";
const CHECKPOINTS = "checkpoints";

const hex = toHex;
/** uint64 as a fixed-width decimal string, so key order is numeric order. */
const pad = (n: bigint): string => n.toString().padStart(20, "0");
/** Local marks share the meta store under this key prefix. */
const MARK = "mark:";
const LOW = "";
const HIGH = "￿";
const actorKey = (r: ResourceId, p: PrincipalId): string => `actor:${hex(r)}:${hex(p)}`;
const snapshotKey = (r: ResourceId, e: DataEpoch, p: PrincipalId): string =>
  `snapshot:${hex(r)}:${e}:${hex(p)}`;
const ORDER_KEY = "order:outbound";

/** A deep copy, frozen; structured clones are already copies, this freezes them. */
function own<T>(value: T): T {
  if (value instanceof Uint8Array) return Uint8Array.from(value) as T;
  if (Array.isArray(value)) return Object.freeze(value.map(own)) as T;
  if (value !== null && typeof value === "object")
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([k, v]) => [k, own(v)])),
    ) as T;
  return value;
}
const copyOf = <T>(value: T | undefined): T | undefined =>
  value === undefined ? undefined : own(value);

const byHex = (a: Uint8Array, b: Uint8Array): number => {
  const [x, y] = [hex(a), hex(b)];
  return x < y ? -1 : x > y ? 1 : 0;
};
const byBig = (a: bigint, b: bigint): number => (a < b ? -1 : a > b ? 1 : 0);
const UNIT_ORDER = (a: StoredDataUnit, b: StoredDataUnit): number =>
  byHex(a.actor, b.actor) || byBig(a.actorSeq, b.actorSeq) || byHex(a.unitId, b.unitId);

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

interface UnitValue {
  readonly r: string;
  readonly a: string;
  readonly s: string;
  readonly st: DataUnitStatus;
  readonly row: StoredDataUnit;
}
interface SnapshotValue {
  readonly r: string;
  readonly e: string;
  readonly p: string;
  readonly n: string;
  readonly row: SnapshotRow;
}
interface Keyed<T> {
  readonly r: string;
  readonly row: T;
}
interface OutboundValue {
  readonly r: string;
  readonly n: number;
  readonly row: OutboundItem;
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

const unitValue = (row: StoredDataUnit): UnitValue => ({
  r: hex(row.resourceId),
  a: hex(row.actor),
  s: pad(row.actorSeq),
  st: row.status,
  row,
});

class HeadMismatch {
  constructor(readonly result: CommitResult) {}
}

function upgrade(db: IDBDatabase): void {
  const plain = (name: Store) => db.createObjectStore(name);
  db.createObjectStore("records").createIndex("r", "r");
  plain("heads");
  plain("conflicts");
  db.createObjectStore("epochs").createIndex("r", "r");
  const units = db.createObjectStore("units");
  units.createIndex("ras", ["r", "a", "s"]);
  units.createIndex("rst", ["r", "st"]);
  db.createObjectStore("keyPackages").createIndex("r", "r");
  const snapshots = db.createObjectStore("snapshots");
  snapshots.createIndex("r", "r");
  snapshots.createIndex("rep", ["r", "e", "p", "n"]);
  plain("resources");
  plain("routes");
  db.createObjectStore("outbound").createIndex("n", "n");
  plain("checkpoints");
  plain("syncStates");
  plain("counters");
  plain("meta");
}

export class IdbLfcpStorage implements LfcpStorage {
  readonly #db: IDBDatabase;
  readonly #onReserved: ((r: ReservedSequence) => void) | undefined;
  readonly #localState: IdbLocalState | undefined;
  #keyring: LocalStateKeyring | null = null;

  private constructor(db: IDBDatabase, options: IdbStorageOptions) {
    this.#db = db;
    this.#onReserved = options.onReserved;
    this.#localState = options.localState;
  }

  /** Opens (creating or upgrading) the database `name`. */
  static async open(name: string, options: IdbStorageOptions = {}): Promise<IdbLfcpStorage> {
    const factory = options.indexedDB ?? globalThis.indexedDB;
    if (factory === undefined)
      throw new LfcpError("UNSUPPORTED_VALUE", "IndexedDB is not available in this runtime");
    const open = factory.open(name, VERSION);
    open.onupgradeneeded = () => upgrade(open.result);
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
      open.onblocked = () =>
        reject(
          new LfcpError("UNSUPPORTED_VALUE", `IndexedDB ${name} is blocked by another connection`),
        );
    });
    const storage = new IdbLfcpStorage(db, options);
    try {
      await storage.#startLocalState();
    } catch (e) {
      db.close();
      throw e;
    }
    return storage;
  }

  #now(): string {
    return (this.#localState?.now?.() ?? new Date()).toISOString();
  }

  /**
   * LFCP-02-098: with `localState`, prepares the keyring (the key goes to the
   * SecretStore before the metadata that names it), then migrates, or
   * continues a half-done migration or rotation. Without it, a database that
   * seals its local state is refused.
   */
  async #startLocalState(): Promise<void> {
    const stored = (await this.meta.get(LOCAL_STATE)) as LocalStateMeta | undefined;
    const local = this.#localState;
    if (local === undefined) {
      if (stored !== undefined)
        throw new LfcpError(
          "UNSUPPORTED_VALUE",
          "this database seals its local state: open it with the localState option",
        );
      return;
    }
    const keyring = await LocalStateKeyring.prepare(
      local.cipher,
      local.secrets,
      stored,
      this.#now(),
    );
    if (JSON.stringify(keyring.meta) !== JSON.stringify(stored))
      await this.meta.put(LOCAL_STATE, keyring.meta);
    this.#keyring = keyring;
    if (keyring.meta.phase !== "ready") await this.#finishPhase();
  }

  /**
   * Seals every checkpoint the current phase needs, in resumable batches,
   * then records the phase as ready and removes a key a rotation retired. A
   * batch writes a row only if it still holds the bytes it read, so a
   * checkpoint committed meanwhile is never overwritten.
   */
  async #finishPhase(): Promise<void> {
    const keyring = this.#keyring as LocalStateKeyring;
    const read = new Map<string, Uint8Array>();
    const scan = (after: string | null, limit: number): Promise<ResealRow[]> =>
      this.#tx(["checkpoints"], "readonly", async (tx) => {
        const range = after === null ? undefined : IDBKeyRange.lowerBound(after, true);
        const values = (await req(
          tx.objectStore("checkpoints").getAll(range, limit),
        )) as ProfileCheckpoint[];
        return values.map((c) => {
          const key = hex(c.resourceId);
          read.set(key, c.state);
          return { store: CHECKPOINTS, key, bytes: Uint8Array.from(c.state) };
        });
      });
    const write = (rows: readonly ResealRow[]): Promise<void> =>
      this.#tx(["checkpoints"], "readwrite", async (tx) => {
        const store = tx.objectStore("checkpoints");
        for (const r of rows) {
          const now = (await req(store.get(r.key))) as ProfileCheckpoint | undefined;
          const before = read.get(r.key);
          if (now === undefined || before === undefined || !bytesEqual(now.state, before)) continue;
          await req(store.put({ ...now, state: r.bytes }, r.key));
        }
      });
    await reseal(keyring, scan, write);
    const retired = keyring.retired;
    const finished = keyring.finished(this.#now());
    await this.meta.put(LOCAL_STATE, finished.meta);
    this.#keyring = finished;
    // The old key goes last: a crash before this line leaves it, harmlessly.
    if (retired !== null) await (this.#localState as IdbLocalState).secrets.delete(retired);
  }

  /**
   * Rotates the local state key (LFCP-02-098 §8): writes the next
   * generation's key, seals every checkpoint again, then removes the old
   * key. Resumed on the next open after a crash.
   */
  async rotateLocalStateKey(): Promise<void> {
    if (this.#keyring === null || this.#localState === undefined)
      throw new LfcpError("UNSUPPORTED_VALUE", "this database was not opened with localState");
    this.#keyring = await this.#keyring.rotate(this.#localState.secrets, this.#now());
    await this.meta.put(LOCAL_STATE, this.#keyring.meta);
    await this.#finishPhase();
  }

  /** The local state encryption status, or null when the database was opened without it. */
  async localStateDiagnostics(): Promise<LocalStateDiagnostics | null> {
    const keyring = this.#keyring;
    if (keyring === null) return null;
    const values = await this.#tx(
      ["checkpoints"],
      "readonly",
      async (tx) => (await req(tx.objectStore("checkpoints").getAll())) as ProfileCheckpoint[],
    );
    const rows = { sealed: 0, plaintext: 0, unreadable: 0 };
    for (const c of values) {
      const opened = keyring.open(CHECKPOINTS, hex(c.resourceId), c.state);
      if (opened.kind === "plain") rows.plaintext++;
      else if (opened.kind === "opened") rows.sealed++;
      else rows.unreadable++;
    }
    return Object.freeze({
      scheme: keyring.meta.scheme,
      generation: keyring.meta.generation,
      keyPresent: keyring.keyPresent,
      phase: keyring.meta.phase,
      rows: Object.freeze(rows),
      lastEvent: keyring.meta.lastEvent,
    });
  }

  /** Closes the connection; later calls fail. */
  close(): void {
    this.#db.close();
  }

  async #tx<T>(
    stores: readonly Store[],
    mode: IDBTransactionMode,
    body: (tx: IDBTransaction) => Promise<T>,
  ): Promise<T> {
    const tx =
      mode === "readwrite"
        ? this.#db.transaction([...stores], mode, { durability: "strict" })
        : this.#db.transaction([...stores], mode);
    const done = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () =>
        reject(tx.error ?? new LfcpError("UNSUPPORTED_VALUE", "the transaction was aborted"));
    });
    let result: T;
    try {
      result = await body(tx);
    } catch (e) {
      try {
        tx.abort();
      } catch {
        // already aborting or finished
      }
      await done.catch(() => undefined);
      throw e;
    }
    await done;
    return result;
  }

  // -------------------------------------------------------------------------
  // Writes

  async commit(writes: readonly StorageWrite[]): Promise<CommitResult> {
    try {
      return await this.#tx(STORES, "readwrite", async (tx) => {
        for (const w of writes) {
          if (w.op !== "set-control-head") continue;
          const head = (await req(tx.objectStore("heads").get(hex(w.resourceId)))) as
            | ControlHeadRow
            | undefined;
          const current = head?.head ?? null;
          const matches =
            current === null
              ? w.expected === null
              : w.expected !== null && bytesEqual(current, w.expected);
          if (!matches)
            throw new HeadMismatch(
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
          const [r, a] = [hex(w.resourceId), hex(w.actor)];
          let cursor = await req(
            tx
              .objectStore("units")
              .index("ras")
              .openCursor(IDBKeyRange.bound([r, a, LOW], [r, a, HIGH]), "prev"),
          );
          while (cursor !== null && !(cursor.value as UnitValue).row.accepted) {
            cursor.continue();
            cursor = await req(cursor.request as IDBRequest<IDBCursorWithValue | null>);
          }
          const current = cursor === null ? null : (cursor.value as UnitValue).row.unitId;
          const matches =
            current === null
              ? w.previous === null
              : w.previous !== null && bytesEqual(current, w.previous);
          if (!matches)
            throw new HeadMismatch(
              Object.freeze({
                ok: false,
                reason: "PREVIOUS_UNIT_MISMATCH",
                resourceId: own(w.resourceId),
                actor: own(w.actor),
                current: current === null ? null : own(current),
              }),
            );
        }
        for (const w of writes) await this.#apply(tx, w);
        return Object.freeze({ ok: true }) as CommitResult;
      });
    } catch (e) {
      if (e instanceof HeadMismatch) return e.result;
      throw e;
    }
  }

  async #putImmutable<T extends { readonly bytes: Uint8Array }>(
    store: IDBObjectStore,
    id: Uint8Array,
    value: { readonly row: T } & Record<string, unknown>,
    what: string,
  ): Promise<void> {
    const old = (await req(store.get(hex(id)))) as { readonly row: T } | undefined;
    if (old !== undefined) {
      if (!bytesEqual(old.row.bytes, value.row.bytes))
        throw new LfcpError("INVALID_STRUCTURE", `${what} ${hex(id)} is stored with other bytes`);
      return;
    }
    await req(store.put(value, hex(id)));
  }

  async #knownUnit(tx: IDBTransaction, unitId: DataUnitId): Promise<StoredDataUnit> {
    const v = (await req(tx.objectStore("units").get(hex(unitId)))) as UnitValue | undefined;
    if (v === undefined) throw new LfcpError("INVALID_STRUCTURE", `no Data Unit ${hex(unitId)}`);
    return v.row;
  }

  async #apply(tx: IDBTransaction, w: StorageWrite): Promise<void> {
    const s = (name: Store) => tx.objectStore(name);
    switch (w.op) {
      case "put-control-records":
        for (const r of w.records)
          await this.#putImmutable(
            s("records"),
            r.recordId,
            { r: hex(r.resourceId), row: r } satisfies Keyed<ControlRecordRow>,
            "Control Record",
          );
        return;
      case "set-control-head":
        await req(s("heads").put(w.head, hex(w.resourceId)));
        return;
      case "set-control-conflict":
        if (w.conflict === null) await req(s("conflicts").delete(hex(w.resourceId)));
        else await req(s("conflicts").put(w.conflict, hex(w.resourceId)));
        return;
      case "expect-previous-unit":
        return; // a precondition, checked by commit()
      case "put-epoch": {
        const key = `${hex(w.resourceId)}:${pad(BigInt(w.epoch.epoch))}`;
        // A null dekRef or closedBy never clears a stored one (read and write
        // in this transaction).
        const stored = (await req(s("epochs").get(key))) as Keyed<EpochRow> | undefined;
        const row = {
          ...w.epoch,
          closedBy: w.epoch.closedBy ?? stored?.row.closedBy ?? null,
          dekRef: w.epoch.dekRef ?? stored?.row.dekRef ?? null,
        };
        await req(s("epochs").put({ r: hex(w.resourceId), row } satisfies Keyed<EpochRow>, key));
        return;
      }
      case "put-data-unit": {
        const old = (await req(s("units").get(hex(w.unit.unitId)))) as UnitValue | undefined;
        if (old !== undefined && !bytesEqual(old.row.bytes, w.unit.bytes))
          throw new LfcpError(
            "INVALID_STRUCTURE",
            `Data Unit ${hex(w.unit.unitId)} is stored with other bytes`,
          );
        const row: StoredDataUnit = {
          ...pickUnit(old?.row ?? w.unit),
          status: w.status,
          detail: w.detail ?? null,
          accepted: w.accepted ?? old?.row.accepted ?? false,
        };
        await req(s("units").put(unitValue(row), hex(w.unit.unitId)));
        return;
      }
      case "set-data-unit-status": {
        const old = await this.#knownUnit(tx, w.unitId);
        const row = { ...old, status: w.status, detail: w.detail ?? null };
        await req(s("units").put(unitValue(row), hex(w.unitId)));
        return;
      }
      case "set-accepted": {
        const old = await this.#knownUnit(tx, w.unitId);
        await req(s("units").put(unitValue({ ...old, accepted: w.accepted }), hex(w.unitId)));
        return;
      }
      case "put-key-package":
        await this.#putImmutable(
          s("keyPackages"),
          w.row.packageId,
          { r: hex(w.row.resourceId), row: w.row } satisfies Keyed<KeyPackageRow>,
          "Key Package",
        );
        return;
      case "put-snapshot":
        await this.#putImmutable(
          s("snapshots"),
          w.row.snapshotId,
          {
            r: hex(w.row.resourceId),
            e: pad(BigInt(w.row.dataEpoch)),
            p: hex(w.row.publisher),
            n: pad(w.row.snapshotSeq),
            row: w.row,
          } satisfies SnapshotValue,
          "Snapshot",
        );
        return;
      case "delete-snapshot":
        await req(s("snapshots").delete(hex(w.snapshotId)));
        return;
      case "put-resource":
        await req(s("resources").put(w.row, hex(w.row.resourceId)));
        return;
      case "put-route":
        await req(s("routes").put(w.route, hex(w.resourceId)));
        return;
      case "enqueue": {
        const old = (await req(s("outbound").get(hex(w.item.itemId)))) as OutboundValue | undefined;
        if (old !== undefined) {
          if (!bytesEqual(old.row.bytes, w.item.bytes))
            throw new LfcpError(
              "INVALID_STRUCTURE",
              `outbound item ${hex(w.item.itemId)} is stored with other bytes`,
            );
          return;
        }
        const n = ((await req(s("counters").get(ORDER_KEY))) as number | undefined) ?? 0;
        await req(s("counters").put(n + 1, ORDER_KEY));
        await req(
          s("outbound").put(
            { r: hex(w.item.resourceId), n: n + 1, row: w.item } satisfies OutboundValue,
            hex(w.item.itemId),
          ),
        );
        return;
      }
      case "update-outbound": {
        const old = (await req(s("outbound").get(hex(w.itemId)))) as OutboundValue | undefined;
        if (old === undefined)
          throw new LfcpError("INVALID_STRUCTURE", `no outbound item ${hex(w.itemId)}`);
        const row: OutboundItem = {
          ...old.row,
          ...(w.attempts === undefined ? {} : { attempts: w.attempts }),
          ...(w.lastAttempt === undefined ? {} : { lastAttempt: w.lastAttempt }),
          ...(w.nextAttempt === undefined ? {} : { nextAttempt: w.nextAttempt }),
          ...(w.blocked === undefined ? {} : { blocked: w.blocked }),
        };
        await req(s("outbound").put({ ...old, row }, hex(w.itemId)));
        return;
      }
      case "dequeue":
        await req(s("outbound").delete(hex(w.itemId)));
        return;
      case "put-profile-checkpoint": {
        const key = hex(w.checkpoint.resourceId);
        const state =
          this.#keyring === null
            ? w.checkpoint.state
            : this.#keyring.seal(CHECKPOINTS, key, w.checkpoint.state);
        await req(s("checkpoints").put({ ...w.checkpoint, state }, key));
        return;
      }
      case "put-sync-state":
        await req(s("syncStates").put(w.row, hex(w.row.resourceId)));
        return;
      case "put-local-mark": {
        // Kept in the meta store under "mark:" (no schema change).
        const key = `${MARK}${w.key}`;
        if (w.value === null) await req(s("meta").delete(key));
        else await req(s("meta").put(w.value, key));
        return;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Sequence reservations

  readonly actorSequences: ActorSequenceReservation = {
    reserveNext: async (resource, principal) => {
      const key = actorKey(resource, principal);
      const next = await this.#tx(["counters", "units"], "readwrite", async (tx) => {
        const last = (await req(tx.objectStore("counters").get(key))) as ActorSequence | undefined;
        const next = nextActorSequence(last);
        const [r, a] = [hex(resource), hex(principal)];
        const top = await req(
          tx
            .objectStore("units")
            .index("ras")
            .openCursor(IDBKeyRange.bound([r, a, LOW], [r, a, HIGH]), "prev"),
        );
        const max = top === null ? 0n : (top.value as UnitValue).row.actorSeq;
        // Fail closed (§9): a counter behind this Principal's own stored units
        // (a restored backup, a lost row) must never hand out a used sequence.
        if (next <= max)
          throw new LfcpError(
            "SEQUENCE_REUSE",
            `the actor sequence state (${next - 1n}) is behind the stored units of this Principal (${max}); refusing to reserve (§9)`,
          );
        await req(tx.objectStore("counters").put(next, key));
        return next;
      });
      this.#onReserved?.({ kind: "actor", key, value: next });
      return next;
    },
  };

  readonly snapshotSequences: SnapshotSequenceReservation = {
    reserveNext: async (resource, epoch, publisher) => {
      const key = snapshotKey(resource, epoch, publisher);
      const next = await this.#tx(["counters", "snapshots"], "readwrite", async (tx) => {
        const last = ((await req(tx.objectStore("counters").get(key))) as bigint | undefined) ?? 0n;
        if (last >= UINT64_MAX)
          throw new LfcpError("OUT_OF_RANGE", "the Snapshot Sequence space is exhausted (§29)");
        const [r, e, p] = [hex(resource), pad(BigInt(epoch)), hex(publisher)];
        const top = await req(
          tx
            .objectStore("snapshots")
            .index("rep")
            .openCursor(IDBKeyRange.bound([r, e, p, LOW], [r, e, p, HIGH]), "prev"),
        );
        const max = top === null ? 0n : (top.value as SnapshotValue).row.snapshotSeq;
        if (last + 1n <= max)
          throw new LfcpError(
            "SEQUENCE_REUSE",
            `the Snapshot Sequence state (${last}) is behind the stored Snapshots of this publisher (${max}); refusing to reserve (§29)`,
          );
        await req(tx.objectStore("counters").put(last + 1n, key));
        return last + 1n;
      });
      this.#onReserved?.({ kind: "snapshot", key, value: next });
      return next;
    },
  };

  /** Every reservation counter: `actor:<resource>:<principal>` and `snapshot:<resource>:<epoch>:<publisher>`. */
  async counters(): Promise<ReadonlyMap<string, bigint>> {
    return this.#tx(["counters"], "readonly", async (tx) => {
      const store = tx.objectStore("counters");
      const [keys, values] = await Promise.all([req(store.getAllKeys()), req(store.getAll())]);
      const out = new Map<string, bigint>();
      keys.forEach((k, i) => {
        if (typeof k === "string" && (k.startsWith("actor:") || k.startsWith("snapshot:")))
          out.set(k, values[i] as bigint);
      });
      return out;
    });
  }

  /**
   * Adapter-local metadata for the application (e.g. an install marker):
   * structured-cloneable values, durable like everything else. Never secrets.
   */
  readonly meta = {
    get: (key: string): Promise<unknown> =>
      this.#tx(["meta"], "readonly", async (tx) =>
        copyOf(await req(tx.objectStore("meta").get(key))),
      ),
    put: (key: string, value: unknown): Promise<void> =>
      this.#tx(["meta"], "readwrite", async (tx) => {
        await req(tx.objectStore("meta").put(value, key));
      }),
  };

  // -------------------------------------------------------------------------
  // Readers

  #get<T>(store: Store, key: string): Promise<T | undefined> {
    return this.#tx([store], "readonly", async (tx) => {
      const v = (await req(tx.objectStore(store).get(key))) as T | undefined;
      return copyOf(v);
    });
  }

  #byResource<T>(store: Store, resource: ResourceId): Promise<T[]> {
    return this.#tx([store], "readonly", async (tx) =>
      ((await req(tx.objectStore(store).index("r").getAll(hex(resource)))) as Keyed<T>[]).map(
        (v) => v.row,
      ),
    );
  }

  #unitsWhere(range: IDBKeyRange, index: "ras" | "rst"): Promise<StoredDataUnit[]> {
    return this.#tx(["units"], "readonly", async (tx) =>
      ((await req(tx.objectStore("units").index(index).getAll(range))) as UnitValue[]).map(
        (v) => v.row,
      ),
    );
  }

  #at(resource: ResourceId, actor: PrincipalId, seq: ActorSequence): Promise<StoredDataUnit[]> {
    return this.#unitsWhere(IDBKeyRange.only([hex(resource), hex(actor), pad(seq)]), "ras").then(
      (us) => us.sort((a, b) => byHex(a.unitId, b.unitId)),
    );
  }

  readonly control = {
    record: (id: ControlRecordId) =>
      this.#get<Keyed<ControlRecordRow>>("records", hex(id)).then((v) => v?.row),
    records: async (resource: ResourceId) =>
      (await this.#byResource<ControlRecordRow>("records", resource))
        .sort((a, b) => byBig(a.controlSeq, b.controlSeq) || byHex(a.recordId, b.recordId))
        .map(own),
    head: (resource: ResourceId) => this.#get<ControlHeadRow>("heads", hex(resource)),
    conflict: (resource: ResourceId) => this.#get<ControlConflictRow>("conflicts", hex(resource)),
    epochs: async (resource: ResourceId) =>
      (await this.#byResource<EpochRow>("epochs", resource))
        .sort((a, b) => byBig(a.epoch, b.epoch))
        .map(own),
  };

  readonly dataUnits = {
    get: (id: DataUnitId) => this.#get<UnitValue>("units", hex(id)).then((v) => v?.row),
    at: async (resource: ResourceId, actor: PrincipalId, seq: ActorSequence) =>
      (await this.#at(resource, actor, seq)).map(own),
    range: async (
      resource: ResourceId,
      actor: PrincipalId,
      from: ActorSequence,
      to: ActorSequence,
    ) => {
      if (from > to) return [];
      const [r, a] = [hex(resource), hex(actor)];
      return (await this.#unitsWhere(IDBKeyRange.bound([r, a, pad(from)], [r, a, pad(to)]), "ras"))
        .sort(UNIT_ORDER)
        .map(own);
    },
    withStatus: async (resource: ResourceId, status: DataUnitStatus) =>
      (await this.#unitsWhere(IDBKeyRange.only([hex(resource), status]), "rst"))
        .sort(UNIT_ORDER)
        .map(own),
    acceptedAt: async (resource: ResourceId, actor: PrincipalId, seq: ActorSequence) =>
      copyOf((await this.#at(resource, actor, seq)).find((u) => u.accepted)?.unitId),
    recordSeen: (unit: DataUnitRow): Promise<SeenRecord> =>
      this.#tx(["units"], "readwrite", async (tx) => {
        const store = tx.objectStore("units");
        const old = (await req(store.get(hex(unit.unitId)))) as UnitValue | undefined;
        if (old !== undefined && !bytesEqual(old.row.bytes, unit.bytes))
          throw new LfcpError(
            "INVALID_STRUCTURE",
            `Data Unit ${hex(unit.unitId)} is stored with other bytes`,
          );
        if (old === undefined)
          await req(
            store.put(
              unitValue({ ...pickUnit(unit), status: "seen", detail: null, accepted: false }),
              hex(unit.unitId),
            ),
          );
        const all = (await req(
          store
            .index("ras")
            .getAll(IDBKeyRange.only([hex(unit.resourceId), hex(unit.actor), pad(unit.actorSeq)])),
        )) as UnitValue[];
        const unitIds = all.map((v) => own(v.row.unitId)).sort(byHex);
        return Object.freeze({ unitIds: Object.freeze(unitIds), firstSeen: old === undefined });
      }),
  };

  readonly keyPackages = {
    get: (id: Hash32) =>
      this.#get<Keyed<KeyPackageRow>>("keyPackages", hex(id)).then((v) => v?.row),
    list: async (
      resource: ResourceId,
      filter: { readonly epoch?: DataEpoch; readonly recipient?: PrincipalId } = {},
    ) =>
      (await this.#byResource<KeyPackageRow>("keyPackages", resource))
        .filter(
          (k) =>
            (filter.epoch === undefined || k.dataEpoch === filter.epoch) &&
            (filter.recipient === undefined || bytesEqual(k.recipient, filter.recipient)),
        )
        .sort((a, b) => byBig(a.dataEpoch, b.dataEpoch) || byHex(a.packageId, b.packageId))
        .map(own),
  };

  readonly snapshots = {
    get: (id: Hash32) => this.#get<SnapshotValue>("snapshots", hex(id)).then((v) => v?.row),
    list: async (resource: ResourceId, filter: { readonly epoch?: DataEpoch } = {}) =>
      (await this.#byResource<SnapshotRow>("snapshots", resource))
        .filter((x) => filter.epoch === undefined || x.dataEpoch === filter.epoch)
        .sort(
          (a, b) =>
            byBig(a.dataEpoch, b.dataEpoch) ||
            byHex(a.publisher, b.publisher) ||
            byBig(a.snapshotSeq, b.snapshotSeq),
        )
        .map(own),
  };

  readonly resources = {
    get: (resource: ResourceId) => this.#get<ResourceRow>("resources", hex(resource)),
    list: () =>
      this.#tx(["resources"], "readonly", async (tx) =>
        ((await req(tx.objectStore("resources").getAll())) as ResourceRow[])
          .sort((a, b) => byHex(a.resourceId, b.resourceId))
          .map(own),
      ),
    route: (resource: ResourceId) => this.#get<RouteRow>("routes", hex(resource)),
  };

  readonly outbound = {
    list: (resource?: ResourceId) =>
      this.#tx(["outbound"], "readonly", async (tx) =>
        ((await req(tx.objectStore("outbound").index("n").getAll())) as OutboundValue[])
          .filter((v) => resource === undefined || v.r === hex(resource))
          .map((v) => own(v.row)),
      ),
    get: (id: Hash32) => this.#get<OutboundValue>("outbound", hex(id)).then((v) => v?.row),
  };

  readonly profileState = {
    checkpoint: async (resource: ResourceId): Promise<ProfileCheckpoint | undefined> => {
      const row = await this.#get<ProfileCheckpoint>("checkpoints", hex(resource));
      if (row === undefined || this.#keyring === null) return row;
      const opened = this.#keyring.open(CHECKPOINTS, hex(resource), row.state);
      // Sealed under a lost key: absent, rebuilt from the stored units.
      if (opened.kind === "unreadable") return undefined;
      return Object.freeze({ ...row, state: opened.bytes });
    },
  };

  readonly syncState = {
    get: (resource: ResourceId) => this.#get<SyncStateRow>("syncStates", hex(resource)),
  };

  readonly localMarks = {
    get: (key: string) => this.#get<string>("meta", `${MARK}${key}`),
    list: (prefix: string) =>
      this.#tx(["meta"], "readonly", async (tx) => {
        const range = IDBKeyRange.bound(`${MARK}${prefix}`, `${MARK}${prefix}${HIGH}`);
        const store = tx.objectStore("meta");
        const [keys, values] = await Promise.all([
          req(store.getAllKeys(range)),
          req(store.getAll(range)),
        ]);
        return keys.map((k, i) => ({
          key: (k as string).slice(MARK.length),
          value: values[i] as string,
        }));
      }),
  };
}
