import {
  type ActorSequence,
  actorSequence,
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
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
  type ControlReader,
  type ControlRecordRow,
  type DataUnitReader,
  type DataUnitRow,
  type DataUnitStatus,
  type EpochRow,
  type KeyPackageReader,
  type KeyPackageRow,
  type LfcpStorage,
  nextActorSequence,
  type OutboundItem,
  type OutboundKind,
  type OutboundReader,
  type ProfileCheckpoint,
  type ProfileStateReader,
  type ResourceReader,
  type ResourceRow,
  type RouteRow,
  type SecretRef,
  type SeenRecord,
  type SnapshotReader,
  type SnapshotRow,
  type SnapshotSequenceReservation,
  type StorageWrite,
  type StoredDataUnit,
} from "@openlfcp/storage";
import Database from "better-sqlite3";
import { migrate } from "./schema.js";

/**
 * LfcpStorage on SQLite (better-sqlite3), for headless Node, the CLI,
 * examples and tests (LFCP-035). Obsidian uses its own adapter (LFCP-059);
 * both run the same contract suite.
 *
 * Durability: WAL journal with synchronous=FULL, so a transaction is on
 * disk when it commits, and every promise resolves after its transaction
 * committed. One commit() is one BEGIN IMMEDIATE transaction: all writes
 * or none. Sequence reservations read and advance their counter inside one
 * BEGIN IMMEDIATE transaction (which holds the write lock across
 * processes), so no two callers, in this process or another, ever get the
 * same value; a crash after the commit skips that value, never reuses it.
 * The guarantees are SQLite's on a local filesystem with working fsync,
 * nothing more.
 */

type Row = Record<string, unknown>;

/** uint64 as 20-digit zero-padded TEXT (sorts numerically, never overflows). */
const u64 = (n: bigint): string => n.toString().padStart(20, "0");
const fromU64 = (s: unknown): bigint => BigInt(s as string);
const blob = (b: Uint8Array): Buffer => Buffer.from(b);
/** A copy as a plain Uint8Array: nothing returned aliases SQLite's buffers. */
const bytes = (v: unknown): Uint8Array => Uint8Array.from(v as Buffer);
const as = <T>(v: unknown): T => bytes(v) as unknown as T;
const maybeAs = <T>(v: unknown): T | null => (v === null ? null : as<T>(v));

const refused = (what: string, id: Uint8Array): never => {
  throw new LfcpError("INVALID_STRUCTURE", `${what} ${toHex(id)} is stored with other bytes`);
};

const IDS = 32;
const joinIds = (ids: readonly Uint8Array[]): Buffer =>
  Buffer.concat(ids.map((i) => Buffer.from(i)));
const splitIds = <T>(v: unknown): T[] => {
  const all = bytes(v);
  const out: T[] = [];
  for (let i = 0; i < all.length; i += IDS) out.push(all.slice(i, i + IDS) as unknown as T);
  return out;
};

const controlRecord = (r: Row): ControlRecordRow => ({
  recordId: as<ControlRecordId>(r.record_id),
  resourceId: as<ResourceId>(r.resource_id),
  controlSeq: fromU64(r.control_seq),
  prevControlId: maybeAs<ControlRecordId>(r.prev_id),
  bytes: bytes(r.bytes),
});

const epochRow = (r: Row): EpochRow => ({
  epoch: dataEpoch(fromU64(r.epoch)),
  dekCommitment: as<Hash32>(r.dek_commitment),
  openedBy: as<ControlRecordId>(r.opened_by),
  closedBy: maybeAs<ControlRecordId>(r.closed_by),
  dekRef: (r.dek_ref as SecretRef | null) ?? null,
});

const storedUnit = (r: Row): StoredDataUnit => ({
  unitId: as<DataUnitId>(r.unit_id),
  resourceId: as<ResourceId>(r.resource_id),
  dataEpoch: dataEpoch(fromU64(r.data_epoch)),
  actor: as<PrincipalId>(r.actor),
  actorSeq: actorSequence(fromU64(r.actor_seq)),
  prevDataUnitId: maybeAs<DataUnitId>(r.prev_id),
  controlHead: as<ControlRecordId>(r.control_head),
  bytes: bytes(r.bytes),
  status: r.status as DataUnitStatus,
  detail: (r.detail as string | null) ?? null,
  accepted: r.accepted === 1,
});

const keyPackage = (r: Row): KeyPackageRow => ({
  packageId: as<Hash32>(r.package_id),
  resourceId: as<ResourceId>(r.resource_id),
  dataEpoch: dataEpoch(fromU64(r.data_epoch)),
  recipient: as<PrincipalId>(r.recipient),
  sender: as<PrincipalId>(r.sender),
  bytes: bytes(r.bytes),
});

const snapshot = (r: Row): SnapshotRow => ({
  snapshotId: as<Hash32>(r.snapshot_id),
  resourceId: as<ResourceId>(r.resource_id),
  dataEpoch: dataEpoch(fromU64(r.data_epoch)),
  publisher: as<PrincipalId>(r.publisher),
  snapshotSeq: fromU64(r.snapshot_seq),
  frontier: bytes(r.frontier),
  bytes: bytes(r.bytes),
});

const resource = (r: Row): ResourceRow => ({
  resourceId: as<ResourceId>(r.resource_id),
  dataProfile: r.data_profile as string,
  localPrincipal:
    r.local_principal === null
      ? null
      : {
          principalId: as<PrincipalId>(r.local_principal),
          signingKeyRef: r.signing_ref as SecretRef,
          agreementKeyRef: r.agreement_ref as SecretRef,
        },
  labels: JSON.parse(r.labels as string) as Record<string, string>,
});

interface StoredEndpoint {
  readonly url: string;
  readonly priority: string;
  readonly flags?: string;
}

const route = (r: Row): RouteRow => ({
  routeVersion: fromU64(r.route_version),
  endpoints: (JSON.parse(r.endpoints as string) as StoredEndpoint[]).map((e) => ({
    url: e.url,
    priority: BigInt(e.priority),
    ...(e.flags === undefined ? {} : { flags: BigInt(e.flags) }),
  })),
  coordinatorUrl: r.coordinator_url as string,
  source: as<ControlRecordId>(r.source),
});

const outboundItem = (r: Row): OutboundItem => ({
  itemId: as<Hash32>(r.item_id),
  resourceId: as<ResourceId>(r.resource_id),
  kind: r.kind as OutboundKind,
  bytes: bytes(r.bytes),
  attempts: r.attempts as number,
  lastAttempt: (r.last_attempt as string | null) ?? null,
});

const checkpointRow = (r: Row): ProfileCheckpoint => ({
  resourceId: as<ResourceId>(r.resource_id),
  dataProfile: r.data_profile as string,
  state: bytes(r.state),
  actorSeq: r.actor_seq as number,
  units: (JSON.parse(r.units as string) as [string, string][]).map(([unitId, ref]) => ({
    unitId: Uint8Array.from(Buffer.from(unitId, "hex")) as unknown as DataUnitId,
    ref,
  })),
});

export interface SqliteStorageOptions {
  /** Milliseconds to wait for another process's write lock (default 5000). */
  readonly busyTimeoutMs?: number;
}

export class SqliteLfcpStorage implements LfcpStorage {
  readonly #db: Database.Database;
  /** The schema version after migration. */
  readonly schemaVersion: number;

  private constructor(db: Database.Database, version: number) {
    this.#db = db;
    this.schemaVersion = version;
  }

  /**
   * Opens (creating if needed) the database at `path`, migrates it to the
   * current schema and sets the durability pragmas.
   */
  static open(path: string, options: SqliteStorageOptions = {}): SqliteLfcpStorage {
    const db = new Database(path);
    try {
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.pragma(`busy_timeout = ${Math.trunc(options.busyTimeoutMs ?? 5000)}`);
      const version = migrate(db);
      return new SqliteLfcpStorage(db, version);
    } catch (e) {
      db.close();
      throw e;
    }
  }

  close(): void {
    if (this.#db.open) this.#db.close();
  }

  #all(sql: string, ...params: unknown[]): Row[] {
    return this.#db.prepare(sql).all(...params) as Row[];
  }

  #get(sql: string, ...params: unknown[]): Row | undefined {
    return this.#db.prepare(sql).get(...params) as Row | undefined;
  }

  /** Runs `fn` synchronously in one BEGIN IMMEDIATE transaction and settles with its result. */
  #tx<T>(fn: () => T): Promise<T> {
    try {
      return Promise.resolve(this.#db.transaction(fn).immediate());
    } catch (e) {
      return Promise.reject(e);
    }
  }

  #read<T>(fn: () => T): Promise<T> {
    try {
      return Promise.resolve(fn());
    } catch (e) {
      return Promise.reject(e);
    }
  }

  commit(writes: readonly StorageWrite[]): Promise<CommitResult> {
    return this.#tx((): CommitResult => {
      for (const w of writes) {
        if (w.op !== "set-control-head") continue;
        const row = this.#get(
          "SELECT head FROM control_heads WHERE resource_id = ?",
          blob(w.resourceId),
        );
        const current = row === undefined ? null : bytes(row.head);
        const matches =
          current === null
            ? w.expected === null
            : w.expected !== null && bytesEqual(current, w.expected);
        if (!matches)
          return Object.freeze({
            ok: false,
            reason: "CONTROL_HEAD_MISMATCH",
            resourceId: Uint8Array.from(w.resourceId) as ResourceId,
            current: current as ControlRecordId | null,
          });
      }
      for (const w of writes) this.#apply(w);
      return Object.freeze({ ok: true });
    });
  }

  /** Inserts an immutable object; the same ID with other bytes throws (rolling the batch back). */
  #immutable(table: string, idColumn: string, id: Uint8Array, row: Row, what: string): void {
    const columns = Object.keys(row);
    const result = this.#db
      .prepare(
        `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")}) ON CONFLICT (${idColumn}) DO NOTHING`,
      )
      .run(...Object.values(row));
    if (result.changes === 0) {
      const old = this.#get(`SELECT bytes FROM ${table} WHERE ${idColumn} = ?`, blob(id));
      if (old === undefined || !bytesEqual(bytes(old.bytes), row.bytes as Uint8Array))
        refused(what, id);
    }
  }

  #apply(w: StorageWrite): void {
    const db = this.#db;
    switch (w.op) {
      case "put-control-records":
        for (const r of w.records)
          this.#immutable(
            "control_records",
            "record_id",
            r.recordId,
            {
              record_id: blob(r.recordId),
              resource_id: blob(r.resourceId),
              control_seq: u64(r.controlSeq),
              prev_id: r.prevControlId === null ? null : blob(r.prevControlId),
              bytes: blob(r.bytes),
            },
            "Control Record",
          );
        return;
      case "set-control-head":
        db.prepare(
          "INSERT INTO control_heads (resource_id, head, control_seq) VALUES (?, ?, ?) ON CONFLICT (resource_id) DO UPDATE SET head = excluded.head, control_seq = excluded.control_seq",
        ).run(blob(w.resourceId), blob(w.head.head), u64(w.head.controlSeq));
        return;
      case "set-control-conflict":
        if (w.conflict === null)
          db.prepare("DELETE FROM control_conflicts WHERE resource_id = ?").run(blob(w.resourceId));
        else
          db.prepare(
            "INSERT INTO control_conflicts (resource_id, heads) VALUES (?, ?) ON CONFLICT (resource_id) DO UPDATE SET heads = excluded.heads",
          ).run(blob(w.resourceId), joinIds(w.conflict.heads));
        return;
      case "put-epoch": {
        const e = w.epoch;
        db.prepare(
          `INSERT INTO epochs (resource_id, epoch, dek_commitment, opened_by, closed_by, dek_ref) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (resource_id, epoch) DO UPDATE SET dek_commitment = excluded.dek_commitment, opened_by = excluded.opened_by, closed_by = excluded.closed_by, dek_ref = excluded.dek_ref`,
        ).run(
          blob(w.resourceId),
          u64(BigInt(e.epoch)),
          blob(e.dekCommitment),
          blob(e.openedBy),
          e.closedBy === null ? null : blob(e.closedBy),
          e.dekRef,
        );
        return;
      }
      case "put-data-unit": {
        const u = w.unit;
        const old = this.#get(
          "SELECT bytes, accepted FROM data_units WHERE unit_id = ?",
          blob(u.unitId),
        );
        if (old === undefined) {
          this.#insertUnit(u, w.status, w.detail ?? null, w.accepted ?? false);
        } else {
          if (!bytesEqual(bytes(old.bytes), u.bytes)) refused("Data Unit", u.unitId);
          const accepted = w.accepted ?? old.accepted === 1;
          db.prepare(
            "UPDATE data_units SET status = ?, detail = ?, accepted = ? WHERE unit_id = ?",
          ).run(w.status, w.detail ?? null, accepted ? 1 : 0, blob(u.unitId));
        }
        return;
      }
      case "set-data-unit-status":
        this.#mustChange(
          db
            .prepare("UPDATE data_units SET status = ?, detail = ? WHERE unit_id = ?")
            .run(w.status, w.detail ?? null, blob(w.unitId)).changes,
          w.unitId,
        );
        return;
      case "set-accepted":
        this.#mustChange(
          db
            .prepare("UPDATE data_units SET accepted = ? WHERE unit_id = ?")
            .run(w.accepted ? 1 : 0, blob(w.unitId)).changes,
          w.unitId,
        );
        return;
      case "put-key-package": {
        const k = w.row;
        this.#immutable(
          "key_packages",
          "package_id",
          k.packageId,
          {
            package_id: blob(k.packageId),
            resource_id: blob(k.resourceId),
            data_epoch: u64(BigInt(k.dataEpoch)),
            recipient: blob(k.recipient),
            sender: blob(k.sender),
            bytes: blob(k.bytes),
          },
          "Key Package",
        );
        return;
      }
      case "put-snapshot": {
        const s = w.row;
        this.#immutable(
          "snapshots",
          "snapshot_id",
          s.snapshotId,
          {
            snapshot_id: blob(s.snapshotId),
            resource_id: blob(s.resourceId),
            data_epoch: u64(BigInt(s.dataEpoch)),
            publisher: blob(s.publisher),
            snapshot_seq: u64(s.snapshotSeq),
            frontier: blob(s.frontier),
            bytes: blob(s.bytes),
          },
          "Snapshot",
        );
        return;
      }
      case "put-resource": {
        const r = w.row;
        db.prepare(
          `INSERT INTO resources (resource_id, data_profile, local_principal, signing_ref, agreement_ref, labels) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (resource_id) DO UPDATE SET data_profile = excluded.data_profile, local_principal = excluded.local_principal, signing_ref = excluded.signing_ref, agreement_ref = excluded.agreement_ref, labels = excluded.labels`,
        ).run(
          blob(r.resourceId),
          r.dataProfile,
          r.localPrincipal === null ? null : blob(r.localPrincipal.principalId),
          r.localPrincipal?.signingKeyRef ?? null,
          r.localPrincipal?.agreementKeyRef ?? null,
          JSON.stringify(r.labels),
        );
        return;
      }
      case "put-route": {
        const r = w.route;
        const endpoints: StoredEndpoint[] = r.endpoints.map((e) => ({
          url: e.url,
          priority: e.priority.toString(),
          ...(e.flags === undefined ? {} : { flags: e.flags.toString() }),
        }));
        db.prepare(
          `INSERT INTO routes (resource_id, route_version, endpoints, coordinator_url, source) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (resource_id) DO UPDATE SET route_version = excluded.route_version, endpoints = excluded.endpoints, coordinator_url = excluded.coordinator_url, source = excluded.source`,
        ).run(
          blob(w.resourceId),
          u64(r.routeVersion),
          JSON.stringify(endpoints),
          r.coordinatorUrl,
          blob(r.source),
        );
        return;
      }
      case "enqueue": {
        const o = w.item;
        const old = this.#get("SELECT bytes FROM outbound WHERE item_id = ?", blob(o.itemId));
        if (old !== undefined) {
          if (!bytesEqual(bytes(old.bytes), o.bytes)) refused("outbound item", o.itemId);
          return;
        }
        db.prepare(
          "INSERT INTO outbound (item_id, resource_id, kind, bytes, attempts, last_attempt) VALUES (?, ?, ?, ?, ?, ?)",
        ).run(blob(o.itemId), blob(o.resourceId), o.kind, blob(o.bytes), o.attempts, o.lastAttempt);
        return;
      }
      case "record-attempt":
        if (
          db
            .prepare("UPDATE outbound SET attempts = ?, last_attempt = ? WHERE item_id = ?")
            .run(w.attempts, w.lastAttempt, blob(w.itemId)).changes === 0
        )
          throw new LfcpError("INVALID_STRUCTURE", `no outbound item ${toHex(w.itemId)}`);
        return;
      case "dequeue":
        db.prepare("DELETE FROM outbound WHERE item_id = ?").run(blob(w.itemId));
        return;
      case "put-profile-checkpoint": {
        const c = w.checkpoint;
        db.prepare(
          `INSERT INTO profile_checkpoints (resource_id, data_profile, state, actor_seq, units) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (resource_id) DO UPDATE SET data_profile = excluded.data_profile, state = excluded.state, actor_seq = excluded.actor_seq, units = excluded.units`,
        ).run(
          blob(c.resourceId),
          c.dataProfile,
          blob(c.state),
          c.actorSeq,
          JSON.stringify(c.units.map((u) => [toHex(u.unitId), u.ref])),
        );
        return;
      }
    }
  }

  #mustChange(changes: number, unitId: DataUnitId): void {
    if (changes === 0) throw new LfcpError("INVALID_STRUCTURE", `no Data Unit ${toHex(unitId)}`);
  }

  #insertUnit(
    u: DataUnitRow,
    status: DataUnitStatus,
    detail: string | null,
    accepted: boolean,
  ): void {
    this.#db
      .prepare(
        `INSERT INTO data_units (unit_id, resource_id, data_epoch, actor, actor_seq, prev_id, control_head, bytes, status, detail, accepted)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        blob(u.unitId),
        blob(u.resourceId),
        u64(BigInt(u.dataEpoch)),
        blob(u.actor),
        u64(BigInt(u.actorSeq)),
        u.prevDataUnitId === null ? null : blob(u.prevDataUnitId),
        blob(u.controlHead),
        blob(u.bytes),
        status,
        detail,
        accepted ? 1 : 0,
      );
  }

  readonly control: ControlReader = {
    record: (id) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM control_records WHERE record_id = ?", blob(id));
        return r === undefined ? undefined : controlRecord(r);
      }),
    records: (res) =>
      this.#read(() =>
        this.#all(
          "SELECT * FROM control_records WHERE resource_id = ? ORDER BY control_seq, record_id",
          blob(res),
        ).map(controlRecord),
      ),
    head: (res) =>
      this.#read((): ControlHeadRow | undefined => {
        const r = this.#get(
          "SELECT head, control_seq FROM control_heads WHERE resource_id = ?",
          blob(res),
        );
        return r === undefined
          ? undefined
          : { head: as<ControlRecordId>(r.head), controlSeq: fromU64(r.control_seq) };
      }),
    conflict: (res) =>
      this.#read((): ControlConflictRow | undefined => {
        const r = this.#get("SELECT heads FROM control_conflicts WHERE resource_id = ?", blob(res));
        return r === undefined ? undefined : { heads: splitIds<ControlRecordId>(r.heads) };
      }),
    epochs: (res) =>
      this.#read(() =>
        this.#all("SELECT * FROM epochs WHERE resource_id = ? ORDER BY epoch", blob(res)).map(
          epochRow,
        ),
      ),
  };

  #at(res: ResourceId, actor: PrincipalId, seq: ActorSequence): StoredDataUnit[] {
    return this.#all(
      "SELECT * FROM data_units WHERE resource_id = ? AND actor = ? AND actor_seq = ? ORDER BY unit_id",
      blob(res),
      blob(actor),
      u64(BigInt(seq)),
    ).map(storedUnit);
  }

  readonly dataUnits: DataUnitReader = {
    get: (id) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM data_units WHERE unit_id = ?", blob(id));
        return r === undefined ? undefined : storedUnit(r);
      }),
    at: (res, actor, seq) => this.#read(() => this.#at(res, actor, seq)),
    range: (res, actor, from, to) =>
      this.#read(() =>
        this.#all(
          "SELECT * FROM data_units WHERE resource_id = ? AND actor = ? AND actor_seq BETWEEN ? AND ? ORDER BY actor_seq, unit_id",
          blob(res),
          blob(actor),
          u64(BigInt(from)),
          u64(BigInt(to)),
        ).map(storedUnit),
      ),
    withStatus: (res, status) =>
      this.#read(() =>
        this.#all(
          "SELECT * FROM data_units WHERE resource_id = ? AND status = ? ORDER BY actor, actor_seq, unit_id",
          blob(res),
          status,
        ).map(storedUnit),
      ),
    acceptedAt: (res, actor, seq) =>
      this.#read(() => this.#at(res, actor, seq).find((u) => u.accepted)?.unitId),
    recordSeen: (unit) =>
      this.#tx((): SeenRecord => {
        const old = this.#get("SELECT bytes FROM data_units WHERE unit_id = ?", blob(unit.unitId));
        if (old !== undefined && !bytesEqual(bytes(old.bytes), unit.bytes))
          refused("Data Unit", unit.unitId);
        if (old === undefined) this.#insertUnit(unit, "seen", null, false);
        const unitIds = this.#at(unit.resourceId, unit.actor, unit.actorSeq).map((u) => u.unitId);
        return Object.freeze({ unitIds: Object.freeze(unitIds), firstSeen: old === undefined });
      }),
  };

  readonly keyPackages: KeyPackageReader = {
    get: (id) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM key_packages WHERE package_id = ?", blob(id));
        return r === undefined ? undefined : keyPackage(r);
      }),
    list: (res, filter = {}) =>
      this.#read(() => {
        const where = ["resource_id = ?"];
        const params: unknown[] = [blob(res)];
        if (filter.epoch !== undefined) {
          where.push("data_epoch = ?");
          params.push(u64(BigInt(filter.epoch)));
        }
        if (filter.recipient !== undefined) {
          where.push("recipient = ?");
          params.push(blob(filter.recipient));
        }
        return this.#all(
          `SELECT * FROM key_packages WHERE ${where.join(" AND ")} ORDER BY data_epoch, package_id`,
          ...params,
        ).map(keyPackage);
      }),
  };

  readonly snapshots: SnapshotReader = {
    get: (id) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM snapshots WHERE snapshot_id = ?", blob(id));
        return r === undefined ? undefined : snapshot(r);
      }),
    list: (res, filter = {}) =>
      this.#read(() =>
        filter.epoch === undefined
          ? this.#all(
              "SELECT * FROM snapshots WHERE resource_id = ? ORDER BY data_epoch, publisher, snapshot_seq",
              blob(res),
            ).map(snapshot)
          : this.#all(
              "SELECT * FROM snapshots WHERE resource_id = ? AND data_epoch = ? ORDER BY data_epoch, publisher, snapshot_seq",
              blob(res),
              u64(BigInt(filter.epoch)),
            ).map(snapshot),
      ),
  };

  readonly resources: ResourceReader = {
    get: (res) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM resources WHERE resource_id = ?", blob(res));
        return r === undefined ? undefined : resource(r);
      }),
    list: () =>
      this.#read(() => this.#all("SELECT * FROM resources ORDER BY resource_id").map(resource)),
    route: (res) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM routes WHERE resource_id = ?", blob(res));
        return r === undefined ? undefined : route(r);
      }),
  };

  readonly outbound: OutboundReader = {
    list: (res) =>
      this.#read(() =>
        (res === undefined
          ? this.#all("SELECT * FROM outbound ORDER BY position")
          : this.#all("SELECT * FROM outbound WHERE resource_id = ? ORDER BY position", blob(res))
        ).map(outboundItem),
      ),
    get: (id) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM outbound WHERE item_id = ?", blob(id));
        return r === undefined ? undefined : outboundItem(r);
      }),
  };

  readonly profileState: ProfileStateReader = {
    checkpoint: (res) =>
      this.#read(() => {
        const r = this.#get("SELECT * FROM profile_checkpoints WHERE resource_id = ?", blob(res));
        return r === undefined ? undefined : checkpointRow(r);
      }),
  };

  /** Durable before it resolves: the new value is committed (WAL, synchronous=FULL) first. */
  readonly actorSequences: ActorSequenceReservation = {
    reserveNext: (res, principal) =>
      this.#tx(() => {
        const key = [blob(res), blob(principal)];
        const row = this.#get(
          "SELECT last FROM actor_sequences WHERE resource_id = ? AND principal = ?",
          ...key,
        );
        const next = nextActorSequence(
          row === undefined ? undefined : actorSequence(fromU64(row.last)),
        );
        this.#db
          .prepare(
            "INSERT INTO actor_sequences (resource_id, principal, last) VALUES (?, ?, ?) ON CONFLICT (resource_id, principal) DO UPDATE SET last = excluded.last",
          )
          .run(...key, u64(next));
        return next;
      }),
  };

  readonly snapshotSequences: SnapshotSequenceReservation = {
    reserveNext: (res: ResourceId, epoch: DataEpoch, publisher: PrincipalId) =>
      this.#tx(() => {
        const key = [blob(res), u64(BigInt(epoch)), blob(publisher)];
        const row = this.#get(
          "SELECT last FROM snapshot_sequences WHERE resource_id = ? AND epoch = ? AND publisher = ?",
          ...key,
        );
        const last = row === undefined ? 0n : fromU64(row.last);
        if (last >= UINT64_MAX)
          throw new LfcpError("OUT_OF_RANGE", "the Snapshot Sequence space is exhausted (§29)");
        this.#db
          .prepare(
            "INSERT INTO snapshot_sequences (resource_id, epoch, publisher, last) VALUES (?, ?, ?, ?) ON CONFLICT (resource_id, epoch, publisher) DO UPDATE SET last = excluded.last",
          )
          .run(...key, u64(last + 1n));
        return last + 1n;
      }),
  };
}
