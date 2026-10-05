import {
  type ActorSequence,
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  hash32,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { importResourceDEK, type ResourceDEK } from "@openlfcp/crypto";
import type {
  CommitResult,
  DataUnitRow,
  EpochRow,
  LfcpStorage,
  SecretStore,
  StorageWrite,
} from "@openlfcp/storage";
import {
  type ChainResult,
  parseDataUnit,
  type SeenRecord,
  type SeenUnits,
  validateControlChain,
} from "@openlfcp/wire";
import { type CreateDataUnitOptions, type CreatedDataUnit, createDataUnit } from "./data-unit.js";

/**
 * The client code on top of the storage interfaces (LFCP-034), so that a
 * durable adapter (LFCP-035) is all a platform has to write.
 */

/** A Data Unit's storage row: its exact bytes and header indexes. Throws for bytes that do not parse. */
export function dataUnitRow(bytes: Uint8Array): DataUnitRow {
  const parsed = parseDataUnit(bytes);
  const p = parsed.payload;
  return {
    unitId: parsed.signed.id as unknown as DataUnitId,
    resourceId: p.resourceId,
    dataEpoch: p.dataEpoch,
    actor: p.actor,
    actorSeq: p.actorSeq,
    prevDataUnitId: p.prevDataUnitId,
    controlHead: p.controlHead,
    bytes: parsed.signed.bytes,
  };
}

/**
 * The wire SeenUnits over LfcpStorage, durable and with un-accept
 * (set-accepted false). A unit is stored only once its signature verifies:
 * the receiver announces the row with expect() before verification, and
 * recordSignatureValid stores it.
 */
export class StoredSeenUnits implements SeenUnits {
  readonly #storage: Pick<LfcpStorage, "dataUnits" | "commit">;
  readonly #expected = new Map<string, DataUnitRow>();

  constructor(storage: Pick<LfcpStorage, "dataUnits" | "commit">) {
    this.#storage = storage;
  }

  /** The row of a unit about to be verified (kept in memory until it is). */
  expect(row: DataUnitRow): void {
    this.#expected.set(toHex(row.unitId), row);
  }

  async recordSignatureValid(
    _resource: ResourceId,
    _actor: PrincipalId,
    _seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<SeenRecord> {
    const key = toHex(unitId);
    const row = this.#expected.get(key) ?? (await this.#storage.dataUnits.get(unitId));
    if (row === undefined)
      throw new Error(`StoredSeenUnits: no row for unit ${key}; call expect() first`);
    this.#expected.delete(key);
    return this.#storage.dataUnits.recordSeen(row);
  }

  acceptedAt(
    resource: ResourceId,
    actor: PrincipalId,
    seq: ActorSequence,
  ): Promise<DataUnitId | undefined> {
    return this.#storage.dataUnits.acceptedAt(resource, actor, seq);
  }

  async acceptedIn(
    resource: ResourceId,
    actor: PrincipalId,
    from: ActorSequence,
    to: ActorSequence,
  ): Promise<readonly { readonly seq: ActorSequence; readonly unitId: DataUnitId }[]> {
    return (await this.#storage.dataUnits.range(resource, actor, from, to))
      .filter((u) => u.accepted)
      .map((u) => ({ seq: u.actorSeq, unitId: u.unitId }));
  }

  async markAccepted(
    _resource: ResourceId,
    _actor: PrincipalId,
    _seq: ActorSequence,
    unitId: DataUnitId,
  ): Promise<void> {
    const r = await this.#storage.commit([{ op: "set-accepted", unitId, accepted: true }]);
    if (!r.ok) throw new Error("set-accepted has no precondition");
  }
}

/**
 * The stored Control Chain of `resource`, validated: the records from the
 * stored head back to Genesis. Undefined when nothing is stored.
 */
export async function loadControlChain(
  storage: Pick<LfcpStorage, "control">,
  resource: ResourceId,
): Promise<ChainResult | undefined> {
  const head = await storage.control.head(resource);
  if (head === undefined) return undefined;
  const byId = new Map(
    (await storage.control.records(resource)).map((r) => [toHex(r.recordId), r]),
  );
  const chain: Uint8Array[] = [];
  for (let at: ControlRecordId | null = head.head; at !== null; ) {
    const r = byId.get(toHex(at));
    if (r === undefined)
      throw new LfcpError(
        "INVALID_CONTROL_CHAIN",
        `stored Control Record ${toHex(at)} is missing (local corruption)`,
      );
    chain.unshift(r.bytes);
    at = r.prevControlId;
  }
  const result = validateControlChain(chain);
  // Fail closed on local corruption: the records must validate to exactly the
  // stored head and sequence; an older or different state is never used silently.
  if (
    result.kind === "linear" &&
    (!bytesEqual(result.state.head, head.head) || result.state.seq !== head.controlSeq)
  )
    throw new LfcpError(
      "INVALID_CONTROL_CHAIN",
      `the stored Control Records validate to sequence ${result.state.seq}, not the stored head at ${head.controlSeq} (local corruption)`,
    );
  return result;
}

/**
 * Persists a validated linear chain in one atomic batch: its exact records,
 * the head (compare-and-set against `expected`), the epoch history (keeping
 * known DEK references), the route, and no conflict. A head that moved
 * meanwhile writes nothing and returns CONTROL_HEAD_MISMATCH.
 */
export async function saveControlChain(
  storage: Pick<LfcpStorage, "control" | "commit">,
  chain: Extract<ChainResult, { kind: "linear" }>,
  expected: ControlRecordId | null,
): Promise<CommitResult> {
  const s = chain.state;
  const known = new Map(
    (await storage.control.epochs(s.resourceId)).map((e) => [String(e.epoch), e]),
  );
  const epochs: StorageWrite[] = [...s.epochs.values()].map((e) => ({
    op: "put-epoch",
    resourceId: s.resourceId,
    epoch: {
      epoch: e.epoch,
      dekCommitment: e.dekCommitment,
      openedBy: e.openedBy,
      closedBy: e.closedBy,
      dekRef: known.get(String(e.epoch))?.dekRef ?? null,
    } satisfies EpochRow,
  }));
  return storage.commit([
    {
      op: "put-control-records",
      records: chain.records.map((r) => ({
        recordId: r.signed.id as unknown as ControlRecordId,
        resourceId: r.payload.resourceId,
        controlSeq: r.payload.controlSeq,
        prevControlId: r.payload.prevControlId,
        bytes: r.signed.bytes,
      })),
    },
    {
      op: "set-control-head",
      resourceId: s.resourceId,
      expected,
      head: { head: s.head, controlSeq: s.seq },
    },
    ...epochs,
    {
      op: "put-route",
      resourceId: s.resourceId,
      route: {
        routeVersion: s.routeVersion,
        endpoints: s.route.endpoints.map((e) => ({
          url: e.url,
          priority: e.priority,
          ...(e.flags === undefined ? {} : { flags: e.flags }),
        })),
        coordinatorUrl: s.route.coordinatorUrl,
        source: s.head,
      },
    },
    { op: "set-control-conflict", resourceId: s.resourceId, conflict: null },
  ]);
}

/** Records a Control Chain fork (CONTROL_CONFLICT): its competing heads, sorted by bytes. */
export async function saveControlConflict(
  storage: Pick<LfcpStorage, "commit">,
  resource: ResourceId,
  conflict: Extract<ChainResult, { kind: "conflict" }>,
): Promise<CommitResult> {
  return storage.commit([
    { op: "set-control-conflict", resourceId: resource, conflict: { heads: conflict.competing } },
  ]);
}

/**
 * The DEK lookup for a receiver or writer: the epoch's stored DEK reference,
 * resolved in the SecretStore. Undefined when this client has no DEK for it.
 */
export function dekResolver(
  storage: Pick<LfcpStorage, "control">,
  secrets: SecretStore,
  resource: ResourceId,
): (epoch: DataEpoch) => Promise<ResourceDEK | undefined> {
  return async (epoch) => {
    const row = (await storage.control.epochs(resource)).find((e) => e.epoch === epoch);
    if (row?.dekRef == null) return undefined;
    const bytes = await secrets.get(row.dekRef);
    return bytes === undefined ? undefined : importResourceDEK(bytes);
  };
}

/**
 * Creates this client's Data Unit with a sequence from the storage's
 * reservation, then commits in one batch: the exact unit (merged and
 * accepted: it is this client's own history), its outbound entry, and any
 * `also` writes (e.g. the profile checkpoint containing the change). A
 * crash before the commit leaves only an abandoned sequence, never a
 * reused one; a retry sends the queued bytes, never a re-created unit.
 */
export async function createQueuedDataUnit<T>(
  storage: Pick<LfcpStorage, "actorSequences" | "commit">,
  options: Omit<CreateDataUnitOptions<T>, "sequences"> & {
    /**
     * Called once the unit is sealed, before the commit: e.g. the Data
     * Profile records which change the unit carries (recordLocal), so that
     * a function `also` can put the updated checkpoint in the same batch.
     */
    readonly onCreated?: (created: CreatedDataUnit, value: T) => void;
  },
  also: readonly StorageWrite[] | ((created: CreatedDataUnit) => readonly StorageWrite[]) = [],
): Promise<CreatedDataUnit> {
  const { onCreated, ...create } = options;
  const created = await createDataUnit({ ...create, sequences: storage.actorSequences });
  onCreated?.(created, options.value);
  const extra = typeof also === "function" ? also(created) : also;
  const row = dataUnitRow(created.bytes);
  const result = await storage.commit([
    { op: "put-data-unit", unit: row, status: "merged", detail: "local", accepted: true },
    {
      op: "enqueue",
      item: {
        itemId: hash32(created.unitId),
        resourceId: row.resourceId,
        kind: "data-unit",
        bytes: created.bytes,
        attempts: 0,
        lastAttempt: null,
        nextAttempt: null,
        blocked: null,
      },
    },
    ...extra,
  ]);
  if (!result.ok) throw new Error(`the local unit was not stored: ${result.reason}`);
  return created;
}
