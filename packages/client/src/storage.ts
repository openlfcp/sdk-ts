import {
  type ActorSequence,
  actorSequence,
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
import { dekCommitment, importResourceDEK, type ResourceDEK } from "@openlfcp/crypto";
import {
  type CommitResult,
  type DataUnitRow,
  dekSecretRef,
  type EpochRow,
  type LfcpStorage,
  type SecretStore,
  type StorageWrite,
} from "@openlfcp/storage";
import {
  type ChainResult,
  parseDataUnit,
  type SeenRecord,
  type SeenUnits,
  validateControlChain,
} from "@openlfcp/wire";
import { receiptIndexWrites } from "./batch-status.js";
import { type CreateDataUnitOptions, type CreatedDataUnit, createDataUnit } from "./data-unit.js";
import {
  intentsHash,
  OperationIdReusedError,
  type Receipt,
  receiptOf,
  receiptWrite,
} from "./receipts.js";

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
 * Epoch rows of `chain` with no DEK reference take a DEK this client
 * already holds under the epoch's standard reference (dekSecretRef): one
 * it created (queueKeyEpoch), or one a Key Package delivered before the
 * row was stored. A DEK is adopted only if it matches the epoch's
 * commitment in the validated chain. Returns the adopted epochs. Called
 * whenever a chain is saved, so the row and its key meet without waiting
 * for another Key Package request.
 */
export async function adoptStoredDeks(
  storage: Pick<LfcpStorage, "control" | "commit">,
  secrets: SecretStore,
  chain: Extract<ChainResult, { kind: "linear" }>,
): Promise<DataEpoch[]> {
  const R = chain.state.resourceId;
  const writes: StorageWrite[] = [];
  const adopted: DataEpoch[] = [];
  for (const row of await storage.control.epochs(R)) {
    if (row.dekRef !== null) continue;
    const epoch = chain.state.epochs.get(String(row.epoch));
    if (epoch === undefined) continue;
    const ref = dekSecretRef(R, row.epoch);
    const bytes = await secrets.get(ref);
    if (bytes === undefined) continue;
    const matches = bytesEqual(
      dekCommitment(R, row.epoch, importResourceDEK(bytes)),
      epoch.dekCommitment,
    );
    bytes.fill(0);
    if (!matches) continue;
    // put-epoch merges inside the commit: a concurrent close is kept.
    writes.push({ op: "put-epoch", resourceId: R, epoch: { ...row, dekRef: ref } });
    adopted.push(row.epoch);
  }
  if (writes.length > 0) {
    const r = await storage.commit(writes);
    if (!r.ok) throw new Error(`the DEK references were not stored: ${r.reason}`);
  }
  return adopted;
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
/**
 * §26.2 (G-DP1-GAP): the unit a writer's next unit names as `previous`:
 * its latest own unit it still holds as accepted, or null before its
 * first. Local units are stored accepted in the commit that queues them,
 * so this is its last published unit, except one it has itself seen
 * excluded by a cutoff (G-EP7) or as equivocation (G-DP5): no receiver
 * accepts those either, so the next unit (e.g. stale work re-applied,
 * G-EP5) names the unit before them and links. After an abandoned
 * sequence N the next unit names N - 1. Read from storage, so a restart
 * chooses the same unit.
 */
export async function latestAcceptedOwnUnit(
  storage: Pick<LfcpStorage, "dataUnits">,
  resource: ResourceId,
  actor: PrincipalId,
): Promise<DataUnitId | null> {
  const mine = await storage.dataUnits.range(
    resource,
    actor,
    actorSequence(1n),
    actorSequence(2n ** 64n - 1n),
  );
  return mine.filter((u) => u.accepted).at(-1)?.unitId ?? null;
}

/**
 * Local units of one (storage, Resource, actor) are created one at a time
 * in this process: each must name the previous one (§26.2). Across
 * processes sharing a store, the commit's expect-previous-unit refuses a
 * unit whose previous was superseded meanwhile.
 */
const localWriters = new WeakMap<object, Map<string, Promise<unknown>>>();

function serialized<R>(storage: object, key: string, run: () => Promise<R>): Promise<R> {
  let tails = localWriters.get(storage);
  if (tails === undefined) {
    tails = new Map();
    localWriters.set(storage, tails);
  }
  const done = (tails.get(key) ?? Promise.resolve()).then(run, run);
  const tail = done.then(
    () => undefined,
    () => undefined,
  );
  tails.set(key, tail);
  void tail.then(() => {
    if (tails.get(key) === tail) tails.delete(key);
  });
  return done;
}

export async function createQueuedDataUnit<T>(
  storage: Pick<LfcpStorage, "actorSequences" | "commit" | "dataUnits">,
  options: Omit<CreateDataUnitOptions<T>, "sequences" | "previousUnitId"> & {
    /** The previous unit (§26.2); default the writer's latest own unit still accepted (latestAcceptedOwnUnit). */
    readonly previousUnitId?: DataUnitId | null;
    /**
     * Called once the unit is sealed, before the commit: e.g. the Data
     * Profile records which change the unit carries (recordLocal), so that
     * a function `also` can put the updated checkpoint in the same batch.
     */
    readonly onCreated?: (created: CreatedDataUnit, value: T) => void;
  },
  also: readonly StorageWrite[] | ((created: CreatedDataUnit) => readonly StorageWrite[]) = [],
): Promise<CreatedDataUnit> {
  const resource = options.view.state.resourceId;
  const actor = options.actor.descriptor.principalId;
  return serialized(storage, `${toHex(resource)}:${toHex(actor)}`, () =>
    createQueuedDataUnitNow(storage, options, also, resource, actor),
  );
}

async function createQueuedDataUnitNow<T>(
  storage: Pick<LfcpStorage, "actorSequences" | "commit" | "dataUnits">,
  options: Parameters<typeof createQueuedDataUnit<T>>[1],
  also: readonly StorageWrite[] | ((created: CreatedDataUnit) => readonly StorageWrite[]),
  resource: ResourceId,
  actor: PrincipalId,
): Promise<CreatedDataUnit> {
  const { onCreated, previousUnitId, ...create } = options;
  const previous =
    previousUnitId !== undefined
      ? previousUnitId
      : await latestAcceptedOwnUnit(storage, resource, actor);
  const created = await createDataUnit({
    ...create,
    previousUnitId: previous,
    sequences: storage.actorSequences,
  });
  onCreated?.(created, options.value);
  const extra = typeof also === "function" ? also(created) : also;
  const row = dataUnitRow(created.bytes);
  const result = await storage.commit([
    // Unless the caller named its own previous unit, it must still be the
    // latest when this unit is stored (another writer, e.g. another process).
    ...(previousUnitId !== undefined
      ? []
      : [{ op: "expect-previous-unit", resourceId: resource, actor, previous } as const]),
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

/**
 * SDK-SECTIONS-INTEGRATION-01 §3.1 (LFCP-02-025): commits one operation, a
 * batch of a profile's changes, as Data Units with their outbound entries,
 * the caller's writes (`also`: its profile checkpoint) and the receipt, in
 * ONE storage transaction: after a crash either all of it exists or none.
 * The units chain their previous units in order (§26.2).
 *
 * Idempotent per (Resource, operationId) (§3.3): an operation that already
 * has a receipt for the same intents returns it and writes nothing; for
 * different intents it throws OperationIdReusedError. The caller stages
 * its changes first and adopts them only once this resolves.
 */
export interface CommitOperationOptions<T>
  extends Omit<CreateDataUnitOptions<T>, "sequences" | "previousUnitId" | "value"> {
  readonly operationId: string;
  /** The batch's intents, as the caller submitted them (their canonical form is hashed, §3.3). */
  readonly intents: readonly unknown[];
  /** The batch's changes in order; each becomes one Data Unit. */
  readonly values: readonly T[];
  readonly affectedNodeIds: readonly string[];
  /** The document's heads after the batch, sorted, as one string. */
  readonly modelRevision: string;
  /** Called for each sealed unit before the commit (e.g. the profile's recordLocal). */
  readonly onCreated?: (created: CreatedDataUnit, value: T, index: number) => void;
}

export async function commitOperation<T>(
  storage: Pick<LfcpStorage, "actorSequences" | "commit" | "dataUnits" | "localMarks">,
  options: CommitOperationOptions<T>,
  also:
    | readonly StorageWrite[]
    | ((units: readonly CreatedDataUnit[]) => readonly StorageWrite[]) = [],
): Promise<{ readonly receipt: Receipt; readonly committed: boolean }> {
  const resource = options.view.state.resourceId;
  const actor = options.actor.descriptor.principalId;
  return serialized(storage, `${toHex(resource)}:${toHex(actor)}`, async () => {
    const hash = intentsHash(options.intents);
    const existing = await receiptOf(storage, resource, options.operationId);
    if (existing !== undefined) {
      if (existing.intentsHash !== hash) throw new OperationIdReusedError(options.operationId);
      return { receipt: existing, committed: false };
    }
    const { onCreated, operationId, intents, values, affectedNodeIds, modelRevision, ...create } =
      options;
    void intents;
    const first = await latestAcceptedOwnUnit(storage, resource, actor);
    const created: CreatedDataUnit[] = [];
    let previous = first;
    for (const [i, value] of values.entries()) {
      const unit = await createDataUnit({
        ...create,
        value,
        previousUnitId: previous,
        sequences: storage.actorSequences,
      });
      onCreated?.(unit, value, i);
      created.push(unit);
      previous = unit.unitId;
    }
    const receipt: Receipt = Object.freeze({
      operationId,
      unitIds: Object.freeze(created.map((u) => u.unitId)),
      affectedNodeIds: Object.freeze([...affectedNodeIds]),
      modelRevision,
      intentsHash: hash,
      durable: true,
    });
    const writes: StorageWrite[] = [
      { op: "expect-previous-unit", resourceId: resource, actor, previous: first },
    ];
    for (const unit of created) {
      const row = dataUnitRow(unit.bytes);
      writes.push(
        { op: "put-data-unit", unit: row, status: "merged", detail: "local", accepted: true },
        {
          op: "enqueue",
          item: {
            itemId: hash32(unit.unitId),
            resourceId: row.resourceId,
            kind: "data-unit",
            bytes: unit.bytes,
            attempts: 0,
            lastAttempt: null,
            nextAttempt: null,
            blocked: null,
          },
        },
      );
    }
    writes.push(
      receiptWrite(resource, receipt),
      ...receiptIndexWrites(resource, receipt),
      ...(typeof also === "function" ? also(created) : also),
    );
    const result = await storage.commit(writes);
    if (!result.ok) throw new Error(`the operation was not stored: ${result.reason}`);
    return { receipt, committed: true };
  });
}
