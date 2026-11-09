import {
  type DataEpoch,
  fromHex,
  type Hash32,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { exportSecretKeyBytes, importResourceDEK, type ResourceDEK } from "@openlfcp/crypto";
import { type LfcpStorage, type SecretStore, secretRef } from "@openlfcp/storage";
import type { PhaseState } from "./phases.js";

/**
 * The durable operation journal and the package ledger
 * (IDENTITY-PROFILE-01 §9.1, §9.5, §9.8).
 *
 * Pairing, accepting an invitation, creating a Resource, revocation with
 * rotation and reconciliation each commit several records and packages,
 * possibly on several Resources. Before any record or package is sent the
 * client persists the operation's intent and the exact signed bytes of the
 * next record; after each ACK it persists the committed record ID. A phase
 * is repeated only by re-sending the same exact bytes; after a
 * CONTROL_HEAD_MISMATCH or a restart it is classified against the accepted
 * chain (phases.ts) and rebuilt only when it is still `pending` on a new
 * head.
 *
 * Journal rows are local marks (`identity-op:<id>`) and hold no secrets
 * (§9.8): a bearer link, a pairing device's keys and a DEK go to the
 * SecretStore only, under the references below, before the row that names
 * them is written (LFCP-034 ordering).
 */

export type OperationKind =
  | "create-identity"
  | "pairing-session"
  | "pairing-approval"
  | "pairing-request"
  | "register-device"
  | "revoke-device"
  | "rotate"
  | "reconcile"
  | "accept-invitation"
  | "create-resource"
  | "add-to-roster";

/** The state of a whole operation. */
export type OperationStatus =
  /** Phases remain; resume it. */
  | "open"
  /** Every phase is committed or complete. */
  | "done"
  /** A phase was superseded: the operation ended without its effect (§9.2). */
  | "superseded"
  /** The human or the flow abandoned it (a cancelled session, a refused request). */
  | "abandoned";

/** A journaled phase. Byte strings are hex; every value is public. */
export interface JournalPhase {
  /** Unique within the operation, e.g. `consume`, `register:<resource hex>`. */
  readonly id: string;
  readonly kind:
    | "host"
    | "unit"
    | "consume"
    | "register"
    | "cancel"
    | "revoke"
    | "rotate"
    | "claim"
    | "document";
  /** The Resource the phase acts on (hex). */
  readonly resource: string;
  readonly state: PhaseState | "refused";
  /** The exact signed bytes of the record or unit to (re)send, persisted before sending. */
  readonly bytes?: string;
  /** The head those bytes were built on (their prev_control_id), for a Control Record. */
  readonly expectedHead?: string;
  /** Every record ID this installation built for the phase, in order (§9.2 committed-own). */
  readonly sent?: readonly string[];
  /** The committed record ID, after the ACK (or after classification found it). */
  readonly recordId?: string;
  /** The NACK code of a refused phase. */
  readonly code?: string;
  /** Phase-specific public facts (a digest, a revocation sequence, an epoch). */
  readonly facts?: Readonly<Record<string, string>>;
}

export interface JournalOperation {
  readonly v: 1;
  readonly id: string;
  readonly kind: OperationKind;
  readonly status: OperationStatus;
  /** Milliseconds since the epoch, from the caller's clock; display only. */
  readonly createdAt: number;
  /** The operation's intent: public facts only (§9.8). */
  readonly intent: Readonly<Record<string, unknown>>;
  readonly phases: readonly JournalPhase[];
}

const OP_PREFIX = "identity-op:";
const LEDGER_PREFIX = "identity-ledger:";

type JournalStorage = Pick<LfcpStorage, "localMarks" | "commit">;

const SECRETS_IN_JOURNAL = /secret|seed|private|dek/i;

function checkNoSecrets(value: unknown, path = "intent"): void {
  if (value === null || typeof value !== "object") return;
  for (const [k, v] of Object.entries(value)) {
    // §9.8: the journal never names a secret field; secrets go to the SecretStore.
    if (SECRETS_IN_JOURNAL.test(k) && k !== "dekRef")
      throw new Error(`a journal row must not hold secrets (${path}.${k}, §9.8)`);
    checkNoSecrets(v, `${path}.${k}`);
  }
}

/**
 * The journal's writes per storage, one at a time (0.5.2, review 418r2 R3):
 * every read-modify-write of an operation row runs under it, so two calls on
 * the same storage (a resumed rotation and abandonDelivery) never write a
 * row each read before the other wrote. Keyed by the storage object; every
 * OperationJournal over it shares the queue.
 */
const QUEUES = new WeakMap<object, Promise<unknown>>();

/** The durable operation journal (§9.1). */
export class OperationJournal {
  readonly #storage: JournalStorage;

  constructor(storage: JournalStorage) {
    this.#storage = storage;
  }

  /** Runs `work` alone among this storage's journal writes. */
  #locked<T>(work: () => Promise<T>): Promise<T> {
    const key = this.#storage as object;
    const before = QUEUES.get(key) ?? Promise.resolve();
    const next = before.then(work, work);
    QUEUES.set(
      key,
      next.catch(() => undefined),
    );
    return next;
  }

  async #put(op: JournalOperation): Promise<void> {
    checkNoSecrets(op.intent);
    const result = await this.#storage.commit([
      { op: "put-local-mark", key: `${OP_PREFIX}${op.id}`, value: JSON.stringify(op) },
    ]);
    if (!result.ok) throw new Error(`the operation journal was not stored: ${result.reason}`);
  }

  /** Persists a new operation before any of its records is sent. */
  async begin(
    op: Omit<JournalOperation, "v" | "status" | "phases"> & {
      readonly phases?: readonly JournalPhase[];
    },
  ): Promise<JournalOperation> {
    const row: JournalOperation = Object.freeze({
      v: 1,
      status: "open",
      phases: [],
      ...op,
    });
    return this.#locked(async () => {
      if ((await this.get(op.id)) !== undefined)
        throw new Error(`operation ${op.id} is already journaled`);
      await this.#put(row);
      return row;
    });
  }

  async get(id: string): Promise<JournalOperation | undefined> {
    const value = await this.#storage.localMarks.get(`${OP_PREFIX}${id}`);
    return value === undefined ? undefined : (JSON.parse(value) as JournalOperation);
  }

  /** Every journaled operation, optionally of one kind and status, oldest first. */
  async list(
    filter: { readonly kind?: OperationKind; readonly status?: OperationStatus } = {},
  ): Promise<readonly JournalOperation[]> {
    return (await this.#storage.localMarks.list(OP_PREFIX))
      .map((m) => JSON.parse(m.value) as JournalOperation)
      .filter(
        (o) =>
          (filter.kind === undefined || o.kind === filter.kind) &&
          (filter.status === undefined || o.status === filter.status),
      )
      .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
  }

  /** Writes the phase (replacing the one with its ID), durably. */
  putPhase(id: string, phase: JournalPhase): Promise<JournalOperation> {
    return this.updatePhase(id, phase.id, () => phase);
  }

  /**
   * Replaces the phase `phaseId` of operation `id` with `update(stored)`,
   * where `stored` is the phase as it is when the write happens, read and
   * written alone among this storage's journal writes (0.5.2). A fact
   * another call wrote meanwhile (an abandoned delivery) is seen by
   * `update`, never overwritten by a copy read before it.
   */
  updatePhase(
    id: string,
    phaseId: string,
    update: (stored: JournalPhase | undefined) => JournalPhase,
  ): Promise<JournalOperation> {
    return this.#locked(async () => {
      const op = await this.load(id);
      const phase = update(op.phases.find((p) => p.id === phaseId));
      const phases = op.phases.some((p) => p.id === phase.id)
        ? op.phases.map((p) => (p.id === phase.id ? phase : p))
        : [...op.phases, phase];
      const next = Object.freeze({ ...op, phases: Object.freeze(phases) });
      await this.#put(next);
      return next;
    });
  }

  /** Updates the intent with more public facts (e.g. the session's record IDs). */
  updateIntent(id: string, patch: Readonly<Record<string, unknown>>): Promise<JournalOperation> {
    return this.#locked(async () => {
      const op = await this.load(id);
      const next = Object.freeze({ ...op, intent: Object.freeze({ ...op.intent, ...patch }) });
      await this.#put(next);
      return next;
    });
  }

  setStatus(id: string, status: OperationStatus): Promise<JournalOperation> {
    return this.#locked(async () => {
      const op = await this.load(id);
      const next = Object.freeze({ ...op, status });
      await this.#put(next);
      return next;
    });
  }

  /** Removes a finished operation's row. */
  async remove(id: string): Promise<void> {
    await this.#storage.commit([{ op: "put-local-mark", key: `${OP_PREFIX}${id}`, value: null }]);
  }

  async load(id: string): Promise<JournalOperation> {
    const op = await this.get(id);
    if (op === undefined) throw new Error(`operation ${id} is not journaled`);
    return op;
  }
}

/** The phase `id` of `op`, if journaled. */
export const phaseOf = (op: JournalOperation, id: string): JournalPhase | undefined =>
  op.phases.find((p) => p.id === id);

/** One sent Key Package (§9.5). */
export interface LedgerEntry {
  readonly resource: ResourceId;
  readonly epoch: DataEpoch;
  readonly recipient: PrincipalId;
  readonly packageId: Hash32;
}

const pendingKey = (resource: ResourceId, epoch: DataEpoch, recipient: PrincipalId) =>
  `identity-package-pending:${toHex(resource)}:${epoch}:${toHex(recipient)}`;

const ledgerKey = (resource: ResourceId, epoch: DataEpoch, recipient: PrincipalId) =>
  `${LEDGER_PREFIX}${toHex(resource)}:${epoch}:${toHex(recipient)}`;

/**
 * The package ledger (§9.5): every Key Package this installation sent, as
 * `(resource, epoch, recipient, package ID)`. It drives reconciliation's
 * key step (§7.1 step 3); delivery is never inferred from the absence of a
 * complaint, and a cleared entry causes a re-send.
 */
export class PackageLedger {
  readonly #storage: JournalStorage;

  constructor(storage: JournalStorage) {
    this.#storage = storage;
  }

  /** Records an acknowledged package and drops its pending bytes, in one commit. */
  async record(entry: LedgerEntry): Promise<void> {
    const result = await this.#storage.commit([
      {
        op: "put-local-mark",
        key: ledgerKey(entry.resource, entry.epoch, entry.recipient),
        value: toHex(entry.packageId),
      },
      {
        op: "put-local-mark",
        key: pendingKey(entry.resource, entry.epoch, entry.recipient),
        value: null,
      },
    ]);
    if (!result.ok) throw new Error(`the package ledger was not stored: ${result.reason}`);
  }

  /** The exact bytes of a package sent but not yet acknowledged (§9.1). */
  async pending(
    resource: ResourceId,
    epoch: DataEpoch,
    recipient: PrincipalId,
  ): Promise<Uint8Array | undefined> {
    const v = await this.#storage.localMarks.get(pendingKey(resource, epoch, recipient));
    return v === undefined ? undefined : fromHex(v);
  }

  /** Persists a package's exact bytes before it is sent. */
  async putPending(
    resource: ResourceId,
    epoch: DataEpoch,
    recipient: PrincipalId,
    bytes: Uint8Array,
  ): Promise<void> {
    const result = await this.#storage.commit([
      { op: "put-local-mark", key: pendingKey(resource, epoch, recipient), value: toHex(bytes) },
    ]);
    if (!result.ok) throw new Error(`the pending package was not stored: ${result.reason}`);
  }

  async has(resource: ResourceId, epoch: DataEpoch, recipient: PrincipalId): Promise<boolean> {
    return (
      (await this.#storage.localMarks.get(ledgerKey(resource, epoch, recipient))) !== undefined
    );
  }

  /** Every entry for `resource`. */
  async list(resource: ResourceId): Promise<readonly LedgerEntry[]> {
    return (await this.#storage.localMarks.list(`${LEDGER_PREFIX}${toHex(resource)}:`)).map((m) => {
      const [, r, e, p] = m.key.split(":") as [string, string, string, string];
      return Object.freeze({
        resource: fromHex(r) as ResourceId,
        epoch: BigInt(e) as DataEpoch,
        recipient: fromHex(p) as PrincipalId,
        packageId: fromHex(m.value) as Hash32,
      });
    });
  }

  /**
   * "Re-send keys" (§7.1 step 3): forgets every package sent to
   * `recipient`, in `resource` or everywhere, so the next reconciliation
   * re-seals them.
   */
  async clear(recipient: PrincipalId, resource?: ResourceId): Promise<number> {
    const prefix = resource === undefined ? LEDGER_PREFIX : `${LEDGER_PREFIX}${toHex(resource)}:`;
    const suffix = `:${toHex(recipient)}`;
    const keys = (await this.#storage.localMarks.list(prefix))
      .map((m) => m.key)
      .filter((k) => k.endsWith(suffix));
    if (keys.length === 0) return 0;
    const result = await this.#storage.commit(
      keys.map((key) => ({ op: "put-local-mark" as const, key, value: null })),
    );
    if (!result.ok) throw new Error(`the package ledger was not updated: ${result.reason}`);
    return keys.length;
  }
}

/**
 * The SecretStore slot of a DEK generated for a KEY_EPOCH that is not
 * committed yet (§9.1: persisted before the record is sent). It is not the
 * epoch's DEK slot: until the record is accepted, another rotator may
 * commit that epoch number with another DEK.
 */
export const pendingDekRef = (resource: ResourceId, operation: string) =>
  secretRef("resource-dek", `${toHex(resource)}.pending.${operation}`);

/** The SecretStore slot of a pairing device's invite-secret (§5.2, §9.8). */
export const pairingSecretRef = (pairingDevice: PrincipalId) =>
  secretRef("invitation-secret", `pairing.${toHex(pairingDevice)}`);

export async function putPendingDek(
  secrets: SecretStore,
  resource: ResourceId,
  operation: string,
  dek: ResourceDEK,
): Promise<void> {
  const bytes = exportSecretKeyBytes(dek);
  try {
    await secrets.put(pendingDekRef(resource, operation), bytes);
  } finally {
    bytes.fill(0);
  }
}

export async function getPendingDek(
  secrets: SecretStore,
  resource: ResourceId,
  operation: string,
): Promise<ResourceDEK | undefined> {
  const bytes = await secrets.get(pendingDekRef(resource, operation));
  if (bytes === undefined) return undefined;
  try {
    return importResourceDEK(bytes);
  } finally {
    bytes.fill(0);
  }
}

/** A fresh, unique operation ID. */
export function newOperationId(kind: OperationKind, random: Uint8Array): string {
  return `${kind}.${toHex(random)}`;
}
