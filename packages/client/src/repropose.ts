import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type Hash32,
  hash32,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  dekSecretRef,
  type LfcpStorage,
  type SecretStore,
  type StorageWrite,
} from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlState,
  controlRecordSigner,
  decodeControlRecord,
  isGrantActive,
  type PrincipalDescriptor,
  parseKeyPackage,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";
import type { OutboundQueue } from "./outbound.js";
import { controlRecordWrites, keyPackageWrites } from "./queue.js";
import { localControlChain } from "./storage.js";

/**
 * Re-proposing this client's own Control Records that the coordinator
 * refused with CONTROL_HEAD_MISMATCH (LFCP-WIRE-01 §21, §47; the LFCP-036
 * design). A record proposed on a head that another writer moved is blocked
 * "repropose" by the OutboundQueue; without this it — and every object that
 * depends on it, such as a grant's invitation Key Package — would wait
 * forever. Here each blocked record is re-authored on the current local
 * head, keeping its intent, re-signed with a new record ID, and its
 * dependent Key Packages are re-sealed to the new head; a record that is no
 * longer authorized or meaningful is dropped with a typed outcome instead.
 *
 * Only the GRANT and REVOKE intents are re-authored: a revocation/rotation
 * is serialized at the author (SyncClient.revokeAccess refuses while a
 * Control Record is pending), so a KEY_EPOCH never reaches re-proposal; one
 * that somehow does is dropped (its epoch number, DEK commitment and final
 * frontier are bound to the head it was built on) and surfaced, so the
 * application re-runs the high-level operation.
 *
 * Re-authoring is idempotent (a grant already on the chain with the same
 * subject and abilities is treated as superseded, not duplicated) and
 * bounded (an item re-proposed `maxAttempts` times without landing is
 * dropped), so a head that keeps moving cannot loop.
 */

export type ReproposeDropReason =
  /** The blocked record was not authored by this client, so it cannot be re-signed. */
  | "not-author"
  /** An equivalent grant is already on the chain: this one was re-proposed before. */
  | "superseded"
  /** The intent is no longer authorized on the moved head. */
  | "unauthorized"
  /** A revocation whose target grant is already inactive on the moved head. */
  | "already-revoked"
  /** A dependent Key Package's DEK is not held, so it cannot be re-sealed. */
  | "no-dek"
  /** A dependent Key Package no longer verifies on the moved head. */
  | "key-unauthorized"
  /** A KEY_EPOCH or other intent that is not re-authored here. */
  | "unsupported-intent"
  /** Re-proposed too many times without landing (the head kept moving). */
  | "attempts-exhausted";

export type ReproposeOutcome =
  | {
      readonly kind: "reproposed";
      readonly oldId: ControlRecordId;
      readonly newId: ControlRecordId;
      /** The dependent Key Packages re-sealed to the new head, old ID → new ID. */
      readonly keyPackages: readonly { readonly oldId: Hash32; readonly newId: Hash32 }[];
    }
  | {
      readonly kind: "dropped";
      readonly oldId: ControlRecordId;
      readonly reason: ReproposeDropReason;
    };

export interface ReproposeResult {
  readonly outcomes: readonly ReproposeOutcome[];
}

type Linear = Extract<ChainResult, { kind: "linear" }>;

export interface ReproposeOptions {
  readonly storage: Pick<LfcpStorage, "control" | "outbound" | "commit">;
  readonly secrets: SecretStore;
  readonly signer: Signer;
  readonly resource: ResourceId;
  /** For dropping in-memory tracking of the items a re-proposal replaces. */
  readonly queue: OutboundQueue;
  /** Re-proposal attempts per blocked record (by item ID hex), owned by the caller. */
  readonly attempts: Map<string, number>;
  /** The cap after which an item is dropped "attempts-exhausted" (default 8). */
  readonly maxAttempts?: number;
}

/** The descriptor of `principal` from the validated chain (its principals, owner or a grant subject). */
function descriptorOf(
  state: ControlState,
  principal: PrincipalId,
): PrincipalDescriptor | undefined {
  const known = state.principals.get(toHex(principal));
  if (known !== undefined) return known;
  if (bytesEqual(state.owner.principalId, principal)) return state.owner;
  return undefined;
}

/** An active grant on `state` with the same subject and ability set (a prior re-proposal of this grant). */
function equivalentGrant(
  state: ControlState,
  subject: PrincipalId,
  abilities: readonly bigint[],
): boolean {
  const want = [...abilities].map(String).sort().join(",");
  for (const g of state.grants.values())
    if (
      bytesEqual(g.subject, subject) &&
      isGrantActive(state, g.id) &&
      [...g.abilities].map(String).sort().join(",") === want
    )
      return true;
  return false;
}

/** Re-signs a record on the local head and checks it extends the chain linearly; undefined when it does not. */
function reauthor(
  local: Linear,
  sign: (header: {
    resourceId: ResourceId;
    controlSeq: bigint;
    prevControlId: ControlRecordId;
  }) => { bytes: Uint8Array; recordId: ControlRecordId },
): { bytes: Uint8Array; newId: ControlRecordId; next: Linear } | undefined {
  const signed = sign({
    resourceId: local.state.resourceId,
    controlSeq: local.state.seq + 1n,
    prevControlId: local.state.head,
  });
  const next = validateControlChain([...local.records.map((r) => r.signed.bytes), signed.bytes]);
  if (next.kind !== "linear") return undefined;
  return { bytes: signed.bytes, newId: signed.recordId, next };
}

type Resealed =
  | {
      readonly ok: true;
      readonly removed: readonly Hash32[];
      readonly added: readonly Uint8Array[];
      readonly mapping: readonly { oldId: Hash32; newId: Hash32 }[];
    }
  | { readonly ok: false; readonly reason: "no-dek" | "key-unauthorized" };

/** Re-seals every queued Key Package that depended on `oldHead` to the re-proposed `newHead`/`next`. */
async function resealDependents(
  options: ReproposeOptions,
  next: Linear,
  oldHead: ControlRecordId,
  newHead: ControlRecordId,
): Promise<Resealed> {
  const removed: Hash32[] = [];
  const added: Uint8Array[] = [];
  const mapping: { oldId: Hash32; newId: Hash32 }[] = [];
  for (const item of await options.storage.outbound.list(options.resource)) {
    if (item.kind !== "key-package") continue;
    let controlHead: Uint8Array;
    let recipientId: PrincipalId;
    let epoch: DataEpoch;
    try {
      const p = parseKeyPackage(item.bytes).payload;
      controlHead = p.controlHead;
      recipientId = p.recipient;
      epoch = p.dataEpoch;
    } catch {
      continue;
    }
    if (!bytesEqual(controlHead, oldHead)) continue;
    const recipient = descriptorOf(next.state, recipientId);
    const bytes = await options.secrets.get(dekSecretRef(options.resource, epoch));
    if (recipient === undefined || bytes === undefined) return { ok: false, reason: "no-dek" };
    const sealed = await sealKeyPackage({
      resourceId: options.resource,
      epoch,
      controlHead: newHead,
      recipient,
      dek: importResourceDEK(bytes),
      signer: options.signer,
    });
    if (verifyKeyPackage(next, parseKeyPackage(sealed.bytes)).kind !== "authorized")
      return { ok: false, reason: "key-unauthorized" };
    removed.push(item.itemId);
    added.push(sealed.bytes);
    mapping.push({ oldId: item.itemId, newId: hash32(parseKeyPackage(sealed.bytes).signed.id) });
  }
  return Object.freeze({ ok: true, removed, added, mapping });
}

/** The queued Key Packages of `resource` whose control head is `controlHead`. */
async function dependentKeyPackages(
  storage: Pick<LfcpStorage, "outbound">,
  resource: ResourceId,
  controlHead: ControlRecordId,
): Promise<Hash32[]> {
  const out: Hash32[] = [];
  for (const item of await storage.outbound.list(resource)) {
    if (item.kind !== "key-package") continue;
    try {
      if (bytesEqual(parseKeyPackage(item.bytes).payload.controlHead, controlHead))
        out.push(item.itemId);
    } catch {
      // not a parsable Key Package: never a dependent of this head.
    }
  }
  return out;
}

/** Enqueues the re-authored record and its re-sealed Key Packages and dequeues the old ones, in one transaction. */
async function swap(
  storage: Pick<LfcpStorage, "commit">,
  queue: OutboundQueue,
  change: {
    removeControl: Hash32;
    removeKeyPackages: readonly Hash32[];
    addControl: Uint8Array;
    addKeyPackages: readonly Uint8Array[];
  },
): Promise<void> {
  const writes: StorageWrite[] = [
    { op: "dequeue", itemId: change.removeControl },
    ...change.removeKeyPackages.map((itemId): StorageWrite => ({ op: "dequeue", itemId })),
    ...controlRecordWrites(change.addControl),
    ...change.addKeyPackages.flatMap(keyPackageWrites),
  ];
  const r = await storage.commit(writes);
  if (!r.ok) throw new Error(`the re-proposal was not committed: ${r.reason}`);
  queue.release([change.removeControl, ...change.removeKeyPackages]);
}

/** Dequeues a blocked record and its dependents and drops the queue's in-memory tracking of them. */
async function dropItem(
  storage: Pick<LfcpStorage, "commit">,
  queue: OutboundQueue,
  ids: readonly Hash32[],
): Promise<void> {
  const r = await storage.commit(ids.map((itemId): StorageWrite => ({ op: "dequeue", itemId })));
  if (!r.ok) throw new Error(`a re-proposal drop was not committed: ${r.reason}`);
  queue.release(ids);
}

/**
 * Re-proposes every blocked "repropose" Control Record of `resource`, in
 * record order, each on the local head left by the ones before it. Returns
 * one outcome per blocked record. Call it under the same serial lock as the
 * queue, so no other record is authored meanwhile.
 */
export async function reproposeControlRecords(options: ReproposeOptions): Promise<ReproposeResult> {
  const { storage, signer, resource, queue } = options;
  const maxAttempts = options.maxAttempts ?? 8;
  const blocked = (await storage.outbound.list(resource))
    .filter((i) => i.kind === "control-record" && i.blocked?.reason === "repropose")
    .map((i) => ({ itemId: i.itemId, record: decodeControlRecord(i.bytes) }))
    .sort((a, b) => (a.record.payload.controlSeq < b.record.payload.controlSeq ? -1 : 1));
  const outcomes: ReproposeOutcome[] = [];
  const mine = signer.descriptor.principalId;

  for (const { itemId, record } of blocked) {
    const oldId = controlRecordId(record.signed.id);
    const drop = async (reason: ReproposeDropReason): Promise<void> => {
      options.attempts.delete(toHex(itemId));
      await dropItem(storage, queue, [
        itemId,
        ...(await dependentKeyPackages(storage, resource, oldId)),
      ]);
      outcomes.push(Object.freeze({ kind: "dropped", oldId, reason }));
    };

    if (!bytesEqual(controlRecordSigner(record), mine)) {
      await drop("not-author");
      continue;
    }
    const attempt = (options.attempts.get(toHex(itemId)) ?? 0) + 1;
    if (attempt > maxAttempts) {
      await drop("attempts-exhausted");
      continue;
    }
    options.attempts.set(toHex(itemId), attempt);

    const local = await localControlChain(storage, resource);
    if (local === undefined || local.kind !== "linear") {
      await drop("unauthorized");
      continue;
    }

    const body = record.body;
    if (body.type === "CAPABILITY_GRANT") {
      if (equivalentGrant(local.state, body.subject.principalId, body.abilities)) {
        await drop("superseded");
        continue;
      }
      const reauthored = reauthor(local, (header) =>
        signControlRecord(
          header,
          {
            type: "CAPABILITY_GRANT",
            subject: body.subject,
            abilities: body.abilities,
            delegable: body.delegable,
            ...(body.claimLimit === undefined ? {} : { claimLimit: body.claimLimit }),
          },
          signer,
        ),
      );
      if (reauthored === undefined) {
        await drop("unauthorized");
        continue;
      }
      const resealed = await resealDependents(options, reauthored.next, oldId, reauthored.newId);
      if (!resealed.ok) {
        await drop(resealed.reason);
        continue;
      }
      await swap(storage, queue, {
        removeControl: itemId,
        removeKeyPackages: resealed.removed,
        addControl: reauthored.bytes,
        addKeyPackages: resealed.added,
      });
      // Carry the attempt count onto the re-authored record, so a head that
      // keeps moving is still bounded (the count is cleared on its ACK).
      options.attempts.delete(toHex(itemId));
      options.attempts.set(toHex(reauthored.newId), attempt);
      outcomes.push(
        Object.freeze({
          kind: "reproposed",
          oldId,
          newId: reauthored.newId,
          keyPackages: resealed.mapping,
        }),
      );
      continue;
    }

    if (body.type === "CAPABILITY_REVOKE") {
      if (!isGrantActive(local.state, body.grantId)) {
        await drop("already-revoked");
        continue;
      }
      const reauthored = reauthor(local, (header) =>
        signControlRecord(header, { type: "CAPABILITY_REVOKE", grantId: body.grantId }, signer),
      );
      if (reauthored === undefined) {
        await drop("unauthorized");
        continue;
      }
      await swap(storage, queue, {
        removeControl: itemId,
        removeKeyPackages: [],
        addControl: reauthored.bytes,
        addKeyPackages: [],
      });
      options.attempts.delete(toHex(itemId));
      options.attempts.set(toHex(reauthored.newId), attempt);
      outcomes.push(
        Object.freeze({ kind: "reproposed", oldId, newId: reauthored.newId, keyPackages: [] }),
      );
      continue;
    }

    await drop("unsupported-intent");
  }
  return Object.freeze({ outcomes: Object.freeze(outcomes) });
}
