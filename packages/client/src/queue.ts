import { type Hash32, hash32, type ResourceId } from "@openlfcp/core";
import type { LfcpStorage, OutboundItem, OutboundKind, StorageWrite } from "@openlfcp/storage";
import {
  canonicalFrontierToCbor,
  parseControlRecord,
  parseKeyPackage,
  parseSnapshot,
} from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import { type CreatedSnapshot, type CreateSnapshotOptions, createSnapshot } from "./snapshot.js";

/**
 * Putting this client's immutable objects into the outbound queue
 * (LFCP-036): each is stored with its exact bytes, and queued, in ONE
 * atomic commit before it can be sent. The queue (OutboundQueue) sends
 * these same bytes until an ACK names the object.
 */

/** A new outbound item: never attempted, not blocked. */
export const outboundItem = (
  kind: OutboundKind,
  itemId: Hash32,
  resourceId: ResourceId,
  bytes: Uint8Array,
): OutboundItem => ({
  itemId,
  resourceId,
  kind,
  bytes,
  attempts: 0,
  lastAttempt: null,
  nextAttempt: null,
  blocked: null,
});

async function commit(
  storage: Pick<LfcpStorage, "commit">,
  writes: readonly StorageWrite[],
): Promise<void> {
  const r = await storage.commit(writes);
  if (!r.ok) throw new Error(`the object was not queued: ${r.reason}`);
}

/** Stores a sealed Key Package (§25) and queues it for KEY_PACKAGE_PUT. */
export async function queueKeyPackage(
  storage: Pick<LfcpStorage, "commit">,
  bytes: Uint8Array,
  also: readonly StorageWrite[] = [],
): Promise<Hash32> {
  const parsed = parseKeyPackage(bytes);
  const p = parsed.payload;
  const id = hash32(parsed.signed.id);
  await commit(storage, [
    {
      op: "put-key-package",
      row: {
        packageId: id,
        resourceId: p.resourceId,
        dataEpoch: p.dataEpoch,
        recipient: p.recipient,
        sender: p.sender,
        bytes: parsed.signed.bytes,
      },
    },
    { op: "enqueue", item: outboundItem("key-package", id, p.resourceId, parsed.signed.bytes) },
    ...also,
  ]);
  return id;
}

/** Stores a sealed Snapshot (§29) with its selection metadata and queues it for SNAPSHOT_PUT. */
export async function queueSnapshot(
  storage: Pick<LfcpStorage, "commit">,
  bytes: Uint8Array,
  also: readonly StorageWrite[] = [],
): Promise<Hash32> {
  const parsed = parseSnapshot(bytes);
  const p = parsed.payload;
  const id = hash32(parsed.signed.id);
  await commit(storage, [
    {
      op: "put-snapshot",
      row: {
        snapshotId: id,
        resourceId: p.resourceId,
        dataEpoch: p.dataEpoch,
        publisher: p.publisher,
        snapshotSeq: p.snapshotSeq,
        frontier: encode(canonicalFrontierToCbor(p.frontier)),
        bytes: parsed.signed.bytes,
      },
    },
    { op: "enqueue", item: outboundItem("snapshot", id, p.resourceId, parsed.signed.bytes) },
    ...also,
  ]);
  return id;
}

/**
 * Creates a Snapshot with a sequence from the storage's reservation and
 * queues it (see createSnapshot and queueSnapshot): a crash before the
 * commit leaves only an abandoned sequence.
 */
export async function createQueuedSnapshot<T>(
  storage: Pick<LfcpStorage, "snapshotSequences" | "commit">,
  options: Omit<CreateSnapshotOptions<T>, "sequences">,
  also: readonly StorageWrite[] = [],
): Promise<CreatedSnapshot> {
  const created = await createSnapshot({ ...options, sequences: storage.snapshotSequences });
  await queueSnapshot(storage, created.bytes, also);
  return created;
}

/**
 * Queues a signed Control Record for CONTROL_PUT (§47); its expected head
 * is its own previous record. It joins the stored chain only once a
 * validated chain contains it (saveControlChain).
 */
export async function queueControlRecord(
  storage: Pick<LfcpStorage, "commit">,
  bytes: Uint8Array,
  also: readonly StorageWrite[] = [],
): Promise<Hash32> {
  const parsed = parseControlRecord(bytes);
  if (parsed.payload.prevControlId === null)
    throw new Error("a Genesis record is hosted with RESOURCE_HOST, not CONTROL_PUT");
  const id = hash32(parsed.signed.id);
  await commit(storage, [
    {
      op: "enqueue",
      item: outboundItem("control-record", id, parsed.payload.resourceId, parsed.signed.bytes),
    },
    ...also,
  ]);
  return id;
}
