import { type DataUnitId, dataUnitId, fromHex, type ResourceId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import type { LfcpStorage, StorageWrite } from "@openlfcp/storage";
import { type CborValue, cborMap, encode } from "@openlfcp/wire/cbor";

/**
 * Commit receipts (SDK-SECTIONS-INTEGRATION-01 §3, LFCP-02-025): the
 * durable record that a batch of intents was committed locally, written in
 * the same storage transaction as its Data Units, outbound entries and
 * profile checkpoint (commitOperation). A receipt is kept as a local mark
 * under its Resource and operation ID until the caller releases it.
 */

/** §3.2: what a committed batch produced. */
export interface Receipt {
  readonly operationId: string;
  /** The Data Unit IDs of the batch, in the order of their changes. */
  readonly unitIds: readonly DataUnitId[];
  /** The nodes the batch writes (and the section when it writes the title). */
  readonly affectedNodeIds: readonly string[];
  /** The local document's heads after the commit, sorted, as one opaque string. */
  readonly modelRevision: string;
  /** §3.3: SHA-256 (hex) of the batch's canonical form. */
  readonly intentsHash: string;
  /** Always true: a receipt exists only for a durable commit. */
  readonly durable: true;
}

/** §3.3: an operation ID that already has a receipt for different intents. A local SDK error. */
export class OperationIdReusedError extends Error {
  readonly code = "OPERATION_ID_REUSED";

  constructor(readonly operationId: string) {
    super(`operation ${operationId} already committed different intents (§3.3)`);
    this.name = "OperationIdReusedError";
  }
}

const PREFIX = "receipt:";
const markKey = (resource: ResourceId, operationId: string) =>
  `${PREFIX}${toHex(resource)}:${operationId}`;

/** A plain value as the CBOR data model: objects become maps, absent fields are left out. */
function cbor(value: unknown, depth = 0): CborValue {
  if (depth > 64) throw new Error("an intent nests too deep to hash");
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      throw new Error(`an intent holds a non-integer number: ${value}`);
    return value;
  }
  if (typeof value === "bigint" || value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map((v) => cbor(v, depth + 1));
  if (typeof value === "object")
    return cborMap(
      Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, cbor(v, depth + 1)] as const),
    );
  throw new Error(`an intent holds a ${typeof value}, which has no canonical form`);
}

/**
 * §3.3: SHA-256 (hex) of the deterministic CBOR (RFC 8949 §4.2.1) of the
 * list of intents in order, each a map from its field names to their
 * values, Text as given, nothing normalized.
 */
export function intentsHash(intents: readonly unknown[]): string {
  return toHex(sha256(encode(cbor(intents))));
}

interface Stored {
  readonly operationId: string;
  readonly unitIds: readonly string[];
  readonly affectedNodeIds: readonly string[];
  readonly modelRevision: string;
  readonly intentsHash: string;
}

/** The local-mark write that stores `receipt` (for the commit's transaction). */
export function receiptWrite(resource: ResourceId, receipt: Receipt): StorageWrite {
  const stored: Stored = {
    operationId: receipt.operationId,
    unitIds: receipt.unitIds.map((u) => toHex(u)),
    affectedNodeIds: [...receipt.affectedNodeIds],
    modelRevision: receipt.modelRevision,
    intentsHash: receipt.intentsHash,
  };
  return {
    op: "put-local-mark",
    key: markKey(resource, receipt.operationId),
    value: JSON.stringify(stored),
  };
}

/** §3.4: the receipt of an operation, definitive across restarts; undefined when nothing was committed. */
export async function receiptOf(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  operationId: string,
): Promise<Receipt | undefined> {
  const raw = await storage.localMarks.get(markKey(resource, operationId));
  if (raw === undefined) return undefined;
  const s = JSON.parse(raw) as Stored;
  return Object.freeze({
    operationId: s.operationId,
    unitIds: Object.freeze(s.unitIds.map((u) => dataUnitId(fromHex(u)))),
    affectedNodeIds: Object.freeze([...s.affectedNodeIds]),
    modelRevision: s.modelRevision,
    intentsHash: s.intentsHash,
    durable: true,
  });
}

/** §3.5: forgets a receipt the caller has finished with. */
export async function releaseReceipt(
  storage: Pick<LfcpStorage, "commit">,
  resource: ResourceId,
  operationId: string,
): Promise<void> {
  const r = await storage.commit([
    { op: "put-local-mark", key: markKey(resource, operationId), value: null },
  ]);
  if (!r.ok) throw new Error(`the receipt was not released: ${r.reason}`);
}
