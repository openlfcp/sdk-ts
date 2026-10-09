import { type DataUnitId, dataUnitId, fromHex, type ResourceId, toHex } from "@openlfcp/core";
import type { LfcpStorage, StorageWrite } from "@openlfcp/storage";
import {
  type Receipt,
  receiptOf,
  receiptsOf,
  releasedReceiptOf,
  releasedReceiptsOf,
  releasedWrite,
} from "./receipts.js";

/**
 * The status of a committed batch (SDK-SECTIONS-INTEGRATION-01 §4.1,
 * LFCP-02-026): which of its units the server accepted, and whether it was
 * rejected. Kept next to the batch's receipt as a local mark, and written
 * in the same storage transaction as the evidence that changes it (the
 * ACK's dequeue), so a restart never loses an acceptance nor invents one.
 * An index maps each unit of a receipt to its operation. A batch whose
 * receipt was released before it was final stays here until it is final
 * (receipts.ts).
 */

/** §4.1. */
export type BatchStatusName =
  | "saved"
  | "pending"
  | "accepted"
  | "evidence-unavailable"
  | "rejected"
  /**
   * LFCP-02-115: not accepted, and the server refuses the Resource in this
   * session (e.g. AUTHORIZATION_FAILED on RESOURCE_OPEN): it cannot be
   * accepted there now. Not a refusal of the content; the work is kept.
   */
  | "blocked";

/** §4.1, §5 `batch`: a committed batch and the evidence about its units. */
export interface BatchStatus {
  readonly operationId: string;
  readonly status: BatchStatusName;
  readonly unitIds: readonly DataUnitId[];
  /** The units a correlated durable ACK from a durability-2 server on the route set named (§4.1). */
  readonly acceptedUnitIds: readonly DataUnitId[];
  readonly affectedNodeIds: readonly string[];
  /** A terminal NACK of one of its units. */
  readonly rejection?: { readonly code: string; readonly unitIds: readonly DataUnitId[] };
}

/** The durability (§37) an ACK must establish to be acceptance evidence (§4.1). */
export const ACCEPTANCE_DURABILITY = 2n;

interface Stored {
  /** Units with acceptance evidence (hex). */
  readonly accepted: readonly string[];
  /** Units acknowledged without it: not durable, below durability 2, or off the route set (hex). */
  readonly unconfirmed: readonly string[];
  readonly rejection?: { readonly code: string; readonly unitIds: readonly string[] };
}

const EMPTY: Stored = { accepted: [], unconfirmed: [] };
const statusKey = (resource: ResourceId, operationId: string) =>
  `batch-status:${toHex(resource)}:${operationId}`;
const unitKey = (resource: ResourceId, unit: string) => `receipt-unit:${toHex(resource)}:${unit}`;

/** The index writes of a new receipt (in the commit's transaction). */
export function receiptIndexWrites(resource: ResourceId, receipt: Receipt): StorageWrite[] {
  return receipt.unitIds.map((u) => ({
    op: "put-local-mark",
    key: unitKey(resource, toHex(u)),
    value: receipt.operationId,
  }));
}

/** Accepted or rejected: nothing more will happen to the batch (§4.1). */
function isFinal(receipt: Receipt, s: Stored): boolean {
  return s.rejection !== undefined || receipt.unitIds.every((u) => s.accepted.includes(toHex(u)));
}

/**
 * The writes of releasing `receipt` (with its receipt mark's removal): a
 * final batch's status and index go; a batch not final yet is kept,
 * reported until it is final.
 */
export async function releaseWrites(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  receipt: Receipt,
): Promise<StorageWrite[]> {
  const s = await stored(storage, resource, receipt.operationId);
  return isFinal(receipt, s)
    ? releaseStatusWrites(resource, receipt)
    : [releasedWrite(resource, receipt.operationId, receipt)];
}

/**
 * The writes that forget a released batch still kept for its status, when
 * a new commit takes its operation ID (the new batch replaces it).
 */
export async function replaceReleasedWrites(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  operationId: string,
): Promise<StorageWrite[]> {
  const released = await releasedReceiptOf(storage, resource, operationId);
  return released === undefined
    ? []
    : [releasedWrite(resource, operationId, null), ...releaseStatusWrites(resource, released)];
}

/** The writes that forget a released receipt's status and index. */
export function releaseStatusWrites(resource: ResourceId, receipt: Receipt): StorageWrite[] {
  return [
    { op: "put-local-mark", key: statusKey(resource, receipt.operationId), value: null },
    ...receipt.unitIds.map(
      (u): StorageWrite => ({
        op: "put-local-mark",
        key: unitKey(resource, toHex(u)),
        value: null,
      }),
    ),
  ];
}

async function stored(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  operationId: string,
): Promise<Stored> {
  const raw = await storage.localMarks.get(statusKey(resource, operationId));
  return raw === undefined ? EMPTY : (JSON.parse(raw) as Stored);
}

/**
 * §4.1: the status of a receipt's batch. `readyDurability` is the current
 * session's READY durability, or null without a session.
 */
export function deriveStatus(
  receipt: Receipt,
  s: Stored,
  readyDurability: bigint | null,
  refused = false,
): BatchStatus {
  const units = receipt.unitIds.map((u) => toHex(u));
  const accepted = units.filter((u) => s.accepted.includes(u));
  const status: BatchStatusName =
    s.rejection !== undefined
      ? "rejected"
      : units.length === 0
        ? "saved"
        : accepted.length === units.length
          ? "accepted"
          : refused
            ? "blocked"
            : units.some((u) => s.unconfirmed.includes(u) && !s.accepted.includes(u)) ||
                (readyDurability !== null && readyDurability < ACCEPTANCE_DURABILITY)
              ? "evidence-unavailable"
              : "pending";
  const ids = (hex: readonly string[]) => Object.freeze(hex.map((h) => dataUnitId(fromHex(h))));
  return Object.freeze({
    operationId: receipt.operationId,
    status,
    unitIds: receipt.unitIds,
    acceptedUnitIds: ids(accepted),
    affectedNodeIds: receipt.affectedNodeIds,
    ...(s.rejection === undefined
      ? {}
      : {
          rejection: Object.freeze({ code: s.rejection.code, unitIds: ids(s.rejection.unitIds) }),
        }),
  });
}

/** The status of one operation's batch; undefined without a receipt. */
export async function batchStatus(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  operationId: string,
  readyDurability: bigint | null,
  refused = false,
): Promise<BatchStatus | undefined> {
  const receipt =
    (await receiptOf(storage, resource, operationId)) ??
    (await releasedReceiptOf(storage, resource, operationId));
  if (receipt === undefined) return undefined;
  return deriveStatus(
    receipt,
    await stored(storage, resource, operationId),
    readyDurability,
    refused,
  );
}

/** Every receipt's batch of a Resource, and every released batch not final yet, by operation ID. */
export async function batchStatuses(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  readyDurability: bigint | null,
  refused = false,
): Promise<BatchStatus[]> {
  const out: BatchStatus[] = [];
  const held = await receiptsOf(storage, resource);
  const ids = new Set(held.map((r) => r.operationId));
  const released = (await releasedReceiptsOf(storage, resource)).filter(
    (r) => !ids.has(r.operationId),
  );
  for (const receipt of [...held, ...released])
    out.push(
      deriveStatus(
        receipt,
        await stored(storage, resource, receipt.operationId),
        readyDurability,
        refused,
      ),
    );
  return out.sort((a, b) => (a.operationId < b.operationId ? -1 : 1));
}

/** What happened to units of receipts: how their batches' stored status changes. */
export type UnitEvidence =
  /** Acceptance evidence (§4.1). */
  | { readonly kind: "accepted" }
  /** Acknowledged without acceptance evidence. */
  | { readonly kind: "unconfirmed" }
  /** A terminal NACK. */
  | { readonly kind: "rejected"; readonly code: string }
  /** Offered again after the server lost them (§4.2): no longer accepted. */
  | { readonly kind: "reoffered" };

/**
 * The writes recording `evidence` for `units` (hex), and the operations
 * whose stored status changed with the units that changed in each. Units
 * of no receipt are ignored. A released batch that becomes final is
 * forgotten in the same writes; its final status is in `finals`, since it
 * cannot be read back. Pure apart from reading the marks.
 */
export async function recordEvidence(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  units: readonly string[],
  evidence: UnitEvidence,
): Promise<{
  readonly writes: StorageWrite[];
  readonly changed: ReadonlyMap<string, readonly string[]>;
  readonly finals: ReadonlyMap<string, BatchStatus>;
}> {
  const byOperation = new Map<string, string[]>();
  for (const u of new Set(units)) {
    const op = await storage.localMarks.get(unitKey(resource, u));
    if (op !== undefined) byOperation.set(op, [...(byOperation.get(op) ?? []), u]);
  }
  const writes: StorageWrite[] = [];
  const changed = new Map<string, readonly string[]>();
  const finals = new Map<string, BatchStatus>();
  for (const [op, mine] of byOperation) {
    const s = await stored(storage, resource, op);
    let next: Stored = s;
    let touched: string[] = [];
    switch (evidence.kind) {
      case "accepted":
        touched = mine.filter((u) => !s.accepted.includes(u));
        next = { ...s, accepted: [...s.accepted, ...touched] };
        break;
      case "unconfirmed":
        touched = mine.filter((u) => !s.accepted.includes(u) && !s.unconfirmed.includes(u));
        next = { ...s, unconfirmed: [...s.unconfirmed, ...touched] };
        break;
      case "rejected":
        if (s.rejection !== undefined) break;
        touched = mine;
        next = { ...s, rejection: { code: evidence.code, unitIds: mine } };
        break;
      case "reoffered":
        touched = mine.filter((u) => s.accepted.includes(u) || s.unconfirmed.includes(u));
        next = {
          ...s,
          accepted: s.accepted.filter((u) => !mine.includes(u)),
          unconfirmed: s.unconfirmed.filter((u) => !mine.includes(u)),
        };
        break;
    }
    if (touched.length === 0) continue;
    changed.set(op, touched);
    const released =
      (await receiptOf(storage, resource, op)) === undefined
        ? await releasedReceiptOf(storage, resource, op)
        : undefined;
    if (released !== undefined && isFinal(released, next)) {
      finals.set(op, deriveStatus(released, next, null));
      writes.push(releasedWrite(resource, op, null), ...releaseStatusWrites(resource, released));
      continue;
    }
    writes.push({
      op: "put-local-mark",
      key: statusKey(resource, op),
      value: JSON.stringify(next),
    });
  }
  return { writes, changed, finals };
}
