import { type DataUnitId, dataUnitId, fromHex, type ResourceId, toHex } from "@openlfcp/core";
import type { LfcpStorage, StorageWrite } from "@openlfcp/storage";
import { type Receipt, receiptOf, receiptsOf } from "./receipts.js";

/**
 * The status of a committed batch (SDK-SECTIONS-INTEGRATION-01 §4.1,
 * LFCP-02-026): which of its units the server accepted, and whether it was
 * rejected. Kept next to the batch's receipt as a local mark, and written
 * in the same storage transaction as the evidence that changes it (the
 * ACK's dequeue), so a restart never loses an acceptance nor invents one.
 * An index maps each unit of a receipt to its operation.
 */

/** §4.1. */
export type BatchStatusName =
  | "saved"
  | "pending"
  | "accepted"
  | "evidence-unavailable"
  | "rejected";

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
): Promise<BatchStatus | undefined> {
  const receipt = await receiptOf(storage, resource, operationId);
  if (receipt === undefined) return undefined;
  return deriveStatus(receipt, await stored(storage, resource, operationId), readyDurability);
}

/** Every receipt's batch of a Resource, by operation ID. */
export async function batchStatuses(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  readyDurability: bigint | null,
): Promise<BatchStatus[]> {
  const out: BatchStatus[] = [];
  for (const receipt of await receiptsOf(storage, resource))
    out.push(
      deriveStatus(receipt, await stored(storage, resource, receipt.operationId), readyDurability),
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
 * of no receipt are ignored. Pure apart from reading the marks.
 */
export async function recordEvidence(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
  units: readonly string[],
  evidence: UnitEvidence,
): Promise<{
  readonly writes: StorageWrite[];
  readonly changed: ReadonlyMap<string, readonly string[]>;
}> {
  const byOperation = new Map<string, string[]>();
  for (const u of new Set(units)) {
    const op = await storage.localMarks.get(unitKey(resource, u));
    if (op !== undefined) byOperation.set(op, [...(byOperation.get(op) ?? []), u]);
  }
  const writes: StorageWrite[] = [];
  const changed = new Map<string, readonly string[]>();
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
    writes.push({
      op: "put-local-mark",
      key: statusKey(resource, op),
      value: JSON.stringify(next),
    });
  }
  return { writes, changed };
}
