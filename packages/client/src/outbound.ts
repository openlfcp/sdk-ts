import {
  type ActorSequence,
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  dataUnitId,
  type Hash32,
  hash32,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import type {
  LfcpStorage,
  OutboundBlock,
  OutboundItem,
  OutboundKind,
  StorageWrite,
} from "@openlfcp/storage";
import {
  addSequence,
  type ControlView,
  type CoreMessageType,
  canonicalFrontierFromCbor,
  classifyDataUnit,
  createMessage,
  DEFAULT_MAX_MESSAGE_BYTES,
  ERROR_CODE,
  encodeMessage,
  type HaveVector,
  type LfcpMessage,
  MESSAGE_TYPE,
  parseControlRecord,
  unionHaves,
  type WireErrorName,
} from "@openlfcp/wire";
import { decodeDeterministic } from "@openlfcp/wire/cbor";

/**
 * The pending outbound queue and its sync state (LFCP-036): a
 * transport-agnostic state machine over the stored outbound items. The
 * transport (LFCP-039a) asks for messages, sends them, and reports ACKs,
 * NACKs and connection loss; time comes from the caller, and nothing here
 * sleeps or sets timers.
 *
 * The object and the message are different things:
 * - an item is an immutable LFCP object (Data Unit, Control Record, Key
 *   Package, Snapshot) persisted with its exact bytes before it is ever
 *   sent (createQueuedDataUnit, queueKeyPackage, …); it leaves the queue
 *   only when an ACK names its ID, or when the application discards it
 *   after it was blocked;
 * - a message is one transport attempt: every send wraps the SAME bytes in
 *   a NEW message with a new Message ID. Nothing here creates an LFCP
 *   object, reserves a sequence or touches plaintext, so a retry can never
 *   reuse a nonce.
 *
 * In-flight state is memory only: after a restart (or a lost connection)
 * every unblocked item is due again and is resent byte for byte.
 */

/** Why an item is being retried; given to the RetryPolicy. */
export type RetryReason =
  /** The connection went away after send, before an answer. */
  | "connection-lost"
  /** A NACK with a transient or unknown code. */
  | "transient"
  /** An ACK of its message that did not name it, or named it below the required durability. */
  | "not-acked";

export interface RetryPolicy {
  /**
   * When the item may be sent again (RFC 3339, caller's clock), or null for
   * at once. Pure: the caller owns time; the result is stored with the item.
   */
  nextAttempt(failure: {
    readonly item: OutboundItem;
    readonly reason: RetryReason;
    readonly code?: WireErrorName | bigint;
    readonly now: string;
  }): string | null;
}

/** Exponential backoff from `baseMs`, doubling per attempt, capped at `maxMs`. */
export function exponentialBackoff(baseMs: number, maxMs: number): RetryPolicy {
  return {
    nextAttempt: ({ item, now }) => {
      const delay = Math.min(maxMs, baseMs * 2 ** Math.max(0, item.attempts - 1));
      return new Date(Date.parse(now) + delay).toISOString();
    },
  };
}

const KIND_TYPE: Readonly<Record<OutboundKind, CoreMessageType>> = {
  "control-record": "CONTROL_PUT",
  "key-package": "KEY_PACKAGE_PUT",
  "data-unit": "DATA_PUT",
  snapshot: "SNAPSHOT_PUT",
};
/** §88: Control Plane first, then Key Packages, Data Units, Snapshots. */
const KIND_ORDER: readonly OutboundKind[] = [
  "control-record",
  "key-package",
  "data-unit",
  "snapshot",
];
/** NACK codes that concern one object: a multi-object message is split to find it. */
const PER_OBJECT: ReadonlySet<WireErrorName> = new Set([
  "STALE_DATA_EPOCH",
  "ACTOR_EQUIVOCATION",
  "AUTHORIZATION_FAILED",
  "MESSAGE_TOO_LARGE",
  "INVALID_SIGNATURE",
  "MALFORMED_MESSAGE",
]);
const CODE_NAMES: ReadonlyMap<bigint, WireErrorName> = new Map(
  Object.entries(ERROR_CODE).map(([name, code]) => [code, name as WireErrorName]),
);
/** Room left in a message for the envelope and body around the objects. */
const OVERHEAD = 1024;

/** One message to send now, and the queued objects it carries. */
export interface OutboundMessage {
  readonly resourceId: ResourceId;
  readonly message: LfcpMessage;
  /** The encoded message; send exactly these bytes. */
  readonly bytes: Uint8Array;
  readonly itemIds: readonly Hash32[];
}

export interface AckOutcome {
  /** Items the ACK named, now removed from the queue. */
  readonly acked: readonly Hash32[];
  /** Items of the acknowledged message the ACK did not name: still queued. */
  readonly notCovered: readonly Hash32[];
  /** The durability the ACK established: READY's level when durable, else 0 (§37, §59). */
  readonly durability: bigint;
  /** Named, but below the required durability: still queued. */
  readonly belowDurability: readonly Hash32[];
  /** False when the ACK answers no message of this session (matched by object ID only). */
  readonly correlated: boolean;
}

/** A blocked item as surfaced to the application. */
export interface BlockedItem {
  readonly itemId: Hash32;
  readonly kind: OutboundKind;
  readonly reason: OutboundBlock;
  readonly detail: string | null;
}

export type NackOutcome =
  /** A per-object refusal for a message of several objects: each is now sent alone. */
  | { readonly kind: "isolating"; readonly code: WireErrorName; readonly items: readonly Hash32[] }
  /**
   * The item is beyond a closed epoch's cutoff (STALE_DATA_EPOCH, G-EP5):
   * never sent again. Applying the user's intent again is a NEW unit in
   * the current epoch, made by the application (not here).
   */
  | { readonly kind: "stale"; readonly items: readonly BlockedItem[] }
  /** The server holds another unit for this (actor, seq): our sequence was reused. A safety alarm. */
  | { readonly kind: "equivocation-alarm"; readonly items: readonly BlockedItem[] }
  /** Refused for good (authority is judged at the unit's own head, so it will not change). */
  | {
      readonly kind: "rejected";
      readonly code: WireErrorName;
      readonly items: readonly BlockedItem[];
    }
  /** A Control Record proposed on a head that moved: build a new record on `currentHead`. */
  | {
      readonly kind: "repropose";
      readonly items: readonly BlockedItem[];
      readonly currentHead: ControlRecordId | null;
    }
  /** The server lacks Control records: retried after the next Control sync (controlSynced). */
  | { readonly kind: "needs-control-sync"; readonly items: readonly Hash32[] }
  /** Transient or unknown: retried after the RetryPolicy delay. */
  | {
      readonly kind: "retry";
      readonly code: WireErrorName | bigint;
      readonly items: readonly Hash32[];
    }
  /** The NACK answers no message of this session. */
  | { readonly kind: "uncorrelated"; readonly code: WireErrorName | bigint };

/** A queued unit of ours that a newly known Key Epoch puts beyond its cutoff (§88 step 7). */
export interface StaleOutboundUnit extends BlockedItem {
  readonly actor: PrincipalId;
  readonly seq: ActorSequence;
  readonly epoch: DataEpoch;
}

export interface OutboundQueueOptions {
  readonly storage: Pick<LfcpStorage, "outbound" | "dataUnits" | "syncState" | "commit">;
  /** Defaults to "at once" (no delay); the caller decides when to ask again. */
  readonly retry?: RetryPolicy;
  /** At most this many objects per DATA_PUT / KEY_PACKAGE_PUT (default 64). */
  readonly maxObjectsPerMessage?: number;
  /**
   * The minimum durability (§37 level) for which an ACK removes an item
   * (default 0: any ACK). The level of an ACK is READY's when it says
   * durable, else 0 (§59: never stronger than advertised).
   */
  readonly minimumDurability?: bigint;
  /** How many recently ACKed IDs the sync state keeps per Resource (default 256). */
  readonly recentAckLimit?: number;
}

interface Flight {
  readonly resourceId: ResourceId;
  readonly type: CoreMessageType;
  readonly itemIds: readonly Hash32[];
}

const AT_ONCE: RetryPolicy = { nextAttempt: () => null };

export class OutboundQueue {
  readonly #storage: OutboundQueueOptions["storage"];
  readonly #retry: RetryPolicy;
  readonly #maxObjects: number;
  readonly #minimumDurability: bigint;
  readonly #recentAckLimit: number;
  /** Session parameters from READY. */
  #durability = 0n;
  #maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES;
  /** message ID hex → what it carried */
  readonly #flights = new Map<string, Flight>();
  /** item ID hex → message ID hex */
  readonly #inFlight = new Map<string, string>();
  /** Items to send one per message (to find which one a per-object NACK meant). */
  readonly #solo = new Set<string>();
  /** Items waiting for a Control sync (MISSING_DEPENDENCY). */
  readonly #awaitingControl = new Set<string>();

  constructor(options: OutboundQueueOptions) {
    this.#storage = options.storage;
    this.#retry = options.retry ?? AT_ONCE;
    this.#maxObjects = Math.max(1, options.maxObjectsPerMessage ?? 64);
    this.#minimumDurability = options.minimumDurability ?? 0n;
    this.#recentAckLimit = options.recentAckLimit ?? 256;
  }

  /** READY: the server's durability level and maximum message size for this session (§37). */
  session(ready: { readonly durability: bigint; readonly maxMessageBytes: bigint }): void {
    this.#durability = ready.durability;
    this.#maxMessageBytes = Number(ready.maxMessageBytes);
  }

  async #commit(writes: readonly StorageWrite[]): Promise<void> {
    if (writes.length === 0) return;
    const r = await this.#storage.commit(writes);
    if (!r.ok) throw new Error(`unexpected storage precondition failure: ${r.reason}`);
  }

  /**
   * The messages to send now for `resource`: every unblocked item that is
   * not in flight, not waiting for a Control sync and due by `now`, in §88
   * order, batched where the message type allows. Each item's attempt is
   * recorded durably before the messages are returned. An item too large
   * for any message is blocked ("too-large") instead.
   */
  async next(resource: ResourceId, now: string): Promise<OutboundMessage[]> {
    const due = (await this.#storage.outbound.list(resource)).filter(
      (o) =>
        o.blocked === null &&
        !this.#inFlight.has(toHex(o.itemId)) &&
        !this.#awaitingControl.has(toHex(o.itemId)) &&
        (o.nextAttempt === null || o.nextAttempt <= now),
    );
    const out: OutboundMessage[] = [];
    const writes: StorageWrite[] = [];
    const limit = this.#maxMessageBytes - OVERHEAD;
    for (const kind of KIND_ORDER) {
      const items = due.filter((o) => o.kind === kind);
      let batch: OutboundItem[] = [];
      let size = 0;
      const flush = () => {
        if (batch.length === 0) return;
        out.push(this.#message(resource, kind, batch));
        batch = [];
        size = 0;
      };
      for (const item of items) {
        // Fail closed on local corruption: an object ID is the SHA-256 of its
        // exact bytes, so other bytes are never sent (nor "repaired").
        if (!bytesEqual(sha256(item.bytes), item.itemId)) {
          writes.push({
            op: "update-outbound",
            itemId: item.itemId,
            blocked: {
              reason: "rejected",
              detail: "local corruption: the stored bytes do not hash to the object ID",
            },
          });
          continue;
        }
        if (item.bytes.length > limit) {
          writes.push({
            op: "update-outbound",
            itemId: item.itemId,
            blocked: { reason: "too-large", detail: `${item.bytes.length} bytes > ${limit}` },
          });
          continue;
        }
        const batchable =
          (kind === "data-unit" || kind === "key-package") && !this.#solo.has(toHex(item.itemId));
        if (!batchable) {
          flush();
          batch = [item];
          flush();
          continue;
        }
        if (batch.length >= this.#maxObjects || size + item.bytes.length > limit) flush();
        batch.push(item);
        size += item.bytes.length;
      }
      flush();
    }
    for (const m of out)
      for (const id of m.itemIds) {
        const item = due.find((o) => bytesEqual(o.itemId, id)) as OutboundItem;
        writes.push({
          op: "update-outbound",
          itemId: id,
          attempts: item.attempts + 1,
          lastAttempt: now,
        });
      }
    await this.#commit(writes);
    for (const m of out) {
      const key = toHex(m.message.messageId);
      this.#flights.set(key, { resourceId: resource, type: m.message.type, itemIds: m.itemIds });
      for (const id of m.itemIds) this.#inFlight.set(toHex(id), key);
    }
    return out;
  }

  /** A new message, with a new Message ID, around the exact stored bytes. */
  #message(
    resource: ResourceId,
    kind: OutboundKind,
    items: readonly OutboundItem[],
  ): OutboundMessage {
    let message: LfcpMessage;
    const first = items[0] as OutboundItem;
    switch (kind) {
      case "data-unit":
        message = createMessage("DATA_PUT", {
          resourceId: resource,
          objects: items.map((i) => i.bytes),
        });
        break;
      case "key-package":
        message = createMessage("KEY_PACKAGE_PUT", {
          resourceId: resource,
          objects: items.map((i) => i.bytes),
        });
        break;
      case "snapshot":
        message = createMessage("SNAPSHOT_PUT", { resourceId: resource, snapshot: first.bytes });
        break;
      case "control-record": {
        // §47: the expected head is the record's own previous record.
        const prev = parseControlRecord(first.bytes).payload.prevControlId;
        if (prev === null)
          throw new Error("a Genesis record is hosted with RESOURCE_HOST, not CONTROL_PUT");
        message = createMessage("CONTROL_PUT", {
          resourceId: resource,
          expectedHead: prev,
          record: first.bytes,
        });
        break;
      }
    }
    return Object.freeze({
      resourceId: resource,
      message,
      bytes: encodeMessage(message),
      itemIds: Object.freeze(items.map((i) => i.itemId)),
    });
  }

  #land(messageId: Uint8Array | undefined): Flight | undefined {
    if (messageId === undefined) return undefined;
    const key = toHex(messageId);
    const flight = this.#flights.get(key);
    if (flight === undefined) return undefined;
    this.#flights.delete(key);
    for (const id of flight.itemIds)
      if (this.#inFlight.get(toHex(id)) === key) this.#inFlight.delete(toHex(id));
    return flight;
  }

  async #retryLater(
    ids: readonly Hash32[],
    reason: RetryReason,
    now: string,
    code?: WireErrorName | bigint,
  ) {
    const writes: StorageWrite[] = [];
    for (const id of ids) {
      const item = await this.#storage.outbound.get(id);
      if (item === undefined) continue;
      writes.push({
        op: "update-outbound",
        itemId: id,
        nextAttempt: this.#retry.nextAttempt({
          item,
          reason,
          now,
          ...(code === undefined ? {} : { code }),
        }),
      });
    }
    await this.#commit(writes);
  }

  /**
   * An ACK (§59): removes the queued items whose IDs it names (field 1),
   * and records them in the Resource's sync state. Items of the
   * acknowledged message it does not name stay queued. Idempotent: a
   * repeated ACK, or one for items already gone, changes nothing.
   */
  async onAck(message: LfcpMessage<"ACK">, now: string): Promise<AckOutcome> {
    const flight = this.#land(message.correlationId);
    const named = message.body.objectIds ?? [];
    const durability = message.body.durable === true ? this.#durability : 0n;
    const requestType = message.body.requestType;
    const acked: Hash32[] = [];
    const below: Hash32[] = [];
    const byResource = new Map<string, Hash32[]>();
    for (const id of named) {
      const item = await this.#storage.outbound.get(id);
      if (item === undefined) continue;
      if (MESSAGE_TYPE[KIND_TYPE[item.kind]] !== requestType) continue;
      if (flight !== undefined && !bytesEqual(item.resourceId, flight.resourceId)) continue;
      if (durability < this.#minimumDurability) {
        below.push(item.itemId);
        continue;
      }
      acked.push(item.itemId);
      const key = toHex(item.resourceId);
      byResource.set(key, [...(byResource.get(key) ?? []), item.itemId]);
      this.#forget(item.itemId);
    }
    const writes: StorageWrite[] = acked.map((itemId) => ({ op: "dequeue", itemId }));
    for (const ids of byResource.values()) {
      const resourceId = (await this.#storage.outbound.get(ids[0] as Hash32))?.resourceId;
      if (resourceId === undefined) continue;
      const old = await this.#storage.syncState.get(resourceId);
      const recent = [
        ...(old?.recentlyAcked ?? []).filter((x) => !ids.some((i) => bytesEqual(i, x))),
        ...ids,
      ];
      writes.push({
        op: "put-sync-state",
        row: {
          resourceId,
          recentlyAcked: recent.slice(-this.#recentAckLimit),
          ackedDurability: durability,
        },
      });
    }
    await this.#commit(writes);
    const notCovered =
      flight?.itemIds.filter(
        (id) => !acked.some((a) => bytesEqual(a, id)) && !below.some((b) => bytesEqual(b, id)),
      ) ?? [];
    const stillQueued: Hash32[] = [];
    for (const id of [...notCovered, ...below])
      if ((await this.#storage.outbound.get(id)) !== undefined) stillQueued.push(id);
    await this.#retryLater(stillQueued, "not-acked", now);
    return Object.freeze({
      acked: Object.freeze(acked),
      notCovered: Object.freeze(
        notCovered.filter((id) => stillQueued.some((s) => bytesEqual(s, id))),
      ),
      durability,
      belowDurability: Object.freeze(below),
      correlated: flight !== undefined,
    });
  }

  #forget(itemId: Hash32): void {
    const key = toHex(itemId);
    this.#inFlight.delete(key);
    this.#solo.delete(key);
    this.#awaitingControl.delete(key);
  }

  async #block(
    ids: readonly Hash32[],
    reason: OutboundBlock,
    detail: string | null,
  ): Promise<BlockedItem[]> {
    const out: BlockedItem[] = [];
    const writes: StorageWrite[] = [];
    for (const id of ids) {
      const item = await this.#storage.outbound.get(id);
      if (item === undefined) continue;
      writes.push({ op: "update-outbound", itemId: id, blocked: { reason, detail } });
      out.push(Object.freeze({ itemId: item.itemId, kind: item.kind, reason, detail }));
      this.#forget(id);
    }
    await this.#commit(writes);
    return out;
  }

  /**
   * A NACK (§60) of one of this session's messages. Per-object codes on a
   * message of several objects resend each object alone, to learn which one
   * the server meant. Then:
   * STALE_DATA_EPOCH → blocked "stale-epoch" (G-EP5: never resent);
   * ACTOR_EQUIVOCATION → blocked "equivocation", surfaced as an alarm;
   * AUTHORIZATION_FAILED (and other per-object refusals) → blocked "rejected";
   * MESSAGE_TOO_LARGE → blocked "too-large";
   * CONTROL_HEAD_MISMATCH → blocked "repropose" with the current head;
   * MISSING_DEPENDENCY → retried after the next controlSynced();
   * anything else → retried after the RetryPolicy delay.
   */
  async onNack(message: LfcpMessage<"NACK">, now: string): Promise<NackOutcome> {
    const code = CODE_NAMES.get(message.body.code) ?? message.body.code;
    const flight = this.#land(message.correlationId);
    if (flight === undefined) return Object.freeze({ kind: "uncorrelated", code });
    const items: Hash32[] = [];
    for (const id of flight.itemIds)
      if ((await this.#storage.outbound.get(id)) !== undefined) items.push(id);
    const detail = message.body.diagnostic ?? null;

    if (typeof code === "string" && PER_OBJECT.has(code) && items.length > 1) {
      for (const id of items) this.#solo.add(toHex(id));
      return Object.freeze({ kind: "isolating", code, items: Object.freeze(items) });
    }
    switch (code) {
      case "STALE_DATA_EPOCH":
        return Object.freeze({
          kind: "stale",
          items: await this.#block(items, "stale-epoch", detail),
        });
      case "ACTOR_EQUIVOCATION":
        return Object.freeze({
          kind: "equivocation-alarm",
          items: await this.#block(items, "equivocation", detail),
        });
      case "MESSAGE_TOO_LARGE":
        return Object.freeze({
          kind: "rejected",
          code,
          items: await this.#block(items, "too-large", detail),
        });
      case "AUTHORIZATION_FAILED":
      case "INVALID_SIGNATURE":
      case "MALFORMED_MESSAGE":
        return Object.freeze({
          kind: "rejected",
          code,
          items: await this.#block(items, "rejected", detail),
        });
      case "CONTROL_HEAD_MISMATCH": {
        const d = message.body.details;
        const currentHead =
          d instanceof Uint8Array && d.length === 32
            ? (hash32(d) as unknown as ControlRecordId)
            : null;
        const blocked = await this.#block(
          items,
          "repropose",
          currentHead === null ? detail : `current head ${toHex(currentHead)}`,
        );
        return Object.freeze({ kind: "repropose", items: blocked, currentHead });
      }
      case "MISSING_DEPENDENCY":
        for (const id of items) this.#awaitingControl.add(toHex(id));
        return Object.freeze({ kind: "needs-control-sync", items: Object.freeze(items) });
      default:
        await this.#retryLater(items, "transient", now, code);
        return Object.freeze({ kind: "retry", code, items: Object.freeze(items) });
    }
  }

  /**
   * The connection is gone: every message in flight is unanswered, so its
   * items are due again (same bytes, a new message) after the RetryPolicy
   * delay. Returns the affected item IDs.
   */
  async connectionLost(now: string): Promise<Hash32[]> {
    const ids = [...this.#flights.values()].flatMap((f) => f.itemIds);
    this.#flights.clear();
    this.#inFlight.clear();
    await this.#retryLater(ids, "connection-lost", now);
    return ids;
  }

  /** The Control Plane of `resource` was synchronized: items held for MISSING_DEPENDENCY are due again. */
  async controlSynced(resource: ResourceId): Promise<void> {
    for (const item of await this.#storage.outbound.list(resource))
      this.#awaitingControl.delete(toHex(item.itemId));
  }

  /**
   * §88 step 7, G-EP5: with a newly validated Control view, our queued
   * Data Units of a closed epoch beyond its final frontier are never sent;
   * they are blocked "stale-epoch" and surfaced (also when in flight: a
   * later ACK still removes them). Units within the cutoff stay queued and
   * are sent as the same bytes.
   */
  async reconcileEpochs(view: ControlView): Promise<StaleOutboundUnit[]> {
    const out: StaleOutboundUnit[] = [];
    const writes: StorageWrite[] = [];
    for (const item of await this.#storage.outbound.list(view.state.resourceId)) {
      if (item.kind !== "data-unit" || item.blocked !== null) continue;
      const unit = await this.#storage.dataUnits.get(dataUnitId(item.itemId));
      if (unit === undefined) continue;
      const c = classifyDataUnit(view, unit);
      if (c.kind !== "quarantine") continue;
      writes.push({
        op: "update-outbound",
        itemId: item.itemId,
        blocked: { reason: "stale-epoch", detail: c.reason },
      });
      this.#solo.delete(toHex(item.itemId));
      out.push(
        Object.freeze({
          itemId: item.itemId,
          kind: item.kind,
          reason: "stale-epoch",
          detail: c.reason,
          actor: unit.actor,
          seq: unit.actorSeq,
          epoch: unit.dataEpoch,
        }),
      );
    }
    await this.#commit(writes);
    return out;
  }

  /** Removes a blocked item once the application has dealt with it (e.g. re-proposed or re-applied). */
  async discard(itemId: Hash32): Promise<void> {
    const item = await this.#storage.outbound.get(itemId);
    if (item === undefined) return;
    if (item.blocked === null)
      throw new Error("only a blocked item can be discarded; an unsent object would be lost");
    this.#forget(itemId);
    await this.#commit([{ op: "dequeue", itemId }]);
  }
}

/** A Resource's sync state: Have-based, never a global cursor. */
export interface ResourceSyncState {
  /** The accepted Data Units this client holds (§28), ours included. */
  readonly have: HaveVector;
  /** Queued items still to be sent or answered. */
  readonly outstanding: readonly OutboundItem[];
  /** Queued items that will not be sent again, until discarded. */
  readonly blocked: readonly OutboundItem[];
  readonly recentlyAcked: readonly Hash32[];
  readonly ackedDurability: bigint | null;
}

/** The sync state of `resource` from storage alone (valid after a restart). */
export async function resourceSyncState(
  storage: Pick<LfcpStorage, "outbound" | "dataUnits" | "syncState" | "snapshots">,
  resource: ResourceId,
): Promise<ResourceSyncState> {
  // Units held through a stored (loaded or published) Snapshot count too (§29).
  let have: HaveVector = await snapshotFrontier(storage, resource);
  for (const status of ["merged", "profile-pending", "profile-rejected"] as const)
    for (const u of await storage.dataUnits.withStatus(resource, status))
      if (u.accepted) have = addSequence(have, u.actor, u.actorSeq);
  const items = await storage.outbound.list(resource);
  const sync = await storage.syncState.get(resource);
  return Object.freeze({
    have,
    outstanding: Object.freeze(items.filter((i) => i.blocked === null)),
    blocked: Object.freeze(items.filter((i) => i.blocked !== null)),
    recentlyAcked: sync?.recentlyAcked ?? [],
    ackedDurability: sync?.ackedDurability ?? null,
  });
}

/** The union of the frontiers of the Snapshots stored for `resource` (those loaded or published here). */
export async function snapshotFrontier(
  storage: Pick<LfcpStorage, "snapshots">,
  resource: ResourceId,
): Promise<HaveVector> {
  let have: HaveVector = [];
  for (const s of await storage.snapshots.list(resource))
    have = unionHaves(have, canonicalFrontierFromCbor(decodeDeterministic(s.frontier)));
  return have;
}
