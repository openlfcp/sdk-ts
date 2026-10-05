import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  type Hash32,
  hash32,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  createMessage,
  type DataProfileCodec,
  decodeMessage,
  ERROR_CODE,
  type LfcpMessage,
  MESSAGE_TYPE,
  parseDataUnit,
  principalDescriptorFromKeys,
  replyTo,
  rotateEpoch,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  createQueuedDataUnit,
  createQueuedSnapshot,
  exponentialBackoff,
  type OutboundMessage,
  OutboundQueue,
  queueControlRecord,
  queueKeyPackage,
  type RetryPolicy,
  resourceSyncState,
} from "../src/index.js";

// The outbound queue with a fake transport: messages are taken from
// next(), and ACK/NACK replies are built by hand. Time is a string the
// test passes in; nothing sleeps.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const WRITER = signer(33);
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));
const T0 = "2026-10-05T12:00:00.000Z";
const T1 = "2026-10-05T12:00:01.000Z";
const T9 = "2026-10-05T13:00:00.000Z";

type Linear = Extract<ChainResult, { kind: "linear" }>;

/** A Resource whose owner granted WRITER data/write and snapshot/publish. */
function chainFor(seed: number) {
  const R = resourceId(bytes32(seed));
  const records: Uint8Array[] = [];
  let head: ControlRecordId | null = null;
  const add = (body: ControlBody) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
      body,
      OWNER,
    );
    records.push(s.bytes);
    head = s.recordId;
    return s;
  };
  add({
    type: "GENESIS",
    dataProfile: PROFILE,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  });
  add({
    type: "CAPABILITY_GRANT",
    subject: WRITER.descriptor,
    abilities: [1n, 2n, 3n],
    delegable: [],
  });
  const view = (extra: readonly Uint8Array[] = []): Linear => {
    const r = validateControlChain([...records, ...extra]);
    if (r.kind !== "linear") throw new Error(r.kind);
    return r;
  };
  return { R, records, add, view };
}

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (p) => String.fromCharCode(...p),
};

/** A writer with its storage and N queued units ("v1", "v2", …). */
async function writer(seed = 200, n = 2) {
  const storage = new InMemoryLfcpStorage();
  const c = chainFor(seed);
  const view = c.view();
  const units: { bytes: Uint8Array; unitId: DataUnitId }[] = [];
  for (let i = 1; i <= n; i++)
    units.push(
      await createQueuedDataUnit(storage, {
        view,
        controlHead: view.state.head,
        actor: WRITER,
        dek: DEK0,
        profile: TEXT,
        previousUnitId: units.at(-1)?.unitId ?? null,
        value: `v${i}`,
      }),
    );
  return { storage, ...c, units };
}

const ids = (m: OutboundMessage) => m.itemIds.map(toHex);
const hex = (id: Uint8Array) => toHex(id);
const ack = (
  m: OutboundMessage,
  objectIds: readonly Uint8Array[],
  durable?: boolean,
): LfcpMessage<"ACK"> =>
  replyTo(m.message, "ACK", {
    requestType: MESSAGE_TYPE[m.message.type as "DATA_PUT"],
    objectIds: objectIds.map((i) => hash32(i)),
    ...(durable === undefined ? {} : { durable }),
  });
const nack = (
  m: OutboundMessage,
  code: keyof typeof ERROR_CODE,
  details?: Uint8Array,
): LfcpMessage<"NACK"> =>
  replyTo(m.message, "NACK", {
    code: ERROR_CODE[code],
    diagnostic: code,
    ...(details === undefined ? {} : { details }),
  });

/** Records every retry decision; schedules nothing (at once). */
function recordingPolicy(): RetryPolicy & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    nextAttempt: ({ reason, code }) => {
      calls.push(code === undefined ? reason : `${reason}:${String(code)}`);
      return null;
    },
  };
}

describe("OutboundQueue (LFCP-036)", () => {
  it("1, 2, 7. sends the exact queued bytes and removes an item only when an ACK names it", async () => {
    const { storage, R, units } = await writer();
    const q = new OutboundQueue({ storage });
    const [m] = await q.next(R, T0);
    expect(m?.message.type).toBe("DATA_PUT");
    const decoded = decodeMessage(m?.bytes as Uint8Array);
    expect(decoded.type === "DATA_PUT" && decoded.body.objects.map(hex)).toEqual(
      units.map((u) => hex(u.bytes)),
    );
    expect((await storage.outbound.list(R)).map((o) => o.attempts)).toEqual([1, 1]);
    // In flight: not offered again until answered.
    expect(await q.next(R, T0)).toEqual([]);
    const r = await q.onAck(ack(m as OutboundMessage, [units[0]?.unitId as DataUnitId]), T0);
    expect(r).toMatchObject({ correlated: true, durability: 0n });
    expect(r.acked.map(hex)).toEqual([hex(units[0]?.unitId as DataUnitId)]);
    expect(r.notCovered.map(hex)).toEqual([hex(units[1]?.unitId as DataUnitId)]);
    expect((await storage.outbound.list(R)).map((o) => hex(o.itemId))).toEqual([
      hex(units[1]?.unitId as DataUnitId),
    ]);
    // The unit itself stays stored, merged and accepted.
    expect(await storage.dataUnits.get(units[0]?.unitId as DataUnitId)).toMatchObject({
      status: "merged",
      accepted: true,
    });
  });

  it("8, 9. a repeated ACK is harmless and an ACK of other objects clears nothing", async () => {
    const { storage, R, units } = await writer();
    const q = new OutboundQueue({ storage });
    const [m] = await q.next(R, T0);
    const a = ack(
      m as OutboundMessage,
      units.map((u) => u.unitId),
    );
    expect((await q.onAck(a, T0)).acked).toHaveLength(2);
    expect(await q.onAck(a, T0)).toMatchObject({ acked: [], correlated: false });
    // A fresh unit, and an ACK naming something else or the wrong request type.
    const c = chainFor(200);
    const view = c.view();
    const u3 = await createQueuedDataUnit(storage, {
      view,
      controlHead: view.state.head,
      actor: WRITER,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: units[1]?.unitId as DataUnitId,
      value: "v3",
    });
    const [m3] = await q.next(R, T0);
    expect((await q.onAck(ack(m3 as OutboundMessage, [bytes32(7)]), T0)).acked).toEqual([]);
    const wrongType = replyTo((m3 as OutboundMessage).message, "ACK", {
      requestType: MESSAGE_TYPE.SNAPSHOT_PUT,
      objectIds: [hash32(u3.unitId)],
    });
    expect((await q.onAck(wrongType, T0)).acked).toEqual([]);
    expect((await storage.outbound.list(R)).map((o) => hex(o.itemId))).toEqual([hex(u3.unitId)]);
    // An ACK that matches by object ID after a restart (no correlation) still clears it.
    const restarted = new OutboundQueue({ storage });
    const late = createMessage("ACK", {
      requestType: MESSAGE_TYPE.DATA_PUT,
      objectIds: [hash32(u3.unitId)],
    });
    expect(await restarted.onAck(late, T0)).toMatchObject({
      correlated: false,
      acked: [hash32(u3.unitId)],
    });
  });

  it("3, 5, 6, 10, 13. a lost connection resends the same bytes in a new message, after the backoff hook", async () => {
    const { storage, R, units } = await writer();
    const policy = exponentialBackoff(1000, 60_000);
    const calls: string[] = [];
    const q = new OutboundQueue({
      storage,
      retry: {
        nextAttempt: (f) => {
          calls.push(f.reason);
          return policy.nextAttempt(f);
        },
      },
    });
    const [first] = await q.next(R, T0);
    expect(await q.connectionLost(T0)).toHaveLength(2);
    expect(calls).toEqual(["connection-lost", "connection-lost"]);
    // Not due before the backoff time; the caller decides when to ask again.
    expect(await q.next(R, T0)).toEqual([]);
    const [again] = await q.next(R, T1);
    expect(hex((again as OutboundMessage).message.messageId)).not.toBe(
      hex((first as OutboundMessage).message.messageId),
    );
    expect(ids(again as OutboundMessage)).toEqual(ids(first as OutboundMessage));
    const a = decodeMessage((again as OutboundMessage).bytes);
    expect(a.type === "DATA_PUT" && a.body.objects.map(hex)).toEqual(
      units.map((u) => hex(u.bytes)),
    );
    expect((await storage.outbound.list(R)).map((o) => [o.attempts, o.nextAttempt])).toEqual([
      [2, "2026-10-05T12:00:01.000Z"],
      [2, "2026-10-05T12:00:01.000Z"],
    ]);
  });

  it("retransmits after a request timeout on a live connection, with bounded backoff (§70)", async () => {
    const { storage, R, units } = await writer();
    const policy = recordingPolicy();
    const q = new OutboundQueue({
      storage,
      retry: policy,
      requestTimeout: { baseMs: 1000, maxMs: 3000 },
    });
    const at = (ms: number) => new Date(Date.parse(T0) + ms).toISOString();
    const [first] = (await q.next(R, T0)) as OutboundMessage[];
    // The request or its ACK is lost; the connection stays up.
    expect(await q.next(R, at(999))).toEqual([]);
    const [second] = (await q.next(R, at(1000))) as OutboundMessage[];
    expect(policy.calls).toEqual(["timeout", "timeout"]); // once per item of the flight
    expect(toHex(second?.bytes ?? new Uint8Array())).not.toBe(
      toHex(first?.bytes ?? new Uint8Array()),
    );
    expect(second?.message.type === "DATA_PUT" && second.message.body.objects.map(toHex)).toEqual(
      units.map((u) => toHex(u.bytes)),
    ); // a new message around the very same unit bytes
    // The next wait doubles (2 s), then is capped (3 s).
    expect(await q.next(R, at(1000 + 1999))).toEqual([]);
    const [third] = (await q.next(R, at(3000))) as OutboundMessage[];
    expect(third).toBeDefined();
    expect(await q.next(R, at(3000 + 2999))).toEqual([]);
    expect(await q.next(R, at(6000))).toHaveLength(1);
    // A late ACK of the first message still removes the items it names.
    const r = await q.onAck(
      ack(
        first as OutboundMessage,
        units.map((u) => u.unitId),
      ),
      at(6001),
    );
    expect(r.acked).toHaveLength(2);
    expect(await storage.outbound.list(R)).toEqual([]);
  });

  it("4, 11. a restarted queue resends the stored bytes; no unit or sequence is created again", async () => {
    const { storage, R, units } = await writer();
    await new OutboundQueue({ storage }).next(R, T0); // sent, then the process "dies"
    const before = await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId);
    expect(before).toBe(3n);
    const [m] = await new OutboundQueue({ storage }).next(R, T0);
    const d = decodeMessage((m as OutboundMessage).bytes);
    expect(
      d.type === "DATA_PUT" && d.body.objects.map((b) => parseDataUnit(b).payload.actorSeq),
    ).toEqual([1n, 2n]);
    expect(d.type === "DATA_PUT" && d.body.objects.map(hex)).toEqual(
      units.map((u) => hex(u.bytes)),
    );
    expect(await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId)).toBe(4n);
  });

  it("counts ACK durability only up to READY's level", async () => {
    const { storage, R, units } = await writer(200, 1);
    const q = new OutboundQueue({ storage, minimumDurability: 2n });
    q.session({ durability: 1n, maxMessageBytes: 1_000_000n });
    const [m] = await q.next(R, T0);
    const r = await q.onAck(ack(m as OutboundMessage, [units[0]?.unitId as DataUnitId], true), T0);
    expect(r).toMatchObject({ durability: 1n, acked: [] });
    expect(r.belowDurability).toHaveLength(1);
    expect(await storage.outbound.list(R)).toHaveLength(1);
    q.session({ durability: 3n, maxMessageBytes: 1_000_000n });
    const [m2] = await q.next(R, T0);
    expect(
      (await q.onAck(ack(m2 as OutboundMessage, [units[0]?.unitId as DataUnitId], false), T0))
        .acked,
    ).toEqual([]);
    const [m3] = await q.next(R, T0);
    expect(
      (await q.onAck(ack(m3 as OutboundMessage, [units[0]?.unitId as DataUnitId], true), T0))
        .durability,
    ).toBe(3n);
    expect(await storage.outbound.list(R)).toEqual([]);
    expect(await storage.syncState.get(R)).toMatchObject({
      ackedDurability: 3n,
      recentlyAcked: [hash32(units[0]?.unitId as DataUnitId)],
    });
  });

  it("isolates a per-object NACK, then blocks only the stale unit (STALE_DATA_EPOCH, G-EP5)", async () => {
    const { storage, R, units } = await writer(200, 3);
    const q = new OutboundQueue({ storage });
    const [m] = await q.next(R, T0);
    expect(await q.onNack(nack(m as OutboundMessage, "STALE_DATA_EPOCH"), T0)).toMatchObject({
      kind: "isolating",
    });
    const solo = await q.next(R, T0);
    expect(solo.map((x) => x.itemIds.length)).toEqual([1, 1, 1]);
    const r = await q.onNack(nack(solo[2] as OutboundMessage, "STALE_DATA_EPOCH"), T0);
    expect(r).toMatchObject({
      kind: "stale",
      items: [{ reason: "stale-epoch", kind: "data-unit" }],
    });
    for (const s of solo.slice(0, 2)) await q.onAck(ack(s, s.itemIds), T0);
    const state = await resourceSyncState(storage, R);
    expect(state.outstanding).toEqual([]);
    expect(state.blocked.map((b) => [hex(b.itemId), b.blocked?.reason])).toEqual([
      [hex(units[2]?.unitId as DataUnitId), "stale-epoch"],
    ]);
    // Blocked items are never offered again, until discarded.
    expect(await q.next(R, T9)).toEqual([]);
    await q.discard(units[2]?.unitId as unknown as Hash32);
    expect(await storage.outbound.list(R)).toEqual([]);
  });

  it("surfaces ACTOR_EQUIVOCATION as an alarm and AUTHORIZATION_FAILED as a final rejection", async () => {
    const { storage, R } = await writer(200, 1);
    const q = new OutboundQueue({ storage });
    const [m] = await q.next(R, T0);
    expect(await q.onNack(nack(m as OutboundMessage, "ACTOR_EQUIVOCATION"), T0)).toMatchObject({
      kind: "equivocation-alarm",
      items: [{ reason: "equivocation" }],
    });
    const other = await writer(201, 1);
    const q2 = new OutboundQueue({ storage: other.storage });
    const [m2] = await q2.next(other.R, T0);
    expect(await q2.onNack(nack(m2 as OutboundMessage, "AUTHORIZATION_FAILED"), T0)).toMatchObject({
      kind: "rejected",
      code: "AUTHORIZATION_FAILED",
      items: [{ reason: "rejected" }],
    });
    expect(await q2.next(other.R, T9)).toEqual([]);
    await expect(q2.discard(hash32(bytes32(5)))).resolves.toBeUndefined();
  });

  it("holds MISSING_DEPENDENCY until a Control sync and retries transient codes after the hook", async () => {
    const { storage, R } = await writer(200, 1);
    const policy = recordingPolicy();
    const q = new OutboundQueue({ storage, retry: policy });
    const [m] = await q.next(R, T0);
    expect(await q.onNack(nack(m as OutboundMessage, "MISSING_DEPENDENCY"), T0)).toMatchObject({
      kind: "needs-control-sync",
    });
    expect(await q.next(R, T9)).toEqual([]);
    await q.controlSynced(R);
    const [m2] = await q.next(R, T0);
    expect(await q.onNack(nack(m2 as OutboundMessage, "RATE_LIMITED"), T0)).toMatchObject({
      kind: "retry",
      code: "RATE_LIMITED",
    });
    const unknown = replyTo((m2 as OutboundMessage).message, "NACK", { code: 99n });
    expect(await q.onNack(unknown, T0)).toMatchObject({ kind: "uncorrelated" });
    const [m3] = await q.next(R, T0);
    expect(
      await q.onNack(replyTo((m3 as OutboundMessage).message, "NACK", { code: 99n }), T0),
    ).toMatchObject({
      kind: "retry",
      code: 99n,
    });
    expect(policy.calls).toEqual(["transient:RATE_LIMITED", "transient:99"]);
  });

  it("re-proposes a Control Record whose expected head moved, never resending it blindly", async () => {
    const { storage, R, records, view } = await writer(200, 0);
    const v = view();
    const rotation = rotateEpoch(v.state, OWNER, { reason: 0n, finalFrontier: [], dek: DEK1 });
    const id = await queueControlRecord(storage, rotation.bytes);
    expect(hex(id)).toBe(hex(rotation.recordId));
    const q = new OutboundQueue({ storage });
    const [m] = await q.next(R, T0);
    expect(m?.message.type).toBe("CONTROL_PUT");
    expect(m?.message.type === "CONTROL_PUT" && hex(m.message.body.expectedHead)).toBe(
      hex(v.state.head),
    );
    const current = bytes32(77);
    const r = await q.onNack(nack(m as OutboundMessage, "CONTROL_HEAD_MISMATCH", current), T0);
    expect(
      r.kind === "repropose" && [hex(r.currentHead as Uint8Array), r.items[0]?.reason],
    ).toEqual([hex(current), "repropose"]);
    expect(await q.next(R, T9)).toEqual([]);
    expect(records).toHaveLength(2);
  });

  it("§88 step 7: our queued units beyond a new epoch's cutoff are never sent; units within it are", async () => {
    const { storage, R, units, view } = await writer(200, 3);
    const v = view();
    const rotation = rotateEpoch(v.state, OWNER, {
      reason: 1n,
      finalFrontier: [{ principalId: WRITER.descriptor.principalId, contiguous: 1n, extras: [] }],
      dek: DEK1,
    });
    const q = new OutboundQueue({ storage });
    const stale = await q.reconcileEpochs(view([rotation.bytes]));
    expect(stale.map((s) => [s.seq, s.detail])).toEqual([
      [2n, "BEYOND_CUTOFF"],
      [3n, "BEYOND_CUTOFF"],
    ]);
    const sent = await q.next(R, T0);
    const d = decodeMessage((sent[0] as OutboundMessage).bytes);
    expect(d.type === "DATA_PUT" && d.body.objects.map(hex)).toEqual([
      hex(units[0]?.bytes as Uint8Array),
    ]);
    expect(await q.reconcileEpochs(view([rotation.bytes]))).toEqual([]);
  });

  it("12. a sequence reserved before a crash is skipped, never reused, and never queued twice", async () => {
    const { storage, R, view } = await writer(200, 1);
    // A reservation whose unit never got stored (the process died in between).
    expect(await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId)).toBe(2n);
    const v = view();
    const next = await createQueuedDataUnit(storage, {
      view: v,
      controlHead: v.state.head,
      actor: WRITER,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "after",
    }).catch((e: unknown) => e);
    // Sequence 3 with a null previous unit is refused before sealing (§26.2); nothing was queued.
    expect(next).toMatchObject({ code: "INVALID_STRUCTURE" });
    expect(await storage.outbound.list(R)).toHaveLength(1);
    expect(await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId)).toBe(4n);
  });

  it("14. keeps several Resources' queues and sync states apart", async () => {
    const storage = new InMemoryLfcpStorage();
    const a = chainFor(210);
    const b = chainFor(220);
    for (const c of [a, b]) {
      const v = c.view();
      await createQueuedDataUnit(storage, {
        view: v,
        controlHead: v.state.head,
        actor: WRITER,
        dek: DEK0,
        profile: TEXT,
        previousUnitId: null,
        value: "x",
      });
    }
    const q = new OutboundQueue({ storage });
    const [ma] = await q.next(a.R, T0);
    expect(await q.next(a.R, T0)).toEqual([]);
    const [mb] = await q.next(b.R, T0);
    expect(mb).toBeDefined();
    await q.onAck(ack(ma as OutboundMessage, (ma as OutboundMessage).itemIds), T0);
    expect(await storage.outbound.list(a.R)).toEqual([]);
    expect(await storage.outbound.list(b.R)).toHaveLength(1);
    expect((await resourceSyncState(storage, a.R)).recentlyAcked).toHaveLength(1);
    expect((await resourceSyncState(storage, b.R)).recentlyAcked).toHaveLength(0);
    expect((await resourceSyncState(storage, a.R)).have).toEqual([
      { principalId: WRITER.descriptor.principalId, contiguous: 1n, extras: [] },
    ]);
  });

  it("queues Key Packages and Snapshots by their exact bytes and orders Control first", async () => {
    const { storage, R, view } = await writer(200, 1);
    const v = view();
    const kp = await sealKeyPackage({
      resourceId: R,
      epoch: dataEpoch(0n),
      controlHead: v.state.head,
      recipient: OWNER.descriptor,
      dek: DEK0,
      signer: WRITER,
    });
    const kpId = await queueKeyPackage(storage, kp.bytes);
    expect((await storage.keyPackages.get(kpId))?.bytes).toEqual(kp.bytes);
    const snap = await createQueuedSnapshot(storage, {
      view: v,
      controlHead: v.state.head,
      publisher: WRITER,
      dek: DEK0,
      frontier: [{ principalId: WRITER.descriptor.principalId, contiguous: 1n }],
      profile: TEXT,
      value: "state",
    });
    expect((await storage.snapshots.get(snap.snapshotId))?.bytes).toEqual(snap.bytes);
    const rotation = rotateEpoch(v.state, OWNER, { reason: 0n, finalFrontier: [], dek: DEK1 });
    await queueControlRecord(storage, rotation.bytes);
    const q = new OutboundQueue({ storage });
    const sent = await q.next(R, T0);
    expect(sent.map((m) => m.message.type)).toEqual([
      "CONTROL_PUT",
      "KEY_PACKAGE_PUT",
      "DATA_PUT",
      "SNAPSHOT_PUT",
    ]);
    for (const m of sent) await q.onAck(ack(m, m.itemIds), T0);
    expect(await storage.outbound.list(R)).toEqual([]);
  });

  it("blocks an object too large for the session's message limit instead of sending it", async () => {
    const { storage, R } = await writer(200, 1);
    const q = new OutboundQueue({ storage });
    q.session({ durability: 2n, maxMessageBytes: 1100n });
    expect(await q.next(R, T0)).toEqual([]);
    expect((await storage.outbound.list(R))[0]?.blocked?.reason).toBe("too-large");
  });
});
