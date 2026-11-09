import { type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import { decodeControlRecord, parseKeyPackage, signControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { deliverKeys, heldDeks, syncChain } from "../../src/identity/context.js";
import { getPendingDek, OperationJournal, PackageLedger } from "../../src/identity/journal.js";
import { ChannelPool, IdentityUnavailable } from "../../src/identity/network.js";
import {
  abandonDelivery,
  outstandingDeliveries,
  resumeRotations,
  retryDelivery,
  rotateAfter,
} from "../../src/identity/rotation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { hostResource, type Node, node, world } from "./world.js";

// "Stop trying" (design 419 (c), decision I31): an owed delivery that keeps
// being refused can be abandoned. resumeRotations no longer resumes it and
// outstandingDeliveries lists it only with includeAbandoned; retryDelivery
// makes it owed again. A rotation whose key is still pending (a lost answer
// to its KEY_EPOCH, §9.1) cannot be abandoned.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

const hasKey = (server: MemoryCoordinator, R: ResourceId, who: PrincipalId, epoch: bigint) =>
  server.packagesOf(R).some((p) => hex(p.recipient) === hex(who) && p.dataEpoch === epoch);

/** P's section Y shared with Q (party 9), Q's key sealed. */
async function shared() {
  const w = await world(0);
  const Q = node(w.server, party(9));
  const Y = (await hostResource(w.server, w.P)).resource;
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  const y0 = await syncChain(w.P.storage, channel, Y);
  const grant = signControlRecord(
    { resourceId: Y, controlSeq: y0.state.seq + 1n, prevControlId: y0.state.head },
    {
      type: "CAPABILITY_GRANT",
      subject: Q.installation.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    },
    w.P.installation.signer,
  ).bytes;
  expect((await channel.putControl(Y, y0.state.head, grant)).kind).toBe("ack");
  const y1 = await syncChain(w.P.storage, channel, Y);
  await deliverKeys({
    channel,
    ledger: new PackageLedger(w.P.storage),
    chain: y1,
    sender: w.P.installation.signer,
    recipients: [Q.installation.signer.descriptor],
    deks: await heldDeks(w.P.secrets, y1),
  });
  return { w, Y };
}

/** P rotates Y under `operation`; Q's package is refused (QUOTA_EXCEEDED): its delivery stays owed. */
async function refusedRotation(
  server: MemoryCoordinator,
  P: Node,
  Y: ResourceId,
  operation: string,
) {
  await new OperationJournal(P.storage).begin({
    id: operation,
    kind: "rotate",
    createdAt: 1,
    intent: {},
  });
  server.fault = (e) =>
    e.op === "key-package" && hex(parseKeyPackage(e.bytes).payload.recipient) === hex(id(9))
      ? { nack: "QUOTA_EXCEEDED" }
      : undefined;
  const channel = await P.network.connect(P.installation.signer, URL);
  const chain = await syncChain(P.storage, channel, Y);
  const r = await rotateAfter({
    ...P,
    channel,
    operation,
    resource: Y,
    revokedAt: chain.state.seq,
  });
  expect(r.keys?.skipped.map((s) => s.recipient)).toEqual([hex(id(9))]);
  return server.chain(Y).state.epoch.epoch;
}

const resume = async (P: Node) => {
  const pool = new ChannelPool(P.network);
  try {
    return await resumeRotations({ ...P, pool });
  } finally {
    pool.closeAll();
  }
};

describe("abandonDelivery and retryDelivery", { timeout: 120_000 }, () => {
  test("an abandoned delivery is neither resumed nor listed; retried, it is delivered", async () => {
    const { w, Y } = await shared();
    const epoch = await refusedRotation(w.server, w.P, Y, "rotate.y");
    expect((await outstandingDeliveries(w.P)).map((o) => o.recipients)).toEqual([[hex(id(9))]]);
    expect(await abandonDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe("abandoned");
    expect(await abandonDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe("abandoned");
    expect(await outstandingDeliveries(w.P)).toEqual([]);
    const listed = await outstandingDeliveries(w.P, { includeAbandoned: true });
    expect(listed.map((o) => [o.abandoned, o.recipients])).toEqual([[true, [hex(id(9))]]]);
    // The server would now take the package: an abandoned delivery is still not resumed.
    w.server.fault = () => undefined;
    const before = w.server.uploads.length;
    expect(await resume(w.P)).toEqual([]);
    expect(w.server.uploads.length).toBe(before);
    expect(hasKey(w.server, Y, id(9), epoch)).toBe(false);
    // Try again: owed, resumed, delivered, done.
    expect(await retryDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe(true);
    expect(await retryDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe(false);
    expect((await resume(w.P)).map((o) => o.status)).toEqual(["rotated"]);
    expect(hasKey(w.server, Y, id(9), epoch)).toBe(true);
    expect(await outstandingDeliveries(w.P, { includeAbandoned: true })).toEqual([]);
  });

  test("a rotation whose key is still pending cannot be abandoned, and is resumed", async () => {
    const { w, Y } = await shared();
    await new OperationJournal(w.P.storage).begin({
      id: "rotate.lost",
      kind: "rotate",
      createdAt: 1,
      intent: {},
    });
    w.server.fault = (e) =>
      e.op === "control" && decodeControlRecord(e.bytes).body.type === "KEY_EPOCH"
        ? "drop-answer"
        : undefined;
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    const chain = await syncChain(w.P.storage, channel, Y);
    await expect(
      rotateAfter({
        ...w.P,
        channel,
        operation: "rotate.lost",
        resource: Y,
        revokedAt: chain.state.seq,
      }),
    ).rejects.toThrow(IdentityUnavailable);
    w.server.fault = () => undefined;
    expect(await abandonDelivery({ ...w.P, operation: "rotate.lost", resource: Y })).toBe(
      "pending",
    );
    expect((await resume(w.P)).map((o) => o.status)).toEqual(["rotated"]);
    expect(hasKey(w.server, Y, id(9), w.server.chain(Y).state.epoch.epoch)).toBe(true);
  });

  test("nothing owed: not-owed; a 0.5.1 journal row (no abandoned state) loads and resumes", async () => {
    const { w, Y } = await shared();
    expect(await abandonDelivery({ ...w.P, operation: "rotate.none", resource: Y })).toBe(
      "not-owed",
    );
    expect(await retryDelivery({ ...w.P, operation: "rotate.none", resource: Y })).toBe(false);
    await refusedRotation(w.server, w.P, Y, "rotate.old");
    w.server.fault = () => undefined;
    // A row as 0.5.1 writes it: delivery outstanding, nothing else new.
    expect((await outstandingDeliveries(w.P)).length).toBe(1);
    expect((await resume(w.P)).map((o) => o.status)).toEqual(["rotated"]);
  });
});

// Review 419 round 2, P3-1 and P3-2 (the reviewer's probes C2 and C1).
describe("abandon and a rotation of the same phase in flight (review 419 P3-1, P3-2)", {
  timeout: 120_000,
}, () => {
  test("C2: abandoned while a resume of the phase waits on the network: it stays abandoned", async () => {
    const { w, Y } = await shared();
    await refusedRotation(w.server, w.P, Y, "rotate.y");
    // The resume is held at its first network call until the abandon is written.
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let armed = true;
    const network = {
      connect: async (...a: Parameters<typeof w.P.network.connect>) => {
        const ch = await w.P.network.connect(...a);
        return new Proxy(ch, {
          get(t, k, r) {
            const v = Reflect.get(t, k, r) as unknown;
            if (typeof v !== "function") return v;
            return async (...args: unknown[]) => {
              if (armed) {
                armed = false;
                await gate;
              }
              return (v as (...x: unknown[]) => unknown).apply(t, args);
            };
          },
        });
      },
    } as typeof w.P.network;
    const pool = new ChannelPool(network);
    const resuming = resumeRotations({ ...w.P, network, pool });
    await new Promise((r) => setTimeout(r, 50));
    expect(await abandonDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe("abandoned");
    release();
    await resuming;
    pool.closeAll();
    const op = await new OperationJournal(w.P.storage).get("rotate.y");
    expect(op?.phases.find((p) => p.id.startsWith("rotate:"))?.facts?.delivery).toBe("abandoned");
    expect(await outstandingDeliveries(w.P)).toEqual([]);
  });

  test("C1: an abandoned phase rotated again, its KEY_EPOCH answer lost: the new key is adopted and handed on", async () => {
    const { w, Y } = await shared();
    await refusedRotation(w.server, w.P, Y, "rotate.y");
    expect(await abandonDelivery({ ...w.P, operation: "rotate.y", resource: Y })).toBe("abandoned");
    w.server.fault = (e) =>
      e.op === "control" && decodeControlRecord(e.bytes).body.type === "KEY_EPOCH"
        ? "drop-answer"
        : undefined;
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    const chain = await syncChain(w.P.storage, channel, Y);
    await expect(
      rotateAfter({
        ...w.P,
        channel,
        operation: "rotate.y",
        resource: Y,
        revokedAt: chain.state.seq,
      }),
    ).rejects.toThrow(IdentityUnavailable);
    w.server.fault = () => undefined;
    const epoch = w.server.chain(Y).state.epoch.epoch;
    const op = await new OperationJournal(w.P.storage).get("rotate.y");
    // The new key change is not the abandoned one.
    expect(op?.phases.find((p) => p.id.startsWith("rotate:"))?.facts?.delivery).toBeUndefined();
    expect(await getPendingDek(w.P.secrets, Y, "rotate.y")).toBeDefined();
    expect((await resume(w.P)).map((o) => o.status)).toEqual(["rotated"]);
    expect(await getPendingDek(w.P.secrets, Y, "rotate.y")).toBeUndefined();
    expect((await heldDeks(w.P.secrets, w.server.chain(Y))).has(String(epoch))).toBe(true);
    expect(hasKey(w.server, Y, id(9), epoch)).toBe(true);
  });
});

// Review 418r2 R3: the delivery mark's read-modify-write is atomic against abandonDelivery.
describe("abandon at the journal's write boundary (review 418r2 R3)", { timeout: 120_000 }, () => {
  test("abandoned while the resume writes the phase row: the abandon is not overwritten", async () => {
    const { w, Y } = await shared();
    await refusedRotation(w.server, w.P, Y, "rotate.y");
    const base = w.P.storage;
    let abandoning: Promise<string> | undefined;
    let inAbandon = false;
    // One storage object for both callers (the journal's queue is per storage).
    const storage: typeof base = new Proxy(base, {
      get(t, k) {
        if (k === "commit")
          return async (writes: Parameters<typeof base.commit>[0]) => {
            const row = writes.find(
              (x) => x.op === "put-local-mark" && x.key === "identity-op:rotate.y",
            );
            // The resume's first write of the row: its value is built; abandon starts now and
            // gets every chance to finish before this commit lands.
            if (row !== undefined && abandoning === undefined && !inAbandon) {
              inAbandon = true;
              abandoning = abandonDelivery({
                ...w.P,
                storage,
                operation: "rotate.y",
                resource: Y,
              });
              await new Promise((r) => setTimeout(r, 50));
            }
            return t.commit(writes);
          };
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const pool = new ChannelPool(w.P.network);
    await resumeRotations({ ...w.P, storage, pool });
    pool.closeAll();
    expect(abandoning).toBeDefined();
    expect(await abandoning).toBe("abandoned");
    const op = await new OperationJournal(base).get("rotate.y");
    expect(op?.phases.find((p) => p.id.startsWith("rotate:"))?.facts?.delivery).toBe("abandoned");
    expect(await outstandingDeliveries({ ...w.P, storage: base })).toEqual([]);
  });
});
