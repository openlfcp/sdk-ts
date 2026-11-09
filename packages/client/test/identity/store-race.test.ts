import { type ResourceId, toHex } from "@openlfcp/core";
import { decodeControlRecord, signControlRecord, validateControlChain } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  ControlChainBusy,
  ControlChainDiverged,
  extendChain,
  IdentityConflict,
  syncChain,
} from "../../src/identity/context.js";
import type { IdentityChannel, IdentityNetwork } from "../../src/identity/network.js";
import { IdentityUnavailable } from "../../src/identity/network.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { revokeDevice, rotateIfExposed } from "../../src/identity/revocation.js";
import { loadControlChain, saveControlChain } from "../../src/storage.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { device, party, URL } from "./support.js";
import { type Node, pair, world } from "./world.js";

// Review 414c / decision I29: the local compare-and-set race of storeChain.
// An identity flow has a record ACKed and stores the chain it extends; an open
// session of the same Resource on the same storage receives that record from
// the coordinator (W §47 pushes it) and stores it first. Before 0.5.2 the flow
// then threw "the Control Chain was not stored: CONTROL_HEAD_MISMATCH" (a plain
// Error), although the stored chain already held its record. Reproduced
// deterministically: right after the coordinator ACKs a chosen record, before
// the flow's own store, the "session" stores the coordinator's chain into the
// flow's storage with the storage's own compare-and-set.

const hex = (b: Uint8Array) => toHex(b);
const id = (n: number) => party(n).signer.descriptor.principalId;

type RecordType = ReturnType<typeof decodeControlRecord>["body"]["type"];

/** A session storing the coordinator's chain of R into `storage`, as an open sync session does. */
async function sessionStores(
  server: MemoryCoordinator,
  storage: Node["storage"],
  R: ResourceId,
): Promise<void> {
  const stored = await loadControlChain(storage, R);
  const r = await saveControlChain(
    storage,
    server.chain(R),
    stored?.kind === "linear" ? stored.state.head : null,
  );
  if (!r.ok) throw new Error(`the session's store failed: ${r.reason}`);
}

/**
 * `node`'s network, where every ACKed CONTROL_PUT of a record of type `type` on a
 * Resource `on` accepts is first stored by the "session"; `raced` counts them.
 */
function racing(
  server: MemoryCoordinator,
  node: Node,
  type: RecordType,
  on: (R: ResourceId) => boolean = () => true,
): { network: IdentityNetwork; raced: () => number } {
  let raced = 0;
  const base = server.network();
  const network: IdentityNetwork = {
    connect: async (signer, url) => {
      const channel = await base.connect(signer, url);
      return new Proxy(channel, {
        get(target, key) {
          if (key === "putControl")
            return async (R: ResourceId, head: Uint8Array, record: Uint8Array) => {
              const answer = await target.putControl(R, head as never, record);
              if (
                answer.kind === "ack" &&
                on(R) &&
                decodeControlRecord(record).body.type === type
              ) {
                await sessionStores(server, node.storage, R);
                raced++;
              }
              return answer;
            };
          const v = Reflect.get(target, key, target) as unknown;
          return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
        },
      }) as IdentityChannel;
    },
  };
  return { network, raced: () => raced };
}

describe("storeChain: an open session stored the ACKed record first (414c, I29)", {
  timeout: 120_000,
}, () => {
  test("approvePairing: the approval's DEVICE_GRANT in I", async () => {
    const w = await world(1);
    const race = racing(w.server, w.P, "DEVICE_GRANT", (R) => hex(R) === hex(w.I));
    // pair() approves with the approver's options: its network races.
    const D = await pair(w, { ...w.P, network: race.network }, 3, "read");
    expect(race.raced()).toBeGreaterThan(0);
    const I = await loadControlChain(w.P.storage, w.I);
    if (I?.kind !== "linear") throw new Error("no I");
    expect(I.state.devices.get(hex(D.installation.signer.descriptor.principalId))).toBeDefined();
  });

  test("revokeDevice: the DEVICE_REVOKE in I and in X", async () => {
    const w = await world(1);
    await pair(w, w.P, 3, "read");
    const race = racing(w.server, w.P, "DEVICE_REVOKE");
    const r = await revokeDevice({ ...w.P, network: race.network, device: id(3), reason: 1n });
    expect(race.raced()).toBeGreaterThanOrEqual(2);
    expect(r.kind).toBe("revoked");
    if (r.kind !== "revoked") return;
    expect(r.results.map((t) => t.revoke)).toEqual(["revoked", "revoked"]);
  });

  test("rotateIfExposed (and revokeDevice's own rotation): the KEY_EPOCH", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    await pair(w, w.P, 3, "read");
    const race = racing(w.server, w.P, "KEY_EPOCH");
    const r = await revokeDevice({ ...w.P, network: race.network, device: id(3), reason: 1n });
    expect(r.kind).toBe("revoked");
    if (r.kind !== "revoked") return;
    expect(r.results.map((t) => t.rotation?.status)).toEqual(["rotated", "rotated"]);
    expect(race.raced()).toBe(2);
    // The same race on a standalone rotateIfExposed: an exposing revocation in X only.
    await pair(w, w.P, 4, "read");
    w.server.down.add(hex(w.I));
    const channel = await race.network.connect(w.P.installation.signer, URL);
    const x = await syncChain(w.P.storage, channel, X);
    const revoke = signControlRecord(
      { resourceId: X, controlSeq: x.state.seq + 1n, prevControlId: x.state.head },
      { type: "DEVICE_REVOKE", root: id(1), device: id(4), reason: 1n },
      w.P.installation.signer,
    );
    expect((await channel.putControl(X, x.state.head, revoke.bytes)).kind).toBe("ack");
    w.server.down.clear();
    const { OperationJournal } = await import("../../src/identity/journal.js");
    await new OperationJournal(w.P.storage).begin({
      id: "rotate.race",
      kind: "rotate",
      createdAt: 1,
      intent: {},
    });
    const out = await rotateIfExposed({ ...w.P, channel, operation: "rotate.race", resource: X });
    expect(out.status).toBe("rotated");
    expect(race.raced()).toBe(3);
  });

  test("registerDevice from reconciliation: the DEVICE_GRANT in X", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    // DEV_3 paired while X was unreachable: registered in I only.
    w.server.down.add(hex(X));
    await pair(w, w.P, 3, "read");
    w.server.down.clear();
    const race = racing(w.server, w.P, "DEVICE_GRANT", (R) => hex(R) === hex(X));
    const r = await reconcileDevices({ ...w.P, network: race.network });
    expect(race.raced()).toBe(1);
    const x = r.targets.find((t) => hex(t.resource) === hex(X));
    expect(x?.status).toBe("done");
    expect(x?.steps.map((s) => [s.step.kind, s.state])).toEqual([["register", "committed-own"]]);
  });
});

describe("storeChain: what the stored chain may be after a refused compare-and-set", {
  timeout: 60_000,
}, () => {
  test("an older state of the same chain is stored over; a diverging one is a fork with a stable code", async () => {
    const w = await world(1);
    await pair(w, w.P, 3, "read");
    const I = w.server.chain(w.I);
    const n = I.records.length;
    const prefixOf = (k: number) => {
      const c = validateControlChain(I.records.slice(0, k).map((r) => r.signed.bytes));
      if (c.kind !== "linear") throw new Error(c.kind);
      return c;
    };
    // Older: the storage holds the chain up to n-2, the flow read n-3 and extends it to n.
    const older = device();
    expect((await saveControlChain(older.storage, prefixOf(n - 2), null)).ok).toBe(true);
    const last = I.records[n - 1]?.signed.bytes as Uint8Array;
    const flowRead = validateControlChain(I.records.slice(0, n - 1).map((r) => r.signed.bytes));
    if (flowRead.kind !== "linear") throw new Error(flowRead.kind);
    // The flow's own previous is n-1 records; the stored head is n-2 (older): stored over.
    await extendChain(older.storage, flowRead, last);
    const stored = await loadControlChain(older.storage, w.I);
    expect(stored?.kind === "linear" && stored.state.seq).toBe(I.state.seq);
    // Diverging: the storage holds another record on the n-1 head.
    const fork = device();
    const other = signControlRecord(
      {
        resourceId: w.I,
        controlSeq: flowRead.state.seq + 1n,
        prevControlId: flowRead.state.head,
      },
      {
        type: "CAPABILITY_GRANT",
        subject: party(12).signer.descriptor,
        abilities: [1n],
        delegable: [],
      },
      w.P.installation.signer,
    );
    const branch = validateControlChain([
      ...flowRead.records.map((r) => r.signed.bytes),
      other.bytes,
    ]);
    if (branch.kind !== "linear") throw new Error(branch.kind);
    expect((await saveControlChain(fork.storage, branch, null)).ok).toBe(true);
    const thrown = await extendChain(fork.storage, prefixOf(n - 1), last).catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(ControlChainDiverged);
    expect(thrown).toBeInstanceOf(IdentityConflict);
    expect((thrown as ControlChainDiverged).code).toBe("CONTROL_CHAIN_DIVERGED");
    // The fork is recorded, so later calls are suspended too (review 417-418 F1).
    expect(await fork.storage.control.conflict(w.I)).toBeDefined();
    await expect(extendChain(fork.storage, prefixOf(n - 1), last)).rejects.toThrow(
      IdentityConflict,
    );
  });
});

// Review 417-418 F1: a fork the storage knows suspends the recovery (§9.7).
describe("storeChain and a recorded fork (review 417-418 F1)", { timeout: 60_000 }, () => {
  /** I's chain on the coordinator after a few pairings, and its prefixes. */
  async function longI() {
    const w = await world(0);
    for (const n of [3, 4, 5]) await pair(w, w.P, n, "read");
    const I = w.server.chain(w.I);
    const prefixOf = (k: number) => {
      const c = validateControlChain(I.records.slice(0, k).map((r) => r.signed.bytes));
      if (c.kind !== "linear") throw new Error(c.kind);
      return c;
    };
    expect(I.records.length).toBeGreaterThanOrEqual(8);
    return { w, I, n: I.records.length, prefixOf };
  }
  /** A fork marker for I, as syncChain records one (two competing heads). */
  const marker = (w: Awaited<ReturnType<typeof world>>, head: Uint8Array) => ({
    op: "set-control-conflict" as const,
    resourceId: w.I,
    conflict: { heads: [head as never, new Uint8Array(32).fill(7) as never] },
  });

  test("a recorded fork with a linear stored head that contains the chain: suspended, nothing accepted", async () => {
    const { w, I, n, prefixOf } = await longI();
    const st = device().storage;
    expect((await saveControlChain(st, I, null)).ok).toBe(true);
    expect((await st.commit([marker(w, I.state.head)])).ok).toBe(true);
    const last = I.records[n - 1]?.signed.bytes as Uint8Array;
    await expect(extendChain(st, prefixOf(n - 1), last)).rejects.toThrow(IdentityConflict);
    expect(await st.control.conflict(w.I)).toBeDefined();
  });

  test("a fork recorded during the recovery is not cleared by the retry: suspended", async () => {
    const { w, I, n, prefixOf } = await longI();
    const base = device().storage;
    // Stored: an older state; the flow extends a later one, so it retries over the stored head.
    expect((await saveControlChain(base, prefixOf(n - 3), null)).ok).toBe(true);
    let recorded = false;
    const st = new Proxy(base, {
      get(t, k) {
        if (k === "commit")
          return async (writes: Parameters<typeof base.commit>[0]) => {
            const head = writes.some((x) => x.op === "set-control-head");
            // Another session records the fork just before the flow's first commit.
            if (head && !recorded) {
              recorded = true;
              await t.commit([marker(w, I.state.head)]);
            }
            return t.commit(writes);
          };
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const last = I.records[n - 1]?.signed.bytes as Uint8Array;
    await expect(extendChain(st, prefixOf(n - 1), last)).rejects.toThrow(IdentityConflict);
    expect(recorded).toBe(true);
    expect(await base.control.conflict(w.I)).toBeDefined();
  });

  test("a stored chain longer than the flow's: accepted, never rolled back", async () => {
    const { I, n, prefixOf } = await longI();
    const st = device().storage;
    expect((await saveControlChain(st, I, null)).ok).toBe(true);
    const at = prefixOf(n - 2);
    const next = I.records[n - 2]?.signed.bytes as Uint8Array;
    await extendChain(st, prefixOf(n - 3), at.records.at(-1)?.signed.bytes as Uint8Array);
    await extendChain(st, at, next);
    const stored = await loadControlChain(st, I.state.resourceId);
    expect(stored?.kind === "linear" && stored.state.seq).toBe(I.state.seq);
  });

  test("a head other sessions keep moving: ControlChainBusy after the initial attempt and four retries", async () => {
    const { w, I, n, prefixOf } = await longI();
    const base = device().storage;
    expect((await saveControlChain(base, prefixOf(1), null)).ok).toBe(true);
    let stored = 1;
    let attempts = 0;
    const st = new Proxy(base, {
      get(t, k) {
        if (k === "commit")
          return async (writes: Parameters<typeof base.commit>[0]) => {
            if (writes.some((x) => x.op === "set-control-head")) {
              attempts++;
              // Another session stores one more record of the same chain first, each time.
              stored++;
              const cur = await loadControlChain(t, w.I);
              await saveControlChain(
                t,
                prefixOf(stored),
                cur?.kind === "linear" ? cur.state.head : null,
              );
            }
            return t.commit(writes);
          };
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const last = I.records[n - 1]?.signed.bytes as Uint8Array;
    const thrown = await extendChain(st, prefixOf(n - 1), last).catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(ControlChainBusy);
    expect(thrown).toBeInstanceOf(IdentityUnavailable);
    expect((thrown as ControlChainBusy).code).toBe("CONTROL_HEAD_MISMATCH");
    expect(attempts).toBe(5);
    expect(await base.control.conflict(w.I)).toBeUndefined();
  });

  test("R1: a fork recorded while the recovery reads the stored chain: suspended, not accepted", async () => {
    const { w, I, n, prefixOf } = await longI();
    const base = device().storage;
    // Stored: the whole chain, which contains the flow's: the containment path.
    expect((await saveControlChain(base, I, null)).ok).toBe(true);
    let recorded = false;
    const control = new Proxy(base.control, {
      get(t, k) {
        const v = Reflect.get(t, k, t) as unknown;
        if (k === "records" && typeof v === "function")
          return async (...a: unknown[]) => {
            // Another session records the fork while loadControlChain reads the records.
            if (!recorded) {
              recorded = true;
              await base.commit([marker(w, I.state.head)]);
            }
            return (v as (...x: unknown[]) => unknown).apply(t, a);
          };
        return typeof v === "function" ? (v as (...x: unknown[]) => unknown).bind(t) : v;
      },
    });
    const st = new Proxy(base, {
      get(t, k) {
        if (k === "control") return control;
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const last = I.records[n - 1]?.signed.bytes as Uint8Array;
    await expect(extendChain(st, prefixOf(n - 1), last)).rejects.toThrow(IdentityConflict);
    expect(recorded).toBe(true);
    expect(await base.control.conflict(w.I)).toBeDefined();
  });

  test("R1: a fork recorded while syncChain waits on the coordinator, nothing new: suspended", async () => {
    const { w, I } = await longI();
    const st = device().storage;
    expect((await saveControlChain(st, I, null)).ok).toBe(true);
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    // The coordinator has nothing new; another session records the fork meanwhile.
    const racing = new Proxy(channel, {
      get(t, k) {
        const v = Reflect.get(t, k, t) as unknown;
        if (k === "control" && typeof v === "function")
          return async (...a: unknown[]) => {
            const out = await (v as (...x: unknown[]) => Promise<unknown>).apply(t, a);
            await st.commit([marker(w, I.state.head)]);
            return out;
          };
        return typeof v === "function" ? (v as (...x: unknown[]) => unknown).bind(t) : v;
      },
    }) as typeof channel;
    await expect(syncChain(st, racing, w.I)).rejects.toThrow(IdentityConflict);
    expect(await st.control.conflict(w.I)).toBeDefined();
  });
});
