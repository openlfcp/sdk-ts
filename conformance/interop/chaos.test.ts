// LFCP-057: network chaos and protocol-security scenarios, live, against the
// Rust reference server. Two TypeScript clients (SyncClient) talk to the real
// server binary; faults are injected per message at the transport boundary
// between a client and the server (WireTap: drop, duplicate, delay, hold,
// cut), or sent as exact messages over an authenticated raw session
// (RawSession). Nothing in the client or the server is mocked.
//
// Each scenario uses its own Resource and Principals. Waits are bounded
// safety nets on explicit conditions, never correctness by sleeping; the one
// reordering uses a barrier. The seeded runs print the seed and the action
// trace of a failing run, so it can be replayed locally:
//   LFCP_CHAOS_SEEDS=<n> runs n more seeds (the PR set is fixed);
//   LFCP_CHAOS_SEED=<seed> runs one seed.
//
// Skipped (with the reason) when cargo or the server checkout is missing,
// unless LFCP_REQUIRE_LIVE=1.
//
// Scenarios 13 and 14, and seeds 2 and 3, are the regressions of two
// liveness defects this suite found: a lost ACK, and a lost DATA_GET reply,
// on a connection that stays up were never retried.

import {
  createDataUnit,
  createQueuedDataUnit,
  createQueuedSnapshot,
  LFCP_SUBPROTOCOL,
  latestAcceptedOwnUnit,
  loadControlChain,
  platformWebSocket,
  queueControlRecord,
  resourceSyncState,
} from "@openlfcp/client";
import {
  type DataUnitId,
  dataEpoch,
  generateResourceId,
  type ObjectId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  generateAgreementKeyPair,
  generateResourceDEK,
  generateSigningKeyPair,
  type ResourceDEK,
} from "@openlfcp/crypto";
import {
  checkChange,
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import {
  type AnyMessage,
  type ChainResult,
  createMessage,
  decodeMessage,
  encodeDataUnitPayload,
  encodeMessage,
  MESSAGE_TYPE,
  parseDataUnit,
  principalDescriptorFromKeys,
  rotateEpoch,
  signControlRecord,
  signObject,
  validateControlChain,
} from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createResource, grantAndKey, type Party, Side, waitFor } from "./harness.js";
import { codeName, RawSession } from "./raw-session.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";
import { type Action, type Frame, WireTap } from "./wire-tap.js";

declare const console: { warn(...a: unknown[]): void; log(...a: unknown[]): void };
declare const process: { env: Record<string, string | undefined> };
declare const setTimeout: (fn: () => void, ms: number) => unknown;

type Linear = Extract<ChainResult, { kind: "linear" }>;

const fresh = (): Party => {
  const key = generateSigningKeyPair();
  const agreement = generateAgreementKeyPair();
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const MAX = 2n ** 64n - 1n;

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

/** Records every profile apply of a side: unit ID hex, in order. */
function spyApply(side: Side): string[] {
  const applied: string[] = [];
  const profile = side.profile as unknown as {
    apply: (u: { unitId: Uint8Array }, v: unknown) => unknown;
  };
  const original = profile.apply.bind(profile);
  profile.apply = (u, v) => {
    applied.push(toHex(u.unitId));
    return original(u, v);
  };
  return applied;
}

const count = (list: readonly string[], id: Uint8Array) =>
  list.filter((x) => x === toHex(id)).length;

/** Data Unit IDs carried by a frame (DATA_PUT, DATA_BATCH). */
const unitsIn = (f: Frame): string[] =>
  f.message?.type === "DATA_PUT" || f.message?.type === "DATA_BATCH"
    ? f.message.body.objects.map((b) => toHex(parseDataUnit(b).signed.id))
    : [];

interface Pair {
  readonly R: ResourceId;
  readonly dek: ResourceDEK;
  readonly owner: Party;
  readonly bob: Party;
  readonly A: Side;
  readonly B: Side;
  readonly tapA: WireTap;
  readonly tapB: WireTap;
  readonly task: ObjectId;
  readonly genesisId: Uint8Array;
  readonly applied: string[];
  /** Retitles the Task on `side` and returns the new unit's ID. */
  edit(side: Side, title: string): Promise<DataUnitId>;
  stop(): Promise<void>;
}

/**
 * OWNER (A) creates and hosts a Shared Objects Resource, grants BOB (B)
 * data/read + data/write with the epoch-0 DEK, and creates a Task that B
 * receives. B's profile applies are recorded (applied).
 */
async function pair(url: string): Promise<Pair> {
  const R = generateResourceId();
  const dek = generateResourceDEK();
  const owner = fresh();
  const bob = fresh();
  const tapA = new WireTap();
  const tapB = new WireTap();
  const { replica, change: init } = SharedObjectsReplica.create({
    resource: R,
    principal: owner.signer.descriptor.principalId,
  });
  const A = new Side({
    url,
    resource: R,
    who: owner,
    profile: new SharedObjectsDataProfile(replica),
    webSocket: tapA.factory,
    snapshots: false,
  });
  const genesis = await createResource(A, url, dek);
  await A.write(init);
  A.start({ open: false });
  await waitFor("A READY", () => A.client.connectionState === "READY");
  await A.client.host(genesis.bytes);
  A.open();
  await waitFor("A LIVE", () => A.client.resourceState(R) === "LIVE");
  await grantAndKey(A, bob, dek);
  await waitFor("grant ACKed", () => A.queueEmpty());
  const B = new Side({
    url,
    resource: R,
    who: bob,
    profile: new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: bob.signer.descriptor.principalId }),
    ),
    webSocket: tapB.factory,
    snapshots: false,
  });
  const applied = spyApply(B);
  B.start();
  await waitFor("B LIVE", () => B.client.resourceState(R) === "LIVE");
  const created = createTask({ title: "base", createdBy: owner.signer.descriptor.principalId });
  await A.write(A.profile.replica.apply(created.intent) as LocalChange);
  const task = created.task.id as ObjectId;
  await waitFor("B has the Task", () => B.profile.replica.task(task)?.task?.title === "base");
  return {
    R,
    dek,
    owner,
    bob,
    A,
    B,
    tapA,
    tapB,
    task,
    genesisId: genesis.recordId,
    applied,
    async edit(side, title) {
      const t = side.profile.replica.task(task)?.task as Task;
      return side.write(side.profile.replica.apply(setTitle(t, title).intent) as LocalChange);
    },
    async stop() {
      await A.stop();
      await B.stop();
    },
  };
}

const titleOf = (side: Side, task: ObjectId) => side.profile.replica.task(task)?.task?.title;

function live(ctx: { skip: () => void }): string {
  if (server === undefined) {
    console.warn(`SKIPPED: LFCP-057 chaos (${skip})`);
    ctx.skip();
    throw new Error("unreachable");
  }
  return server.url;
}

const withLog = async (f: () => Promise<void>) => {
  try {
    await f();
  } catch (e) {
    throw new Error(
      `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server?.log().slice(-3000)}`,
    );
  }
};

describe("LFCP-057: network chaos (live)", () => {
  it("1. a DATA_PUT committed but cut before its ACK is retried as the same unit, applied once", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        let cut = false;
        p.tapA.rule((f) => {
          if (
            !cut &&
            f.direction === "in" &&
            f.message?.type === "ACK" &&
            f.message.body.requestType === MESSAGE_TYPE.DATA_PUT
          ) {
            cut = true;
            return { kind: "cut" };
          }
          return undefined;
        });
        const id = await p.edit(p.A, "after the cut");
        await waitFor("the retried unit is ACKed", () => p.A.queueEmpty(), 20_000);
        expect(cut).toBe(true);
        const puts = p.tapA
          .messages("DATA_PUT", "out")
          .filter((f) => unitsIn(f).includes(toHex(id)));
        expect(puts.length).toBeGreaterThanOrEqual(2);
        const sent = puts.map((f) =>
          f.message?.type === "DATA_PUT" ? toHex(f.message.body.objects[0] as Uint8Array) : "",
        );
        expect(new Set(sent).size).toBe(1); // the exact same bytes, never regenerated
        expect(new Set(puts.map((f) => f.connection)).size).toBeGreaterThanOrEqual(2);
        const mine = await p.A.storage.dataUnits.range(
          p.R,
          p.owner.signer.descriptor.principalId,
          1n as never,
          MAX as never,
        );
        expect(mine.filter((u) => toHex(u.unitId) === toHex(id))).toHaveLength(1);
        await waitFor("B sees the edit", () => titleOf(p.B, p.task) === "after the cut");
        expect(count(p.applied, id)).toBe(1);
      } finally {
        await p.stop();
      }
    });
  }, 60_000);

  it("2. duplicated deliveries both ways are harmless: one profile application per unit", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        p.tapA.rule((f) =>
          f.direction === "out" && f.message?.type === "DATA_PUT"
            ? { kind: "duplicate" }
            : undefined,
        );
        p.tapB.rule((f) =>
          f.direction === "in" && f.message?.type === "DATA_BATCH"
            ? { kind: "duplicate" }
            : undefined,
        );
        const ids = [
          await p.edit(p.A, "one"),
          await p.edit(p.A, "two"),
          await p.edit(p.A, "three"),
        ];
        await waitFor("B has all three", () => titleOf(p.B, p.task) === "three");
        await waitFor("A's queue drains", () => p.A.queueEmpty());
        for (const id of ids) expect(count(p.applied, id)).toBe(1);
        expect(p.B.errors()).toEqual([]);
      } finally {
        await p.stop();
      }
    });
  }, 60_000);

  it("3. a reordered push is held as a gap, never applied out of order, and repaired", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        let release: (v?: unknown) => void = () => undefined;
        const barrier = new Promise((r) => {
          release = r;
        });
        let held = 0;
        p.tapB.rule((f) => {
          if (f.direction !== "in" || f.message?.type !== "DATA_BATCH") return undefined;
          held++;
          if (held === 1) return { kind: "hold", until: barrier }; // the first push waits
          if (held === 2) setTimeout(() => release(), 0); // released after the second is delivered
          return undefined;
        });
        const first = await p.edit(p.A, "k");
        const second = await p.edit(p.A, "k+1");
        await waitFor("B converges", () => titleOf(p.B, p.task) === "k+1", 20_000);
        const outcomes = p.B.events.flatMap((e) => (e.type === "unit" ? [e.outcome] : []));
        expect(outcomes.some((o) => o.kind === "held" && toHex(o.unitId) === toHex(second))).toBe(
          true,
        );
        // Never applied out of order: k before k+1, each once.
        const order = p.applied.filter((x) => x === toHex(first) || x === toHex(second));
        expect(order).toEqual([toHex(first), toHex(second)]);
      } finally {
        await p.stop();
      }
    });
  }, 60_000);

  it("11. a lost live push is recovered by anti-entropy (DATA_HAVE → DATA_GET)", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        let dropped: Frame | undefined;
        p.tapB.rule((f) => {
          if (
            dropped === undefined &&
            f.direction === "in" &&
            f.message?.type === "DATA_BATCH" &&
            f.message.correlationId === undefined
          ) {
            dropped = f;
            return { kind: "drop" };
          }
          return undefined;
        });
        const id = await p.edit(p.A, "pushed, then lost");
        await waitFor(
          "B recovers the unit",
          () => titleOf(p.B, p.task) === "pushed, then lost",
          20_000,
        );
        expect(dropped !== undefined && unitsIn(dropped)).toEqual([toHex(id)]);
        const after = p.tapB.frames.slice(p.tapB.frames.indexOf(dropped as Frame));
        expect(after.some((f) => f.direction === "out" && f.message?.type === "DATA_GET")).toBe(
          true,
        );
        expect(
          after.some(
            (f) =>
              f.direction === "in" &&
              f.message?.type === "DATA_BATCH" &&
              f.message.correlationId !== undefined &&
              unitsIn(f).includes(toHex(id)),
          ),
        ).toBe(true);
        expect(count(p.applied, id)).toBe(1);
      } finally {
        await p.stop();
      }
    });
  }, 60_000);

  it("12. repeated reconnects with queued units: no sequence reuse, no loss, convergence", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        // Three connections in turn lose their link right after a DATA_PUT. A cut
        // connection is still closing for a moment, so each one is cut once.
        const cut = new Set<number>();
        p.tapB.rule((f) => {
          if (f.direction !== "out" || f.message?.type !== "DATA_PUT") return undefined;
          if (cut.size >= 3 || cut.has(f.connection)) return undefined;
          cut.add(f.connection);
          return { kind: "deliver-then-cut" };
        });
        const ids: DataUnitId[] = [];
        for (let i = 1; i <= 6; i++) ids.push(await p.edit(p.B, `B ${i}`));
        await waitFor("B's queue drains", () => p.B.queueEmpty(), 30_000);
        await waitFor("A converges", () => titleOf(p.A, p.task) === "B 6", 20_000);
        const connections = new Set(p.tapB.frames.map((f) => f.connection));
        expect(cut.size).toBe(3);
        expect(connections.size).toBeGreaterThanOrEqual(4);
        const mine = await p.B.storage.dataUnits.range(
          p.R,
          p.bob.signer.descriptor.principalId,
          1n as never,
          MAX as never,
        );
        expect(mine.map((u) => u.actorSeq)).toEqual([1n, 2n, 3n, 4n, 5n, 6n]);
        expect(JSON.stringify(p.A.profile.replica.root())).toBe(
          JSON.stringify(p.B.profile.replica.root()),
        );
      } finally {
        await p.stop();
      }
    });
  }, 90_000);

  it("13. a lost ACK on a live connection: the put is retransmitted after the request timeout", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        let dropped = false;
        p.tapA.rule((f) => {
          if (
            !dropped &&
            f.direction === "in" &&
            f.message?.type === "ACK" &&
            f.message.body.requestType === MESSAGE_TYPE.DATA_PUT
          ) {
            dropped = true;
            return { kind: "drop" };
          }
          return undefined;
        });
        const id = await p.edit(p.A, "ACK lost");
        await waitFor("the retransmitted put is ACKed", () => p.A.queueEmpty(), 30_000);
        const puts = p.tapA
          .messages("DATA_PUT", "out")
          .filter((f) => unitsIn(f).includes(toHex(id)));
        expect(puts.length).toBeGreaterThanOrEqual(2);
        expect(new Set(puts.map((f) => f.connection)).size).toBe(1); // no reconnect
        await waitFor("B applies it", () => titleOf(p.B, p.task) === "ACK lost");
        expect(count(p.applied, id)).toBe(1);
      } finally {
        await p.stop();
      }
    });
  }, 60_000);

  it("14. a lost DATA_GET reply on a live connection: the data round is issued again", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        await p.B.stop();
        await p.edit(p.A, "fetched twice");
        await waitFor("A's unit ACKed", () => p.A.queueEmpty());
        const before = p.tapB.frames.length;
        let dropped = false;
        p.tapB.rule((f) => {
          if (
            !dropped &&
            f.direction === "in" &&
            f.message?.type === "DATA_BATCH" &&
            f.message.correlationId !== undefined
          ) {
            dropped = true;
            return { kind: "drop" };
          }
          return undefined;
        });
        p.B.start();
        await waitFor("B catches up", () => titleOf(p.B, p.task) === "fetched twice", 45_000);
        const after = p.tapB.frames.slice(before);
        const gets = after.filter((f) => f.direction === "out" && f.message?.type === "DATA_GET");
        expect(dropped).toBe(true);
        expect(gets.length).toBeGreaterThanOrEqual(2);
        expect(new Set(gets.map((f) => f.connection)).size).toBe(1); // no reconnect
      } finally {
        await p.stop();
      }
    });
  }, 90_000);

  it("15. a lost SNAPSHOT reply falls back to the data round after the request timeout", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const tap = new WireTap();
      let fresh: Side | undefined;
      try {
        await p.edit(p.A, "covered by the Snapshot");
        await waitFor("A's unit ACKed", () => p.A.queueEmpty());
        // OWNER publishes a Snapshot of everything it holds.
        const chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const have = (await resourceSyncState(p.A.storage, p.R)).have;
        await createQueuedSnapshot(p.A.storage, {
          view: chain,
          controlHead: chain.state.head,
          publisher: p.owner.signer,
          dek: p.dek,
          frontier: have.map((h) => ({
            principalId: h.principalId,
            contiguous: h.contiguous,
            ...(h.extras.length > 0 ? { ranges: [...h.extras] } : {}),
          })),
          profile: p.A.profile.snapshotCodec(),
          value: p.A.profile.snapshotState(),
        });
        p.A.client.flush();
        await waitFor("the Snapshot is ACKed", () => p.A.queueEmpty());
        // A fresh replica of BOB, with Snapshots on; the SNAPSHOT reply is lost.
        await p.B.stop();
        tap.rule((f) =>
          f.direction === "in" && f.message?.type === "SNAPSHOT" ? { kind: "drop" } : undefined,
        );
        fresh = new Side({
          url,
          resource: p.R,
          who: p.bob,
          profile: new SharedObjectsDataProfile(
            SharedObjectsReplica.empty({
              resource: p.R,
              principal: p.bob.signer.descriptor.principalId,
            }),
          ),
          webSocket: tap.factory,
          snapshots: true,
        });
        const side = fresh;
        side.start();
        await waitFor(
          "the fresh replica converges from units",
          () => titleOf(side, p.task) === "covered by the Snapshot",
          45_000,
        );
        expect(tap.messages("SNAPSHOT_GET", "out")).toHaveLength(1);
        expect(tap.messages("SNAPSHOT", "in").length).toBeGreaterThanOrEqual(1); // sent, and dropped
        expect(tap.messages("DATA_GET", "out").length).toBeGreaterThan(0);
        expect(side.events.some((e) => e.type === "snapshot-loaded")).toBe(false);
        expect(new Set(tap.frames.map((f) => f.connection)).size).toBe(1); // no reconnect
      } finally {
        await fresh?.stop();
        await p.stop();
      }
    });
  }, 90_000);

  it("4. Have holes from abandoned sequences: only the real ranges are requested, the hole stays", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        await p.B.stop();
        const getsBefore = p.tapB.messages("DATA_GET", "out").length;
        const ownerId = p.owner.signer.descriptor.principalId;
        // OWNER has 1 (init) and 2 (create); writes 3..100, abandons 101..104, writes 105..107.
        for (let i = 3; i <= 100; i++) await p.edit(p.A, `edit ${i}`);
        for (let i = 101; i <= 104; i++) await p.A.storage.actorSequences.reserveNext(p.R, ownerId);
        for (let i = 105; i <= 107; i++) await p.edit(p.A, `edit ${i}`);
        await waitFor("OWNER's units ACKed", () => p.A.queueEmpty(), 60_000);
        p.B.start();
        await waitFor("B catches up", () => titleOf(p.B, p.task) === "edit 107", 60_000);
        await waitFor("B LIVE", () => p.B.client.resourceState(p.R) === "LIVE");
        const requested = p.tapB
          .messages("DATA_GET", "out")
          .slice(getsBefore)
          .flatMap((f) => (f.message?.type === "DATA_GET" ? f.message.body.ranges : []))
          .filter((r) => toHex(r.actor) === toHex(ownerId))
          .map((r) => [r.start, r.end] as const);
        expect(requested.length).toBeGreaterThan(0);
        for (const [a, b] of requested) expect(b < 101n || a > 104n).toBe(true); // never the hole
        const have = (await resourceSyncState(p.B.storage, p.R)).have.find(
          (h) => toHex(h.principalId) === toHex(ownerId),
        );
        expect([have?.contiguous, have?.extras]).toEqual([100n, [[105n, 107n]]]);
        // The server's Have keeps the same hole.
        const opened = p.tapB.messages("RESOURCE_OPENED", "in").at(-1)?.message as
          | {
              body: {
                haves: {
                  principalId: Uint8Array;
                  contiguous: bigint;
                  ranges?: [bigint, bigint][];
                }[];
              };
            }
          | undefined;
        const serverHave = opened?.body.haves.find((h) => toHex(h.principalId) === toHex(ownerId));
        expect([serverHave?.contiguous, serverHave?.ranges]).toEqual([100n, [[105n, 107n]]]);
      } finally {
        await p.stop();
      }
    });
  }, 180_000);

  it("6. a stale CONTROL_PUT is CONTROL_HEAD_MISMATCH with the current head, and commits nothing", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const raw = new RawSession({ url, signer: p.owner.signer });
      try {
        const chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const stale = signControlRecord(
          { resourceId: p.R, controlSeq: 1n, prevControlId: p.genesisId as never },
          {
            type: "CAPABILITY_GRANT",
            subject: fresh().signer.descriptor,
            abilities: [1n],
            delegable: [],
          },
          p.owner.signer,
        );
        await raw.connect();
        const answer = await raw.request(
          createMessage("CONTROL_PUT", {
            resourceId: p.R,
            expectedHead: p.genesisId as never,
            record: stale.bytes,
          }),
        );
        expect(answer.type).toBe("NACK");
        if (answer.type !== "NACK") return;
        expect(codeName(answer.body.code)).toBe("CONTROL_HEAD_MISMATCH");
        expect(toHex(answer.body.details as Uint8Array)).toBe(toHex(chain.state.head));
        const batch = await raw.request(
          createMessage("CONTROL_GET", { resourceId: p.R, start: 0n, end: 100n }),
        );
        expect(batch.type === "CONTROL_BATCH" && batch.body.objects.length).toBe(
          Number(chain.state.seq) + 1,
        );
        // A Data Unit authorized at an older valid head is not rejected for its age (§26.3).
        const dek = p.dek;
        const local = p.A.profile.replica.apply(
          setTitle(p.A.profile.replica.task(p.task)?.task as Task, "at the Genesis head").intent,
        ) as LocalChange;
        const old = await createQueuedDataUnit(p.A.storage, {
          view: chain,
          controlHead: p.genesisId,
          actor: p.owner.signer,
          dek,
          profile: p.A.profile.codecFor({
            resourceId: p.R,
            actor: p.owner.signer.descriptor.principalId,
          }),
          value: checkChange(local.change),
          onCreated: (c, v) => p.A.profile.recordLocal(c.unitId, v),
        });
        expect(toHex(parseDataUnit(old.bytes).payload.controlHead)).toBe(toHex(p.genesisId));
        p.A.client.flush();
        await waitFor("the old-head unit is ACKed", () => p.A.queueEmpty());
        await waitFor("B applies it", () => titleOf(p.B, p.task) === "at the Genesis head");
        expect(count(p.applied, old.unitId)).toBe(1);
      } finally {
        raw.close();
        await p.stop();
      }
    });
  }, 60_000);

  it("7. a tampered signed unit is INVALID_SIGNATURE at the server and never profile-applied", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const raw = new RawSession({ url, signer: p.owner.signer });
      try {
        const chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const local = p.A.profile.replica.apply(
          setTitle(p.A.profile.replica.task(p.task)?.task as Task, "tampered").intent,
        ) as LocalChange;
        const unit = await createDataUnit({
          view: chain,
          controlHead: chain.state.head,
          actor: p.owner.signer,
          dek: p.dek,
          sequences: p.A.storage.actorSequences,
          previousUnitId: await latestAcceptedOwnUnit(
            p.A.storage,
            p.R,
            p.owner.signer.descriptor.principalId,
          ),
          profile: p.A.profile.codecFor({
            resourceId: p.R,
            actor: p.owner.signer.descriptor.principalId,
          }),
          value: checkChange(local.change),
        });
        const tampered = Uint8Array.from(unit.bytes);
        tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 1; // a signature byte
        await raw.connect();
        const answer = await raw.request(
          createMessage("DATA_PUT", { resourceId: p.R, objects: [tampered] }),
        );
        expect(answer.type === "NACK" && codeName(answer.body.code)).toBe("INVALID_SIGNATURE");
        // A receiver given the bytes directly rejects them before the profile.
        const before = p.applied.length;
        const view = (await loadControlChain(p.B.storage, p.R)) as Linear;
        expect(await p.B.applier.receive(view, tampered)).toMatchObject({
          kind: "rejected",
          wireCode: "INVALID_SIGNATURE",
        });
        expect(p.applied.length).toBe(before);
        expect(p.tapB.frames.some((f) => unitsIn(f).includes(toHex(unit.unitId)))).toBe(false);
      } finally {
        raw.close();
        await p.stop();
      }
    });
  }, 60_000);

  it("8. garbage sealed by an authorized signer: the server accepts it (N3), the client fails it locally", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const raw = new RawSession({ url, signer: p.owner.signer });
      try {
        const chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const me = p.owner.signer.descriptor.principalId;
        const previous = await latestAcceptedOwnUnit(p.A.storage, p.R, me);
        const seq = await p.A.storage.actorSequences.reserveNext(p.R, me);
        const payload = encodeDataUnitPayload({
          resourceId: p.R,
          dataEpoch: dataEpoch(0n),
          actor: me,
          actorSeq: seq,
          prevDataUnitId: previous,
          controlHead: chain.state.head,
          ciphertext: Uint8Array.from({ length: 48 }, (_, i) => (i * 37 + 11) & 0xff),
        });
        const garbage = signObject(payload, p.owner.signer);
        await raw.connect();
        const answer = await raw.request(
          createMessage("DATA_PUT", { resourceId: p.R, objects: [garbage.bytes] }),
        );
        expect(answer.type).toBe("ACK"); // the server cannot decrypt: it stores it (N3)
        await waitFor("B received the unit", () =>
          p.B.events.some(
            (e) =>
              e.type === "unit" &&
              e.outcome.kind === "local-failure" &&
              toHex(e.outcome.unitId) === toHex(garbage.id),
          ),
        );
        const outcome = p.B.events.find(
          (e) =>
            e.type === "unit" &&
            toHex((e.outcome as { unitId: Uint8Array }).unitId) === toHex(garbage.id),
        );
        expect(outcome?.type === "unit" && outcome.outcome).toMatchObject({
          kind: "local-failure",
          reason: "AEAD",
        });
        expect(count(p.applied, garbage.id)).toBe(0);
        // No wire code: B sent no ERROR or NACK about it.
        expect(
          p.tapB.frames.filter(
            (f) =>
              f.direction === "out" && (f.message?.type === "ERROR" || f.message?.type === "NACK"),
          ),
        ).toEqual([]);
        // The next real unit links past it (G-DP1-GAP: 'previous' is the latest accepted unit).
        const next = await p.edit(p.A, "after the garbage");
        await waitFor(
          "B applies the next unit",
          () => titleOf(p.B, p.task) === "after the garbage",
        );
        expect(count(p.applied, next)).toBe(1);
      } finally {
        raw.close();
        await p.stop();
      }
    });
  }, 60_000);

  it("9. a revoked writer's write beyond the cutoff is STALE_DATA_EPOCH and never merges", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const raw = new RawSession({ url, signer: p.bob.signer });
      try {
        const appliedA = spyApply(p.A);
        await p.edit(p.B, "B before the revocation");
        await waitFor("B's unit ACKed", () => p.B.queueEmpty());
        await waitFor("A applies it", () => titleOf(p.A, p.task) === "B before the revocation");
        const staleView = (await loadControlChain(p.B.storage, p.R)) as Linear;
        await p.B.stop();
        // OWNER revokes BOB and rotates: epoch 0 closes at what OWNER accepted.
        let chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const grantId = [...chain.state.grants.values()].find(
          (g) => toHex(g.subject) === toHex(p.bob.signer.descriptor.principalId),
        )?.id as Uint8Array;
        const revoke = signControlRecord(
          { resourceId: p.R, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
          { type: "CAPABILITY_REVOKE", grantId: grantId as never },
          p.owner.signer,
        );
        await queueControlRecord(p.A.storage, revoke.bytes);
        const withRevoke = validateControlChain([
          ...chain.records.map((r) => r.signed.bytes),
          revoke.bytes,
        ]);
        if (withRevoke.kind !== "linear") throw new Error(withRevoke.kind);
        const frontier = (await resourceSyncState(p.A.storage, p.R)).have;
        const rotation = rotateEpoch(withRevoke.state, p.owner.signer, {
          reason: 1n,
          finalFrontier: frontier,
          dek: generateResourceDEK(),
        });
        await queueControlRecord(p.A.storage, rotation.bytes);
        p.A.client.flush();
        await waitFor("revoke and rotation ACKed", () => p.A.queueEmpty());
        await waitFor("A holds the rotation", async () => {
          chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
          return chain.state.epoch.epoch === 1n;
        });
        // BOB, offline with his stale view and the epoch-0 key, writes beyond his cutoff.
        const local = p.B.profile.replica.apply(
          setTitle(p.B.profile.replica.task(p.task)?.task as Task, "stale write").intent,
        ) as LocalChange;
        const stale = await createDataUnit({
          view: staleView,
          controlHead: staleView.state.head,
          actor: p.bob.signer,
          dek: p.dek,
          sequences: p.B.storage.actorSequences,
          previousUnitId: await latestAcceptedOwnUnit(
            p.B.storage,
            p.R,
            p.bob.signer.descriptor.principalId,
          ),
          profile: p.B.profile.codecFor({
            resourceId: p.R,
            actor: p.bob.signer.descriptor.principalId,
          }),
          value: checkChange(local.change),
        });
        await raw.connect();
        const answer = await raw.request(
          createMessage("DATA_PUT", { resourceId: p.R, objects: [stale.bytes] }),
        );
        expect(answer.type === "NACK" && codeName(answer.body.code)).toBe("STALE_DATA_EPOCH");
        // OWNER, given the bytes, quarantines them without merging.
        const before = appliedA.length;
        expect(await p.A.applier.receive(chain, stale.bytes)).toMatchObject({
          kind: "quarantined",
          code: "STALE_DATA_EPOCH",
        });
        expect(appliedA.length).toBe(before);
        expect(titleOf(p.A, p.task)).toBe("B before the revocation");
      } finally {
        raw.close();
        await p.stop();
      }
    });
  }, 90_000);

  it("10. an exact replay is harmless; a different unit at the same sequence is ACTOR_EQUIVOCATION", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const raw = new RawSession({ url, signer: p.owner.signer });
      try {
        const me = p.owner.signer.descriptor.principalId;
        const mine = await p.A.storage.dataUnits.range(p.R, me, 1n as never, MAX as never);
        const last = mine.at(-1) as (typeof mine)[number];
        await raw.connect();
        const replay = await raw.request(
          createMessage("DATA_PUT", { resourceId: p.R, objects: [last.bytes] }),
        );
        expect(replay.type).toBe("ACK");
        expect(count(p.applied, last.unitId)).toBe(1);
        // A second, different unit for OWNER's last sequence.
        const chain = (await loadControlChain(p.A.storage, p.R)) as Linear;
        const prev = parseDataUnit(last.bytes).payload.prevDataUnitId;
        const forked = SharedObjectsReplica.fromChanges(p.A.profile.replica.changes().slice(0, 1), {
          resource: p.R,
          principal: me,
        }).replica;
        const other = forked.apply(
          createTask({ title: "the other history", createdBy: me }).intent,
        ) as LocalChange;
        const twin = await createDataUnit({
          view: chain,
          controlHead: chain.state.head,
          actor: p.owner.signer,
          dek: p.dek,
          sequences: { reserveNext: () => Promise.resolve(last.actorSeq) },
          previousUnitId: prev,
          profile: p.A.profile.codecFor({ resourceId: p.R, actor: me }),
          value: checkChange(other.change),
        });
        const answer = await raw.request(
          createMessage("DATA_PUT", { resourceId: p.R, objects: [twin.bytes] }),
        );
        expect(answer.type === "NACK" && codeName(answer.body.code)).toBe("ACTOR_EQUIVOCATION");
        // Never pushed live to B, never applied.
        await p.edit(p.A, "after the equivocation attempt");
        await waitFor(
          "B sees a later unit",
          () => titleOf(p.B, p.task) === "after the equivocation attempt",
        );
        expect(p.tapB.frames.some((f) => unitsIn(f).includes(toHex(twin.unitId)))).toBe(false);
        expect(count(p.applied, twin.unitId)).toBe(0);
      } finally {
        raw.close();
        await p.stop();
      }
    });
  }, 60_000);
});

describe("LFCP-057: security assertions (live)", () => {
  it("an unauthenticated connection gets no Resource operation", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const replies: AnyMessage[] = [];
      const ws = platformWebSocket()(url, [LFCP_SUBPROTOCOL]);
      ws.binaryType = "arraybuffer";
      const opened = new Promise<void>((r) => {
        ws.onopen = () => r();
      });
      ws.onmessage = (ev) => {
        try {
          replies.push(decodeMessage(new Uint8Array(ev.data as ArrayBuffer)));
        } catch {
          // ignore undecodable
        }
      };
      await opened;
      ws.send(
        encodeMessage(
          createMessage("RESOURCE_OPEN", {
            resourceId: generateResourceId(),
            heads: [],
            haves: [],
          }),
        ),
      );
      await waitFor("an answer", () => replies.length > 0, 10_000);
      ws.close();
      const r = replies[0] as AnyMessage;
      expect(r.type === "NACK" && codeName(r.body.code)).toBe("AUTHORIZATION_FAILED");
    });
  }, 30_000);

  it("a hosting credential is not a capability: a stranger with one cannot open a Resource", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      const stranger = new RawSession({
        url,
        signer: fresh().signer,
        credential: Uint8Array.of(1, 2, 3, 4),
      });
      try {
        await stranger.connect();
        const r = await stranger.request(
          createMessage("RESOURCE_OPEN", { resourceId: p.R, heads: [], haves: [] }),
        );
        expect(r.type === "NACK" && codeName(r.body.code)).toBe("AUTHORIZATION_FAILED");
        const get = await stranger.request(
          createMessage("DATA_GET", {
            resourceId: p.R,
            ranges: [{ actor: p.owner.signer.descriptor.principalId, start: 1n, end: 5n }],
          }),
        );
        expect(get.type === "NACK" && codeName(get.body.code)).toBe("AUTHORIZATION_FAILED");
      } finally {
        stranger.close();
        await p.stop();
      }
    });
  }, 60_000);
});

/** mulberry32: a small seeded PRNG, so a failing seed replays exactly. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PR_SEEDS = [1, 2, 3];
const extra = Number(process.env.LFCP_CHAOS_SEEDS ?? "0");
const SEEDS =
  process.env.LFCP_CHAOS_SEED !== undefined
    ? [Number(process.env.LFCP_CHAOS_SEED)]
    : [...PR_SEEDS, ...Array.from({ length: extra }, (_, i) => 1000 + i)];

describe("LFCP-057: seeded faults (live)", () => {
  for (const seed of SEEDS)
    it(`seed ${seed}: drops, duplicates, delays and cuts on Data messages still converge`, async (ctx) => {
      const url = live(ctx);
      const random = prng(seed);
      const trace: string[] = [];
      const faulty =
        (name: string) =>
        (f: Frame): Action | undefined => {
          const data =
            (f.direction === "out" && f.message?.type === "DATA_PUT") ||
            (f.direction === "in" &&
              (f.message?.type === "DATA_BATCH" || f.message?.type === "ACK"));
          if (!data) return undefined;
          const r = random();
          const action: Action =
            r < 0.1
              ? { kind: "drop" }
              : r < 0.2
                ? { kind: "duplicate" }
                : r < 0.3
                  ? { kind: "delay", ms: Math.floor(random() * 150) }
                  : r < 0.33
                    ? { kind: "deliver-then-cut" }
                    : { kind: "deliver" };
          trace.push(
            `${name} ${f.direction} ${f.message?.type} c${f.connection}: ${JSON.stringify(action)}`,
          );
          return action;
        };
      const p = await pair(url);
      try {
        p.tapA.rule(faulty("A"));
        p.tapB.rule(faulty("B"));
        for (let i = 1; i <= 4; i++) {
          await p.edit(p.A, `A ${i}`);
          await p.edit(p.B, `B ${i}`);
        }
        await waitFor(
          "convergence",
          async () =>
            (await p.A.queueEmpty()) &&
            (await p.B.queueEmpty()) &&
            JSON.stringify(p.A.profile.replica.root()) ===
              JSON.stringify(p.B.profile.replica.root()),
          60_000,
        );
        const seqs = (
          await p.B.storage.dataUnits.range(
            p.R,
            p.bob.signer.descriptor.principalId,
            1n as never,
            MAX as never,
          )
        ).map((u) => u.actorSeq);
        expect(seqs).toEqual([1n, 2n, 3n, 4n]);
      } catch (e) {
        throw new Error(
          `seed ${seed} failed (replay with LFCP_CHAOS_SEED=${seed}): ${e instanceof Error ? e.message : String(e)}\n` +
            `--- action trace ---\n${trace.join("\n")}\n--- server log (tail) ---\n${server?.log().slice(-2000)}`,
        );
      } finally {
        await p.stop();
      }
    }, 120_000);
});

describe("LFCP-057: server restart (live; last, it restarts the shared server)", () => {
  it("5. units committed before a SIGKILL survive the restart; queued ones are sent after it", async (ctx) => {
    const url = live(ctx);
    await withLog(async () => {
      const p = await pair(url);
      try {
        await p.B.stop();
        const committed = [
          await p.edit(p.A, "c1"),
          await p.edit(p.A, "c2"),
          await p.edit(p.A, "c3"),
        ];
        await waitFor("committed units ACKed", () => p.A.queueEmpty());
        await (server as RunningRustServer).kill();
        const queued = [await p.edit(p.A, "q1"), await p.edit(p.A, "q2")];
        expect(await p.A.queueEmpty()).toBe(false);
        await (server as RunningRustServer).restart();
        await waitFor("queued units sent after the restart", () => p.A.queueEmpty(), 30_000);
        p.B.start();
        await waitFor("B catches up", () => titleOf(p.B, p.task) === "q2", 30_000);
        for (const id of [...committed, ...queued])
          expect((await p.B.storage.dataUnits.get(id))?.accepted).toBe(true);
      } finally {
        await p.stop();
      }
    });
  }, 120_000);
});
