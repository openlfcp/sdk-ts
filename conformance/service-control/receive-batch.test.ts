// E-030l: the receive path commits one storage transaction per DATA_BATCH for the "seen",
// accepted and status writes of its units, on both durable storages: SQLite (the bridge's) and
// IndexedDB (the plugin's, here fake-indexeddb). Nothing of a batch is stored, so nothing
// advertises it (the Have Vector is built from storage, W §68 step 10), before that commit; a
// crash before it loses the whole batch, which is fetched again and received again with nothing
// lost or duplicated (W §70: delivery is at-least-once).

import "fake-indexeddb/auto";

import { dataUnitRow, resourceSyncState } from "@openlfcp/client";
import {
  InMemoryLfcpStorage,
  type LfcpStorage,
  type StorageWrite,
  type StoredDataUnit,
} from "@openlfcp/storage";
import { IdbLfcpStorage } from "@openlfcp/storage-idb";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import { beforeAll, describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";
import { sealedYear } from "./sealed-year.js";

type Durable = LfcpStorage & { close(): void };

/** A durable storage that can be closed and opened again, as a process restart would. */
interface Backend {
  readonly name: string;
  open(): Promise<Durable>;
  dispose(): void;
}

let idbCount = 0;
const backends: (() => Backend)[] = [
  () => {
    const dir = makeTempDir("lfcp-receive-batch-");
    return {
      name: "sqlite",
      open: async () => SqliteLfcpStorage.open(inDir(dir, "lfcp.sqlite")),
      dispose: () => removeTempDir(dir),
    };
  },
  () => {
    const name = `lfcp-receive-batch-${++idbCount}`;
    return { name: "idb", open: () => IdbLfcpStorage.open(name), dispose: () => {} };
  },
];

/** Counts the transactions the receive path opens: commits, and recordSeen (its own one). */
function counted(inner: LfcpStorage, onUnitCommit?: () => Promise<void>) {
  const n = { commits: 0, unitCommits: 0, recordSeen: 0 };
  const isUnitWrite = (w: StorageWrite) =>
    w.op === "put-data-unit" || w.op === "set-data-unit-status" || w.op === "set-accepted";
  const storage: LfcpStorage = Object.create(inner);
  Object.defineProperty(storage, "dataUnits", {
    value: {
      ...inner.dataUnits,
      recordSeen: (unit: Parameters<LfcpStorage["dataUnits"]["recordSeen"]>[0]) => {
        n.recordSeen += 1;
        return inner.dataUnits.recordSeen(unit);
      },
    },
  });
  Object.defineProperty(storage, "commit", {
    value: async (writes: readonly StorageWrite[]) => {
      n.commits += 1;
      if (writes.some(isUnitWrite)) {
        n.unitCommits += 1;
        await onUnitCommit?.();
      }
      return inner.commit(writes);
    },
  });
  return { storage, n };
}

const DAYS = 2;
const BATCH = 40;

describe("E-030l: one storage transaction per DATA_BATCH on the receive path", () => {
  let year: Awaited<ReturnType<typeof sealedYear>>;
  let reference: unknown;
  beforeAll(async () => {
    year = await sealedYear(DAYS);
    // What a client that never crashed holds: the profile state after every unit.
    const { profile, applier } = year.client(new InMemoryLfcpStorage());
    await applier.receiveBatch(year.view, year.sealed);
    reference = profile.state();
  }, 120_000);

  const batches = () => {
    const out: Uint8Array[][] = [];
    for (let i = 0; i < year.sealed.length; i += BATCH) out.push(year.sealed.slice(i, i + BATCH));
    return out;
  };

  /** Every unit stored once, merged and accepted; nothing else of the Resource stored. */
  async function expectAllMerged(storage: LfcpStorage) {
    const stored: StoredDataUnit[] = [];
    for (const bytes of year.sealed) {
      const u = await storage.dataUnits.get(dataUnitRow(bytes).unitId);
      expect(u, "every unit is stored").toBeDefined();
      stored.push(u as StoredDataUnit);
    }
    expect(stored.every((u) => u.status === "merged" && u.accepted)).toBe(true);
    expect(await storage.dataUnits.withStatus(year.resourceId, "merged")).toHaveLength(
      year.sealed.length,
    );
    for (const s of ["seen", "held", "profile-pending", "equivocation"] as const)
      expect(await storage.dataUnits.withStatus(year.resourceId, s)).toHaveLength(0);
  }

  for (const make of backends) {
    describe(make().name, () => {
      it("commits the seen, accepted and merged writes of a batch in one transaction", async () => {
        const backend = make();
        const durable = await backend.open();
        try {
          const { storage, n } = counted(durable);
          const { profile, applier } = year.client(storage);
          const runs = batches();
          expect(runs.length).toBeGreaterThan(1);
          for (const run of runs) {
            const before = { ...n };
            const outcomes = await applier.receiveBatch(year.view, run);
            expect(outcomes.map((o) => o.kind)).toEqual(run.map(() => "applied"));
            // One transaction for the units' writes; the crash-loop record is the other two.
            expect(n.unitCommits - before.unitCommits).toBe(1);
            expect(n.recordSeen - before.recordSeen).toBe(0);
            expect(n.commits - before.commits).toBe(3);
          }
          expect(profile.state()).toEqual(reference);
          await expectAllMerged(durable);
          // A replay of everything is a duplicate, and stores nothing.
          const before = { ...n };
          const again = await applier.receiveBatch(year.view, year.sealed);
          expect(new Set(again.map((o) => o.kind))).toEqual(new Set(["duplicate"]));
          expect(n.unitCommits - before.unitCommits).toBe(0);
        } finally {
          durable.close();
          backend.dispose();
        }
      });

      it("a crash before the batch commit: nothing stored or advertised, refetched and applied once", async () => {
        const [first, second, ...rest] = batches();
        if (first === undefined || second === undefined) throw new Error("too few units");
        const backend = make();
        const durable = await backend.open();
        const have = async () => (await resourceSyncState(durable, year.resourceId)).have;
        let crash = false;
        let atCommit: { stored: number; have: unknown } | undefined;
        const { storage } = counted(durable, async () => {
          if (!crash) return;
          // What storage holds when the batch commit starts: none of its units.
          let stored = 0;
          for (const bytes of second)
            if ((await durable.dataUnits.get(dataUnitRow(bytes).unitId)) !== undefined) stored += 1;
          atCommit = { stored, have: await have() };
          // The process dies here, before the commit writes anything.
          throw new Error("crash before the batch commit");
        });
        const { applier } = year.client(storage);
        const applied = await applier.receiveBatch(year.view, first);
        expect(applied.map((o) => o.kind)).toEqual(first.map(() => "applied"));
        const haveAfterFirst = await have();

        // The batch is verified, admitted and merged in memory; its commit never happens.
        crash = true;
        await expect(applier.receiveBatch(year.view, second)).rejects.toThrow(
          "crash before the batch commit",
        );
        expect(atCommit).toEqual({ stored: 0, have: haveAfterFirst });
        // Nothing of it reached storage, so nothing of it is advertised (DATA_HAVE).
        for (const bytes of second)
          expect(await durable.dataUnits.get(dataUnitRow(bytes).unitId)).toBeUndefined();
        expect(await have()).toEqual(haveAfterFirst);
        durable.close();

        // Restart: storage opened again, the profile rebuilt from what is stored.
        const reopened = await backend.open();
        try {
          const { profile, applier: restarted } = year.client(reopened);
          await restarted.replayStored(year.view);
          // The sync engine asks again for what it lacks: the crashed batch, whole.
          const refetched = await restarted.receiveBatch(year.view, second);
          expect(refetched.map((o) => o.kind)).toEqual(second.map(() => "applied"));
          for (const run of rest) {
            const outcomes = await restarted.receiveBatch(year.view, run);
            expect(outcomes.map((o) => o.kind)).toEqual(run.map(() => "applied"));
          }
          // At-least-once: the whole history again is all duplicates.
          const again = await restarted.receiveBatch(year.view, year.sealed);
          expect(new Set(again.map((o) => o.kind))).toEqual(new Set(["duplicate"]));
          expect(profile.state()).toEqual(reference);
          await expectAllMerged(reopened);
        } finally {
          reopened.close();
          backend.dispose();
        }
      });
    });
  }
});
