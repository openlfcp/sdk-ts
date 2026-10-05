/// <reference lib="dom" />
import "fake-indexeddb/auto";
import {
  actorSequence,
  controlRecordId,
  dataEpoch,
  dataUnitId,
  hash32,
  LfcpError,
  principalId,
  resourceId,
} from "@openlfcp/core";
import type { DataUnitRow } from "@openlfcp/storage";
import { afterEach, describe, expect, it } from "vitest";
import { IdbLfcpStorage, type ReservedSequence } from "../src/index.js";

const id = (b: number) => new Uint8Array(32).fill(b);
const R = resourceId(id(1));
const ALICE = principalId(id(10));
const E0 = dataEpoch(0n);
const unit = (n: number, seq: bigint): DataUnitRow => ({
  unitId: dataUnitId(id(150 + n)),
  resourceId: R,
  dataEpoch: E0,
  actor: ALICE,
  actorSeq: actorSequence(seq),
  prevDataUnitId: null,
  controlHead: controlRecordId(id(100)),
  bytes: Uint8Array.of(0xd2, n),
});

let n = 0;
const open: IdbLfcpStorage[] = [];
async function fresh(options: Parameters<typeof IdbLfcpStorage.open>[1] = {}) {
  const name = `idb-${++n}`;
  const s = await IdbLfcpStorage.open(name, options);
  open.push(s);
  return { name, s };
}
afterEach(() => {
  for (const s of open.splice(0)) s.close();
});

describe("IdbLfcpStorage (LFCP-059)", () => {
  it("asks for strict durability on every readwrite transaction", async () => {
    const proto = IDBDatabase.prototype;
    const original = proto.transaction;
    const seen: { mode: string | undefined; durability: string | undefined }[] = [];
    proto.transaction = function (this: IDBDatabase, ...args: Parameters<typeof original>) {
      seen.push({ mode: args[1], durability: args[2]?.durability });
      return original.apply(this, args);
    } as typeof original;
    try {
      const { s } = await fresh();
      await s.actorSequences.reserveNext(R, ALICE);
      await s.commit([{ op: "put-data-unit", unit: unit(1, 1n), status: "seen" }]);
      await s.dataUnits.recordSeen(unit(2, 2n));
      await s.snapshotSequences.reserveNext(R, E0, ALICE);
      await s.meta.put("k", 1);
      await s.dataUnits.get(dataUnitId(id(151)));
    } finally {
      proto.transaction = original;
    }
    const writes = seen.filter((x) => x.mode === "readwrite");
    expect(writes.length).toBe(5);
    expect(writes.every((x) => x.durability === "strict")).toBe(true);
  });

  it("reports each durable reservation, and abandons it when the hook throws", async () => {
    const reported: ReservedSequence[] = [];
    let fail = false;
    const { s } = await fresh({
      onReserved: (r) => {
        if (fail) throw new Error("mirror unavailable");
        reported.push(r);
      },
    });
    expect(await s.actorSequences.reserveNext(R, ALICE)).toBe(1n);
    fail = true;
    await expect(s.actorSequences.reserveNext(R, ALICE)).rejects.toThrow("mirror unavailable");
    fail = false;
    expect(await s.actorSequences.reserveNext(R, ALICE)).toBe(3n); // 2 was abandoned
    expect(await s.snapshotSequences.reserveNext(R, E0, ALICE)).toBe(1n);
    expect(reported.map((r) => [r.kind, r.value])).toEqual([
      ["actor", 1n],
      ["actor", 3n],
      ["snapshot", 1n],
    ]);
    expect(Object.fromEntries(await s.counters())).toEqual({
      [reported[0]?.key as string]: 3n,
      [reported[2]?.key as string]: 1n,
    });
  });

  it("lists only reservation counters, and keeps them and metadata across a reopen", async () => {
    const { name, s } = await fresh();
    await s.commit([
      {
        op: "enqueue",
        item: {
          itemId: hash32(id(151)),
          resourceId: R,
          kind: "data-unit",
          bytes: Uint8Array.of(1),
          attempts: 0,
          lastAttempt: null,
          nextAttempt: null,
          blocked: null,
        },
      },
    ]);
    await s.actorSequences.reserveNext(R, ALICE);
    await s.meta.put("install", { installId: "abc", principal: "p" });
    s.close();
    const again = await IdbLfcpStorage.open(name);
    open.push(again);
    expect([...(await again.counters()).values()]).toEqual([1n]);
    expect(await again.meta.get("install")).toEqual({ installId: "abc", principal: "p" });
    expect(await again.meta.get("missing")).toBeUndefined();
  });

  it("fails clearly where IndexedDB is missing", async () => {
    const g = globalThis as { indexedDB?: IDBFactory };
    const saved = g.indexedDB;
    delete g.indexedDB;
    try {
      await expect(IdbLfcpStorage.open("y")).rejects.toBeInstanceOf(LfcpError);
    } finally {
      g.indexedDB = saved as IDBFactory;
    }
  });
});
