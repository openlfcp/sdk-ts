import {
  actorSequence,
  controlRecordId,
  dataEpoch,
  dataUnitId,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  type DataUnitRow,
  InMemoryLfcpStorage,
  type LfcpStorage,
  type StorageWrite,
} from "@openlfcp/storage";
import { describe, expect, it } from "vitest";
import { ReceiveBatchStorage } from "../src/receive-batch.js";

const id = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) & 0xff);
const R = resourceId(id(1));
const ALICE = principalId(id(2));
const unit = (n: number, seq: bigint): DataUnitRow => ({
  unitId: dataUnitId(id(150 + n)),
  resourceId: R,
  dataEpoch: dataEpoch(0n),
  actor: ALICE,
  actorSeq: actorSequence(seq),
  prevDataUnitId: null,
  controlHead: controlRecordId(id(100)),
  bytes: Uint8Array.of(0xd2, 0x84, n, Number(seq), 0, 0xff),
});

/** The storage under the batch, recording every commit it gets. */
function recorded() {
  const inner = new InMemoryLfcpStorage();
  const commits: (readonly StorageWrite[])[] = [];
  const storage: Pick<LfcpStorage, "dataUnits" | "snapshots" | "commit" | "localMarks"> = {
    dataUnits: inner.dataUnits,
    snapshots: inner.snapshots,
    localMarks: inner.localMarks,
    commit: (writes) => {
      commits.push(writes);
      return inner.commit(writes);
    },
  };
  return { inner, commits, batch: new ReceiveBatchStorage(storage) };
}

const hex = (ids: readonly Uint8Array[]) => ids.map(toHex);

describe("ReceiveBatchStorage (E-030l)", () => {
  it("holds a batch's unit writes, reads them back, and commits them once at the end", async () => {
    const { inner, commits, batch } = recorded();
    const a = unit(1, 1n);
    const b = unit(2, 2n);
    await batch.batch(async () => {
      expect(await batch.dataUnits.recordSeen(a)).toEqual({ unitIds: [a.unitId], firstSeen: true });
      expect((await batch.dataUnits.recordSeen(a)).firstSeen).toBe(false);
      await batch.commit([{ op: "set-accepted", unitId: a.unitId, accepted: true }]);
      await batch.commit([{ op: "set-data-unit-status", unitId: a.unitId, status: "merged" }]);
      await batch.dataUnits.recordSeen(b);
      // Read-your-writes: the checks of the next unit see the units before it.
      expect(await batch.dataUnits.acceptedAt(R, ALICE, actorSequence(1n))).toEqual(a.unitId);
      expect(hex((await batch.dataUnits.withStatus(R, "merged")).map((u) => u.unitId))).toEqual(
        hex([a.unitId]),
      );
      expect(
        (await batch.dataUnits.range(R, ALICE, actorSequence(1n), actorSequence(9n))).map(
          (u) => u.status,
        ),
      ).toEqual(["merged", "seen"]);
      // Nothing is stored yet.
      expect(commits).toHaveLength(0);
      expect(await inner.dataUnits.get(a.unitId)).toBeUndefined();
    });
    expect(commits).toHaveLength(1);
    expect(commits[0]?.map((w) => w.op)).toEqual(["put-data-unit", "put-data-unit"]);
    expect(await inner.dataUnits.get(a.unitId)).toMatchObject({ status: "merged", accepted: true });
    expect(await inner.dataUnits.get(b.unitId)).toMatchObject({ status: "seen", accepted: false });
  });

  it("sees an equivocating twin in the same batch, and one already stored", async () => {
    const { inner, batch } = recorded();
    const a = unit(1, 1n);
    const twin = unit(2, 1n);
    const third = unit(3, 1n);
    await inner.dataUnits.recordSeen(a);
    await batch.batch(async () => {
      expect(hex((await batch.dataUnits.recordSeen(twin)).unitIds)).toEqual(
        hex([a.unitId, twin.unitId]),
      );
      expect(hex((await batch.dataUnits.recordSeen(third)).unitIds)).toEqual(
        hex([a.unitId, twin.unitId, third.unitId]),
      );
      await expect(
        batch.dataUnits.recordSeen({ ...twin, bytes: Uint8Array.of(1) }),
      ).rejects.toThrow(/other bytes/);
    });
    expect(await inner.dataUnits.at(R, ALICE, actorSequence(1n))).toHaveLength(3);
  });

  it("flushes held writes before any other write, so storage sees them in order", async () => {
    const { commits, batch } = recorded();
    const a = unit(1, 1n);
    await batch.batch(async () => {
      await batch.dataUnits.recordSeen(a);
      await batch.commit([{ op: "put-local-mark", key: "k", value: "v" }]);
    });
    expect(commits.map((c) => c.map((w) => w.op))).toEqual([["put-data-unit"], ["put-local-mark"]]);
  });

  it("passes a write for an unknown unit to storage, which refuses it as before", async () => {
    const { inner, batch } = recorded();
    const plain = new InMemoryLfcpStorage();
    const missing = { op: "set-accepted", unitId: unit(9, 1n).unitId, accepted: true } as const;
    const refused = await plain.commit([missing]).catch((e: unknown) => e);
    const a = unit(1, 1n);
    const got = await batch
      .batch(async () => {
        await batch.dataUnits.recordSeen(a);
        await batch.commit([missing]);
      })
      .catch((e: unknown) => e);
    expect(String(got)).toEqual(String(refused));
    // The work before it stays durable.
    expect(await inner.dataUnits.get(a.unitId)).toBeDefined();
  });

  it("commits what the batch did when it throws, and passes through outside a batch", async () => {
    const { inner, commits, batch } = recorded();
    const a = unit(1, 1n);
    await expect(
      batch.batch(async () => {
        await batch.dataUnits.recordSeen(a);
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(await inner.dataUnits.get(a.unitId)).toBeDefined();
    commits.length = 0;
    await batch.commit([{ op: "set-data-unit-status", unitId: a.unitId, status: "held" }]);
    expect(commits).toHaveLength(1);
    expect((await inner.dataUnits.get(a.unitId))?.status).toBe("held");
  });
});
