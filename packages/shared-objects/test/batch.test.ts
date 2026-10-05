import * as A from "@automerge/automerge";
import {
  type DataUnitId,
  dataUnitId,
  type ObjectId,
  principalId,
  resourceId,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  checkChange,
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "../src/index.js";
import { applyBatchChecked } from "../src/replica.js";

// Receiving many changes at once (receiveChanges, applyBatch): the §14.1
// rules of receiveChange, with ONE Automerge call per batch (one call per
// change is quadratic). Synthetic values.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xb0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const BOB = principalId(Uint8Array.from({ length: 32 }, (_, i) => 64 + i));
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });
const unit = (n: number): DataUnitId => dataUnitId(Uint8Array.from({ length: 32 }, () => n));

/** Alice's history: init, create, then `n` title changes. */
function history(n: number) {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const created = replica.apply(
    createTask({ id: ID, title: "t", createdBy: ALICE }).intent,
  ) as LocalChange;
  const titles: LocalChange[] = [];
  for (let i = 0; i < n; i++)
    titles.push(
      replica.apply(setTitle(replica.task(ID)?.task as Task, `t${i}`).intent) as LocalChange,
    );
  return { replica, changes: [init, created, ...titles] };
}

const withSeq = (change: Uint8Array, seq: number): Uint8Array => {
  const { hash: _, ...rest } = A.decodeChange(change);
  return A.encodeChange({ ...rest, seq });
};

describe("receiveChanges", () => {
  it("converges from any order with duplicates, in one batch", () => {
    const { replica, changes } = history(20);
    const bytes = changes.map((c) => c.change).reverse();
    const r = SharedObjectsReplica.empty(opts(BOB));
    const result = r.receiveChanges([...bytes, ...bytes]);
    expect(result.applied).toHaveLength(changes.length);
    expect(result.waiting).toEqual([]);
    expect(result.refused).toEqual([]);
    expect(r.heads()).toEqual(replica.heads());
    expect(result.objects.map((o) => o.objectId)).toEqual([ID]);
    // Again: all duplicates, nothing new.
    const again = r.receiveChanges(bytes);
    expect(again.applied).toEqual([]);
    expect(again.duplicates).toHaveLength(changes.length);
  });

  it("keeps changes without their dependencies outside the engine", () => {
    const { changes } = history(3);
    const r = SharedObjectsReplica.empty(opts(BOB));
    const result = r.receiveChanges(changes.slice(1).map((c) => c.change));
    expect(result.waiting).toHaveLength(changes.length - 1);
    expect(r.changes()).toEqual([]);
    expect(r.heads()).toEqual([]);
  });

  it("refuses a skipping or equivocating change and applies the rest; the replica stays sound", () => {
    const { changes } = history(3);
    const [init, created, t0, t1] = changes as [LocalChange, LocalChange, LocalChange, LocalChange];
    // t0 claiming sequence 4 (a gap), and an equivocating twin of created.
    const twinSource = SharedObjectsReplica.empty(opts());
    twinSource.receiveChange(init.change);
    const twin = twinSource.apply(
      createTask({
        id: "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId,
        title: "x",
        createdBy: ALICE,
      }).intent,
    ) as LocalChange;
    const r = SharedObjectsReplica.empty(opts(BOB));
    const result = r.receiveChanges([
      init.change,
      created.change,
      twin.change,
      withSeq(t0.change, 4),
    ]);
    expect(result.applied.map((c) => c.hash)).toEqual([init.hash, created.hash]);
    expect(result.refused.map((x) => [x.change.hash, x.error.code])).toEqual([
      [twin.hash, "ACTOR_EQUIVOCATION"],
      [checkChange(withSeq(t0.change, 4)).hash, "PROFILE_INVALID"],
    ]);
    // The real t0 and t1 still apply; the replica writes, saves and loads.
    expect(r.receiveChanges([t1.change, t0.change]).applied).toHaveLength(2);
    r.apply(setStatus(r.task(ID)?.task as Task, "done").intent);
    const reloaded = SharedObjectsReplica.fromSave(r.save(), opts(BOB));
    expect(reloaded.task(ID)?.task).toMatchObject({ title: "t1", status: "done" });
  });

  it("restores the document when the engine fails on a batch (pre-check bypassed)", () => {
    const { changes } = history(2);
    const [init, created, t0] = changes as [LocalChange, LocalChange, LocalChange];
    const [doc] = A.applyChanges(A.init(), [init.change, created.change]);
    const heads = [...A.getHeads(doc)].sort();
    const state = JSON.stringify(A.toJS(doc));
    const result = applyBatchChecked(doc, [checkChange(withSeq(t0.change, 4))]);
    if (!("error" in result)) throw new Error("Automerge accepted a skipping change");
    expect([...A.getHeads(result.restored)].sort()).toEqual(heads);
    expect(JSON.stringify(A.toJS(A.load(A.save(result.restored))))).toBe(state);
  });
});

describe("SharedObjectsDataProfile.applyBatch", () => {
  it("merges a reversed batch, buffers what waits, rejects only the refused unit", () => {
    const { changes } = history(5);
    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    const units = changes.map((c, i) => ({
      unit: { unitId: unit(i + 1) },
      value: checkChange(c.change),
    }));
    // Without the first unit everything waits.
    const first = profile.applyBatch(units.slice(1).reverse());
    expect(first.merged).toEqual([]);
    expect(first.pending).toHaveLength(units.length - 1);
    // The first unit releases all the buffered ones in one engine call.
    const second = profile.applyBatch([units[0] as (typeof units)[number]]);
    expect(second.merged).toHaveLength(units.length);
    expect(second.pending).toEqual([]);
    expect(second.objects).toEqual([ID]);
    expect(second.diagnostics).toEqual([]);
    // A taken sequence rejects that unit only.
    const twin = withSeq(changes[2]?.change as Uint8Array, 2);
    const third = profile.applyBatch([{ unit: { unitId: unit(99) }, value: checkChange(twin) }]);
    expect(third.rejected.map((r) => r.code)).toEqual(["ACTOR_EQUIVOCATION"]);
    expect(profile.has(unit(99))).toBe(false);
  });
});
