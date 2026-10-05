import * as A from "@automerge/automerge";
import { type ObjectId, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  createTask,
  type LocalChange,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "../src/index.js";
import { applyChecked } from "../src/replica.js";

// SHARED-OBJECTS-PROFILE-01 §9 and §14.1 (SPEC-PATCH-06 item 7): a writer
// keeps writing after a rebuild removes its own changes, a change with a
// missing dependency never enters the engine, and a change that skips its
// actor's sequence is refused before Automerge sees it. Synthetic values.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const BOB = principalId(Uint8Array.from({ length: 32 }, (_, i) => 64 + i));
const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const opts = (principal = ALICE, minSeq?: number) => ({
  resource: RESOURCE,
  principal,
  ...(minSeq === undefined ? {} : { minSeq }),
});

/** Alice's changes 1 (init), 2 (create), 3 (title) and 4 (status, on 3). */
function alice() {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const create = replica.apply(
    createTask({ id: ID, title: "Draft", createdBy: ALICE }).intent,
  ) as LocalChange;
  const task = () => replica.task(ID)?.task as Task;
  const title = replica.apply(setTitle(task(), "Final").intent) as LocalChange;
  const status = replica.apply(setStatus(task(), "done").intent) as LocalChange;
  return { replica, init, create, title, status, task };
}

/** `change` re-encoded with another sequence number (a crafted change). */
function withSeq(change: Uint8Array, seq: number): Uint8Array {
  const decoded = A.decodeChange(change);
  const { hash: _, ...rest } = decoded;
  return A.encodeChange({ ...rest, seq });
}

describe("a change that skips its actor's sequence (§14.1)", () => {
  it("is INVALID_AUTOMERGE_BYTES before Automerge sees it, and the replica stays sound", () => {
    const a = alice();
    const carol = SharedObjectsReplica.empty(opts(CAROL));
    carol.receiveChange(a.init.change);
    carol.receiveChange(a.create.change);
    const before = JSON.stringify(carol.root());
    // Change 3 claiming sequence 4: its dependency (2) is present, sequence 3 is not.
    expect(() => carol.receiveChange(withSeq(a.title.change, 4))).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" }),
    );
    expect(JSON.stringify(carol.root())).toBe(before);
    expect(carol.receiveChange(a.title.change).status).toBe("applied");
    carol.apply(setStatus(carol.task(ID)?.task as Task, "in_progress").intent);
    const reloaded = SharedObjectsReplica.fromSave(carol.save(), opts(CAROL));
    expect(JSON.stringify(reloaded.root())).toBe(JSON.stringify(carol.root()));
    expect(reloaded.task(ID)?.task).toMatchObject({ title: "Final", status: "in_progress" });
  });

  it("leaves no half-applied state when the engine itself throws (pre-check bypassed)", () => {
    const a = alice();
    const [doc] = A.applyChanges(A.init(), [a.init.change, a.create.change]);
    const heads = [...A.getHeads(doc)].sort();
    const state = JSON.stringify(A.toJS(doc));
    const result = applyChecked(doc, withSeq(a.title.change, 4));
    if (!("error" in result)) throw new Error("Automerge accepted a skipping change");
    expect([...A.getHeads(result.restored)].sort()).toEqual(heads);
    expect(JSON.stringify(A.toJS(A.load(A.save(result.restored))))).toBe(state);
    const written = A.change(result.restored, (d) => {
      d.extra = 1;
    });
    const reloaded = A.load(A.save(written));
    expect(JSON.parse(JSON.stringify(A.toJS(reloaded)))).toEqual({
      ...JSON.parse(state),
      extra: 1,
    });
  });
});

describe("own changes removed by a rebuild (§9, §14.1)", () => {
  it("do not stop the writer: the next change reuses the removed sequence", () => {
    const a = alice();
    expect(a.replica.actorSeq).toBe(4);
    const { replica, unapplied } = a.replica.rebuildWithout([a.title.hash]);
    expect(unapplied.map((c) => c.hash)).toEqual([a.status.hash]); // builds on 3
    expect([replica.actorSeq, replica.writable]).toEqual([2, true]);
    expect(replica.task(ID)?.task).toMatchObject({ title: "Draft", status: "todo" });
    const again = replica.apply(
      setTitle(replica.task(ID)?.task as Task, "Re-applied").intent,
    ) as LocalChange;
    expect(again.seq).toBe(3);
    expect(again.hash).not.toBe(a.title.hash);
  });

  it("refuses the removed change once the reissue is merged (ACTOR_EQUIVOCATION)", () => {
    const a = alice();
    const { replica } = a.replica.rebuildWithout([a.title.hash]);
    replica.apply(setTitle(replica.task(ID)?.task as Task, "Re-applied").intent);
    expect(() => replica.receiveChange(a.title.change)).toThrow(
      expect.objectContaining({ code: "ACTOR_EQUIVOCATION" }),
    );
  });

  it("keep a replica that was already behind its persisted sequence refused", () => {
    const a = alice();
    const behind = SharedObjectsReplica.fromChanges(
      [a.init.change, a.create.change],
      opts(ALICE, 4),
    ).replica;
    expect(behind.writable).toBe(false);
    const { replica } = behind.rebuildWithout([]);
    expect(replica.writable).toBe(false);
    expect(() => replica.apply(setTitle(replica.task(ID)?.task as Task, "x").intent)).toThrow(
      expect.objectContaining({ code: "SEQUENCE_REUSE" }),
    );
  });

  it("let an innocent dependent writer reissue: the receiver never queued the dead change", () => {
    const a = alice();
    // Bob merged Alice's 1..3 and wrote on top of 3.
    const bob = SharedObjectsReplica.fromChanges(
      [a.init.change, a.create.change, a.title.change],
      opts(BOB),
    ).replica;
    const onTitle = bob.apply(
      setStatus(bob.task(ID)?.task as Task, "in_progress").intent,
    ) as LocalChange;
    expect(onTitle.seq).toBe(1);
    // A cutoff removes Alice's 3; Bob's change goes with it, and Bob writes again.
    const rebuilt = bob.rebuildWithout([a.title.hash]);
    expect(rebuilt.unapplied.map((c) => c.hash)).toEqual([onTitle.hash]);
    const reissued = rebuilt.replica.apply(
      setStatus(rebuilt.replica.task(ID)?.task as Task, "in_progress").intent,
    ) as LocalChange;
    expect(reissued.seq).toBe(1);
    // Carol accepted Bob's first unit without Alice's 3: it stays outside the engine.
    const carol = SharedObjectsReplica.empty(opts(CAROL));
    carol.receiveChange(a.init.change);
    carol.receiveChange(a.create.change);
    expect(carol.receiveChange(onTitle.change).status).toBe("missing_dependencies");
    expect(carol.receiveChange(reissued.change).status).toBe("applied");
    expect(carol.receiveChange(onTitle.change).status).toBe("missing_dependencies");
    expect(carol.task(ID)?.task).toMatchObject({ title: "Draft", status: "in_progress" });
    expect(JSON.stringify(carol.root())).toBe(JSON.stringify(rebuilt.replica.root()));
  });
});
