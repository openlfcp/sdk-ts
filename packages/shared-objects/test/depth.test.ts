import * as A from "@automerge/automerge";
import { type ObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { MAX_DOCUMENT_DEPTH } from "../src/admission/limits.js";
import {
  createTask,
  deriveActorId,
  frameSnapshot,
  type LocalChange,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "../src/index.js";

// SHARED-OBJECTS-PROFILE-01 §11.2 (SPEC-PATCH-08): no object deeper than 256
// levels below the root, checked before the Automerge engine. Automerge JS
// 3.5.0 traps applying about 6,500 levels and its wasm module stays
// terminated, so a deep change must never reach it. Synthetic values only.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });
const ACTOR = toHex(deriveActorId(RESOURCE, ALICE));
const invalidBytes = expect.objectContaining({
  code: "PROFILE_INVALID",
  diagnostic: "INVALID_AUTOMERGE_BYTES",
});

function alice() {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const create = replica.apply(
    createTask({ id: ID, title: "Draft", createdBy: ALICE }).intent,
  ) as LocalChange;
  return { replica, init, create };
}

/** Alice's next change: `levels` maps nested from `parent` (the root by default), each under the last. */
function nested(
  after: Uint8Array,
  levels: number,
  options: { parent?: string; seq?: number; last?: string } = {},
): Uint8Array {
  const base = A.decodeChange(after);
  const startOp = base.startOp + base.ops.length;
  let parent = options.parent ?? "_root";
  const ops = Array.from({ length: levels }, (_, i) => {
    const op = {
      action: i === levels - 1 && options.last !== undefined ? options.last : "makeMap",
      obj: parent,
      key: "d",
      pred: [],
    };
    parent = `${startOp + i}@${ACTOR}`;
    return op;
  });
  return A.encodeChange({
    actor: ACTOR,
    seq: options.seq ?? base.seq + 1,
    startOp,
    time: 0,
    message: null,
    deps: [base.hash],
    ops,
  } as never);
}

const receiver = (a: ReturnType<typeof alice>) =>
  SharedObjectsReplica.fromChanges([a.init.change, a.create.change], opts(CAROL)).replica;

describe("changes (§11.2)", () => {
  it("accepts an object at depth 256 and refuses depth 257, on both receive paths", () => {
    const a = alice();
    expect(receiver(a).receiveChange(nested(a.create.change, MAX_DOCUMENT_DEPTH)).status).toBe(
      "applied",
    );
    const deep = nested(a.create.change, MAX_DOCUMENT_DEPTH + 1);
    expect(() => receiver(a).receiveChange(deep)).toThrow(invalidBytes);
    expect(
      receiver(a)
        .receiveChanges([deep])
        .refused.map((r) => r.error),
    ).toEqual([invalidBytes]);
    // Every object kind counts: a text object at depth 257.
    const text = nested(a.create.change, MAX_DOCUMENT_DEPTH + 1, { last: "makeText" });
    expect(() => receiver(a).receiveChange(text)).toThrow(invalidBytes);
  });

  it("counts depth across changes: the change that crosses 256 is refused, its dependents held", () => {
    const a = alice();
    const r = receiver(a);
    let last = a.create.change;
    let parent = "_root";
    const outcomes: string[] = [];
    for (let k = 0; k < 10; k++) {
      const c = nested(last, 30, { parent });
      const decoded = A.decodeChange(c);
      parent = `${decoded.startOp + 29}@${ACTOR}`;
      last = c;
      try {
        outcomes.push(r.receiveChange(c).status);
      } catch {
        outcomes.push("refused");
      }
    }
    expect(outcomes).toEqual([...Array(8).fill("applied"), "refused", "missing_dependencies"]);
  });

  it("refuses 10,000 levels at once, before the engine could trap", () => {
    const a = alice();
    const r = receiver(a);
    const t = performance.now();
    expect(() => r.receiveChange(nested(a.create.change, 10_000))).toThrow(invalidBytes);
    expect(performance.now() - t).toBeLessThan(1_000);
    // The engine is alive and the replica usable.
    r.apply(setTitle(r.task(ID)?.task as Task, "After").intent);
    expect(r.task(ID)?.task?.title).toBe("After");
  });

  it("knows the depth of a deleted parent (from the history) and refuses an unknown one", () => {
    const a = alice();
    // A map at depth 1 under the root, then deleted.
    const made = nested(a.create.change, 1);
    const id = `${A.decodeChange(made).startOp}@${ACTOR}`;
    const deleted = A.encodeChange({
      actor: ACTOR,
      seq: A.decodeChange(made).seq + 1,
      startOp: A.decodeChange(made).startOp + 1,
      time: 0,
      message: null,
      deps: [A.decodeChange(made).hash],
      ops: [{ action: "del", obj: "_root", key: "d", pred: [id] }],
    } as never);
    // A fresh replica of that history (no cached depths) receives a child of the deleted map.
    const r = SharedObjectsReplica.fromChanges(
      [a.init.change, a.create.change, made, deleted],
      opts(CAROL),
    ).replica;
    expect(r.receiveChange(nested(deleted, 255, { parent: id })).status).toBe("applied");
    const r2 = SharedObjectsReplica.fromChanges(
      [a.init.change, a.create.change, made, deleted],
      opts(CAROL),
    ).replica;
    expect(() => r2.receiveChange(nested(deleted, 256, { parent: id }))).toThrow(invalidBytes);
    // Writing into an object the document never had is refused before the engine.
    expect(() =>
      receiver(a).receiveChange(nested(a.create.change, 1, { parent: `999@${ACTOR}` })),
    ).toThrow(invalidBytes);
  });
});

describe("writers (§11.2, §30)", () => {
  it("refuse a value nested deeper than 64 levels before Automerge builds it", () => {
    const a = alice();
    let value: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 10_000; i++) value = { d: value };
    const { task } = createTask({
      id: "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId,
      title: "Deep",
      createdBy: ALICE,
    });
    expect(() =>
      a.replica.apply({
        intent: "task.create",
        task: { ...task, extensions: { "org.example.app": value } },
      } as never),
    ).toThrow(/deeper than 64 levels/);
    // Nothing was written and the engine is alive.
    expect(a.replica.actorSeq).toBe(2);
    a.replica.apply(setTitle(a.replica.task(ID)?.task as Task, "After").intent);
    expect(a.replica.task(ID)?.task?.title).toBe("After");
  });
});

describe("Snapshots (§11.2, §13.1)", () => {
  it("load a document at depth 256 and refuse one at depth 257 before loading", () => {
    const a = alice();
    const doc = (levels: number) =>
      A.save(
        A.applyChanges(A.init(), [
          a.init.change,
          a.create.change,
          nested(a.create.change, levels),
        ])[0],
      );
    expect(() =>
      SharedObjectsReplica.fromSnapshot(frameSnapshot(doc(MAX_DOCUMENT_DEPTH)), opts(CAROL)),
    ).not.toThrow();
    expect(() =>
      SharedObjectsReplica.fromSnapshot(frameSnapshot(doc(MAX_DOCUMENT_DEPTH + 1)), opts(CAROL)),
    ).toThrow(invalidBytes);
  });
});
