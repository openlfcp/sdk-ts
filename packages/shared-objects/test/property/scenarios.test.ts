// LFCP-037 required scenarios not in the Automerge reference corpus.
//
// Scenarios 1-11 of the LFCP-037 prompt are corpus scenarios S02-S12,
// asserted by conformance/shared-objects/automerge-corpus.test.ts and
// corpus-orders.test.ts (every causal order, duplicates, three replicas).
// Scenario 12 (multiple objects) has no corpus scenario and is here.

import { describe, expect, it } from "vitest";
import { checkConverged, World } from "./harness.js";

// Intent kinds of World.op (see harness.ts #intent): k selects the intent,
// v the value from its pool.
const K = { title: 0, status: 1, due: 5, addTag: 9, removeTag: 10, delete: 13 } as const;
const V = { done: 2, cancelled: 3, api: 0, plan: 0, review: 2, oct15: 1 } as const;

describe("LFCP-037 scenario 12: multiple objects", () => {
  it("conflicts in Task A do not corrupt Task B", () => {
    const world = new World(3, 2);
    const [a, b] = world.objects.map((o) => o.id) as [string, string];
    // Task A (object 0): a status conflict, a concurrent tag add/remove and a delete.
    world.op(0, 0, K.addTag, V.api);
    world.converge(1);
    world.op(0, 0, K.status, V.done);
    world.op(1, 0, K.status, V.cancelled);
    world.op(0, 0, K.removeTag, V.api);
    world.op(2, 0, K.addTag, V.api);
    world.op(2, 0, K.delete, 0);
    // Task B (object 1): independent edits on another replica.
    world.op(1, 1, K.title, V.review);
    world.op(2, 1, K.due, V.oct15);
    world.converge(2);

    expect(checkConverged(world)).toEqual([]);
    for (const node of world.nodes) {
      const replica = node.replica;
      expect(replica.conflicts()).toEqual({ [a]: { status: ["cancelled", "done"] } });
      const taskA = replica.task(a);
      expect(taskA?.tags).toEqual(["api"]);
      expect(taskA?.fields.lifecycle.values).toEqual(["deleted"]);
      const taskB = replica.task(b);
      expect(taskB?.status).toBe("ready");
      expect(taskB?.task).toMatchObject({
        title: "Review",
        status: "todo",
        due: "2026-10-15",
        lifecycle: "active",
        tags: {},
      });
      for (const view of Object.values(taskB?.fields ?? {})) expect(view.conflicted).toBe(false);
    }
  });
});
