// LFCP-037: the Automerge reference corpus scenarios S02-S12 in every
// delivery order. automerge-corpus.test.ts applies each scenario in its
// recorded order and in reverse; this applies every permutation of its
// changes, with a duplicate, to replicas of all three fixture Principals
// (a change waits until its dependencies apply), and checks:
//
// - the logical state and conflict sets are the corpus' (never bytes);
// - validate() is clean;
// - after the merge, further intents succeed and keep unknown data
//   (S11: an unknown field and extension; S12: an unknown object type).
//
// The LFCP-037 prompt's scenarios 1-11 are S02, S03, S05, S06, S07, S08,
// S09, S10, S04, S11 and S12; scenario 12 is in
// packages/shared-objects/test/property/scenarios.test.ts.

import { fromHex, type ObjectId, principalId, resourceId } from "@openlfcp/core";
import {
  createTask,
  type Json,
  type SharedObjectsReplica as Replica,
  type ReplicaIntent,
  SharedObjectsReplica,
} from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import { openSpec } from "../spec.mjs";
import { readCorpus } from "./corpus.js";

const spec = openSpec();
const corpus = readCorpus();
const suite = spec.readJson(
  "test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json",
) as {
  fixtures: { resource_a_hex: string; principals: Record<string, { id_hex: string }> };
};
const resource = resourceId(fromHex(suite.fixtures.resource_a_hex));
const principals = ["andrey", "pavel", "masha"].map((name) =>
  principalId(fromHex(suite.fixtures.principals[name]?.id_hex as string)),
);

const SCENARIOS = ["S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12"];

function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, i) =>
    permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]),
  );
}

/** Deliver `order` to a fresh replica; a change missing dependencies waits. */
function deliver(order: readonly Uint8Array[], principal: number): Replica {
  const replica = SharedObjectsReplica.empty({
    resource,
    principal: principals[principal % principals.length] as ReturnType<typeof principalId>,
  });
  let waiting: Uint8Array[] = [];
  for (const bytes of order) {
    waiting.push(bytes);
    for (let progress = true; progress; ) {
      progress = false;
      waiting = waiting.filter((w) => {
        const done = replica.receiveChange(w).status !== "missing_dependencies";
        progress ||= done;
        return !done;
      });
    }
  }
  expect(waiting).toEqual([]);
  return replica;
}

describe(`Automerge corpus S02-S12 in every delivery order (${spec.lock.tag})`, () => {
  for (const id of SCENARIOS) {
    const scenario = corpus.scenarios.find((s) => s.id === id);
    if (scenario === undefined) throw new Error(`the corpus has no ${id}`);
    const bytes = scenario.changes.map((c) => fromHex(c.change_hex));

    it(`${id}: ${scenario.description}: every order converges to the corpus state`, () => {
      const orders = permutations(bytes.map((_, i) => i));
      orders.forEach((order, n) => {
        // Each order with a duplicate of its first change at the end.
        const delivered = [...order, order[0] as number].map((i) => bytes[i] as Uint8Array);
        const replica = deliver(delivered, n);
        const at = `${id} order ${order.join(",")}`;
        expect(replica.root(), at).toEqual(scenario.state);
        expect(replica.conflicts(), at).toEqual(scenario.conflicts);
        expect(replica.validate().valid, at).toBe(true);
        expect(replica.heads(), at).toEqual([...scenario.heads].sort());
      });
    });

    it(`${id}: after the merge, further intents succeed and keep unknown data`, () => {
      const replica = deliver([...bytes].reverse(), 2);
      const before = replica.root() as { objects: Record<string, Record<string, Json>> };
      const tasks = Object.entries(before.objects).filter(([, o]) => o.type === "task");
      const others = Object.entries(before.objects).filter(([, o]) => o.type !== "task");
      // A Task this replica creates and edits, next to whatever the scenario holds.
      const fresh = "019a2f85-7b31-7c42-8000-00000000c037" as ObjectId;
      const created = createTask({ id: fresh, title: "New", createdBy: principals[2] as never });
      const intents: ReplicaIntent[] = [
        created.intent,
        { intent: "task.set_status", id: fresh, status: "done" },
        ...tasks.flatMap(([key]): ReplicaIntent[] => [
          { intent: "task.set_title", id: key as ObjectId, title: "Edited after merge" },
          { intent: "task.set_status", id: key as ObjectId, status: "in_progress" },
          { intent: "task.add_tag", id: key as ObjectId, tag: "merged" },
        ]),
      ];
      for (const intent of intents)
        expect(replica.apply(intent), JSON.stringify(intent)).not.toBeNull();
      expect(replica.validate().valid).toBe(true);
      const after = replica.root() as { objects: Record<string, Record<string, Json>> };
      // Every field the intents did not write is unchanged, unknown ones included.
      for (const [key, object] of tasks) {
        const { title: _t, status: _s, tags: _g, ...kept } = object;
        expect(after.objects[key]).toMatchObject(kept);
        expect(after.objects[key]?.title).toBe("Edited after merge");
      }
      // Objects of unknown types are untouched.
      for (const [key, object] of others) expect(after.objects[key]).toEqual(object);
      if (id === "S11") {
        const task = Object.values(after.objects)[0] as Record<string, Json>;
        expect(task.x_future_scalar).toBe("future-value");
        expect(task.extensions).toEqual({ "com.example.tracker": { ticket: "ABC-42" } });
      }
      if (id === "S12") expect(others.length).toBe(1);
      expect(after.objects[fresh]?.status).toBe("done");
    });
  }
});
