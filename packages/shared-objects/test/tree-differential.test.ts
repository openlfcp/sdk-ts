// The derived tree decides whether two changes are concurrent with vector
// clocks (soak #11) where it built a set of ancestors per change. Random
// histories of three writers deleting, deleting again, restoring, editing
// and moving nodes, merged in part at random, give the same tree, hidden
// nodes, recovery, retained concurrent edits and conflicts as the
// deriveTree of 0.2.0-beta.9 (test/support/tree-695cd08.ts).

import * as A from "@automerge/automerge";
import { principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask } from "../src/index.js";
import { deriveTree, type SectionIntent, SectionReplica } from "../src/sections/index.js";
import { deriveTree as reference } from "./support/tree-695cd08.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const writers = [1, 2, 3].map((n) => principalId(new Uint8Array(32).fill(n)));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const SEEDS = 300;
const STEPS = 40;

function random(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

/** The document of `changes`, as a peer that received them holds it. */
const docOf = (changes: readonly Uint8Array[]) =>
  A.applyChanges(A.init<unknown>(), [...changes])[0] as A.Doc<unknown>;

describe("the derived tree with vector clocks gives what beta.9 gave", () => {
  it(`${SEEDS} random histories of three writers`, () => {
    let compared = 0;
    let withRetained = 0;
    for (let seed = 1; seed <= SEEDS; seed++) {
      const rnd = random(seed);
      const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
      const first = SectionReplica.empty({ resource, principal: writers[0] as never });
      const tasks: string[] = [];
      const base: SectionIntent[] = [
        { intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: writers[0] },
      ] as SectionIntent[];
      for (let i = 0; i < 6; i++) {
        const t = id(100 + i);
        tasks.push(t);
        base.push({
          intent: "task.create_in_section",
          task: createTask({ id: t as never, title: `t${i}`, createdBy: writers[0] as never }).task,
          parent: i > 0 && rnd() < 0.4 ? (tasks[i - 1] as string) : SECTION,
          after: null,
          placementId: id(5000 + i),
        } as SectionIntent);
      }
      first.commit(base);
      const replicas = writers.map((w, k) => {
        if (k === 0) return first;
        const r = SectionReplica.empty({ resource, principal: w as never });
        r.receiveChanges(first.changes());
        return r;
      });
      let placement = 6000;
      for (let step = 0; step < STEPS; step++) {
        const r = pick(replicas);
        const t = pick(tasks);
        const k = rnd();
        const intent = (
          k < 0.25
            ? { intent: "node.delete", id: t }
            : k < 0.35
              ? { intent: "node.restore", id: t }
              : k < 0.6
                ? { intent: "task.set_title", id: t, title: `t ${Math.floor(rnd() * 100)}` }
                : k < 0.75
                  ? { intent: "task.set_status", id: t, status: pick(["todo", "done"]) }
                  : {
                      intent: "node.move",
                      id: t,
                      parent: rnd() < 0.5 ? SECTION : pick(tasks),
                      after: null,
                      placementId: id(placement++),
                    }
        ) as SectionIntent;
        try {
          r.commit([intent]);
        } catch {
          // refused (a node deleted or in conflict): nothing written
        }
        // Merge in part, at random: concurrent histories.
        if (rnd() < 0.3) {
          const to = pick(replicas);
          if (to !== r) to.receiveChanges(r.changes());
        }
        if (step % 20 === 19) {
          for (const x of replicas) {
            const doc = docOf(x.changes());
            const now = deriveTree(doc);
            expect(JSON.stringify(now), `seed ${seed} step ${step}`).toBe(
              JSON.stringify(reference(doc)),
            );
            // The replica's own (cached) tree is the same.
            expect(JSON.stringify(x.tree())).toBe(JSON.stringify(now));
            compared++;
            if (now.retainedConcurrentEdits.length > 0) withRetained++;
          }
        }
      }
    }
    // The comparisons included histories where a concurrent edit is retained.
    expect(compared).toBe(SEEDS * (STEPS / 20) * 3);
    expect(withRetained).toBeGreaterThan(SEEDS / 2);
  }, 600_000);
});
