// The Shared Sections Data Profile handler (LFCP-02-025): the codec bound
// to the signer's section actor, buffering until dependencies arrive,
// refusal by the section admission, exclusion, and checkpoint/restore.

import * as A from "@automerge/automerge";
import { type DataUnitId, dataUnitId, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/index.js";
import { createTask } from "../src/index.js";
import {
  deriveSectionActorId,
  type SectionIntent,
  SectionReplica,
  type SectionsListenerFailure,
  type SectionsNodesChanged,
  SharedSectionsDataProfile,
} from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const bob = principalId(new Uint8Array(32).fill(2));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const [SECTION, T, X] = [id(1), id(2), id(3)];
const unit = (n: number): { unitId: DataUnitId } => ({
  unitId: dataUnitId(new Uint8Array(32).fill(n)),
});

/** Alice's section: create, then a Task, then a title, as three changes. */
function written() {
  const r = SectionReplica.empty({ resource, principal: alice });
  const steps: SectionIntent[][] = [
    [{ intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice }],
    [
      {
        intent: "task.create_in_section",
        task: createTask({ id: T as never, title: "T", createdBy: alice }).task,
        parent: SECTION,
        after: null,
      },
    ],
    [{ intent: "item.create", id: X, parent: SECTION, after: T, text: "x", createdBy: alice }],
  ];
  const changes = steps.map((s) => checkChange(r.commit(s)?.change as Uint8Array));
  return { r, changes };
}

// biome-ignore lint/suspicious/noExplicitAny: a crafted change writes any shape
type Doc = Record<string, any>;
const bobProfile = () =>
  new SharedSectionsDataProfile(SectionReplica.empty({ resource, principal: bob }));

describe("SharedSectionsDataProfile", () => {
  it("decodes only changes of the signer's section actor (§2)", () => {
    const { changes } = written();
    const p = bobProfile();
    const plaintext = p
      .codecFor({ resourceId: resource, actor: alice })
      .encode(changes[0] as never);
    expect(p.codecFor({ resourceId: resource, actor: alice }).decode(plaintext).hash).toBe(
      changes[0]?.hash,
    );
    expect(() => p.codecFor({ resourceId: resource, actor: bob }).decode(plaintext)).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHANGE_ACTOR_MISMATCH" }),
    );
  });

  it("buffers a change until its dependencies merge, then merges both and reports the nodes", () => {
    const { changes } = written();
    const p = bobProfile();
    const events: SectionsNodesChanged[] = [];
    p.onNodesChanged((e) => events.push(e));
    expect(p.apply(unit(2), changes[1] as never).pending).toBeDefined();
    expect(p.pendingUnits().map(toHex)).toEqual([toHex(unit(2).unitId)]);
    const r = p.apply(unit(1), changes[0] as never);
    expect(r.merged.map(toHex)).toEqual([unit(1).unitId, unit(2).unitId].map(toHex));
    // The section's title appears with section.create (§3: the section when its title is written).
    expect(r.objects).toEqual([SECTION, T]);
    expect(events.at(-1)).toMatchObject({ nodeIds: [SECTION, T], origin: "remote" });
  });

  it("rejects a change the section admission refuses, and keeps the rest", () => {
    const { r, changes } = written();
    const actor = toHex(deriveSectionActorId(resource, alice));
    const bad = A.change(A.load<Doc>(r.save(), { actor }), { time: 0 }, (d) => {
      d.section.children.splice(0, 1);
    });
    const badChange = checkChange(A.getLastLocalChange(bad) as Uint8Array);
    const p = bobProfile();
    p.applyBatch(changes.map((c, i) => ({ unit: unit(i + 1), value: c })));
    expect(() => p.apply(unit(9), badChange)).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHILDREN_LIST_MUTATED" }),
    );
    expect(p.has(unit(9).unitId)).toBe(false);
    expect(p.replica.snapshot().order.map((e) => e.id)).toEqual([T, X]);
  });

  it("excludes a unit and puts the units that build on it back to waiting", () => {
    const { changes } = written();
    const p = bobProfile();
    p.applyBatch(changes.map((c, i) => ({ unit: unit(i + 1), value: c })));
    const out = p.exclude([unit(2).unitId]);
    expect(out.pending.map(toHex)).toEqual([toHex(unit(3).unitId)]);
    expect(out.objects).toEqual([T, X].sort());
    expect(p.replica.snapshot().order).toEqual([]);
  });

  it("restores a checkpoint with its merged units, and refuses to write below its sequence (§9)", () => {
    const { r, changes } = written();
    const p = new SharedSectionsDataProfile(SectionReplica.empty({ resource, principal: alice }));
    p.applyBatch(changes.map((c, i) => ({ unit: unit(i + 1), value: c })));
    const restored = SharedSectionsDataProfile.restore(p.checkpoint(), {
      resource,
      principal: alice,
    });
    expect(restored.has(unit(3).unitId)).toBe(true);
    expect(restored.replica.revision()).toBe(r.revision());
    // A device that lost its last change: its checkpoint says sequence 3, its state has 2.
    const behind = SharedSectionsDataProfile.restore(
      {
        ...p.checkpoint(),
        state: SectionReplica.fromChanges(
          changes.slice(0, 2).map((c) => c.bytes),
          { resource, principal: alice },
        ).replica.save(),
        units: [],
      },
      { resource, principal: alice },
    );
    expect(() => behind.replica.commit([{ intent: "section.set_title", title: "No" }])).toThrow(
      expect.objectContaining({ code: "SEQUENCE_REUSE" }),
    );
  });

  it("records this client's own units for the checkpoint", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    const p = new SharedSectionsDataProfile(r);
    const staged = r.stage([
      { intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice },
    ]);
    staged?.apply();
    p.recordLocal(unit(1).unitId, staged?.change as never);
    expect(p.checkpoint().units).toEqual([{ unitId: unit(1).unitId, ref: staged?.change.hash }]);
  });

  describe("nodes changed by a remote change (§5; affectedNodeIds rule of §3)", () => {
    /** Bob's profile holding Alice's section, and a way to deliver Alice's next change to it. */
    function shared() {
      const { r, changes } = written();
      const p = bobProfile();
      for (const [i, c] of changes.entries()) p.apply(unit(i + 1), c as never);
      const events: SectionsNodesChanged[] = [];
      p.onNodesChanged((e) => events.push(e));
      let n = 10;
      const deliver = (intents: SectionIntent[]) => {
        const change = checkChange(r.commit(intents)?.change as Uint8Array);
        p.apply(unit(n++), change as never);
        return events.at(-1);
      };
      return { p, r, events, deliver };
    }

    const taskIntents: [string, SectionIntent][] = [
      ["title", { intent: "task.set_title", id: T as never, title: "T by Alice" }],
      ["status", { intent: "task.set_status", id: T as never, status: "in_progress" }],
      ["completion", { intent: "task.complete", id: T as never, completionDate: "2026-10-09" }],
      ["due date", { intent: "task.set_due", id: T as never, date: "2026-10-20" }],
      ["priority", { intent: "task.set_priority", id: T as never, priority: "high" }],
      ["tag", { intent: "task.add_tag", id: T as never, tag: "launch" }],
    ];
    for (const [field, intent] of taskIntents)
      it(`reports the task node when a Task's ${field} changes`, () => {
        const { deliver } = shared();
        expect(deliver([intent])).toMatchObject({ nodeIds: [T], origin: "remote" });
      });

    it("reports the section when its title changes", () => {
      const { deliver } = shared();
      expect(deliver([{ intent: "section.set_title", title: "S by Alice" }])).toMatchObject({
        nodeIds: [SECTION],
        origin: "remote",
      });
    });

    it("reports the task node when concurrent titles put the field in conflict", () => {
      const { p, deliver } = shared();
      p.replica.commit([{ intent: "task.set_title", id: T as never, title: "T by Bob" }]);
      const e = deliver([{ intent: "task.set_title", id: T as never, title: "T by Alice" }]);
      expect(e).toMatchObject({ nodeIds: [T], origin: "remote" });
      expect(p.replica.task(T)?.fields.title.conflicted).toBe(true);
    });

    it("leaves the local path as it was: a staged batch reports its affectedNodeIds", () => {
      const r = SectionReplica.empty({ resource, principal: alice });
      const p = new SharedSectionsDataProfile(r);
      const events: SectionsNodesChanged[] = [];
      p.onNodesChanged((e) => events.push(e));
      const binding = p.commitBinding(alice);
      const commitLocal = (intents: SectionIntent[]) => {
        const staged = binding.stage(intents);
        staged?.apply();
        staged?.committed(staged.values.map((_, i) => unit(40 + events.length + i).unitId));
        return events.at(-1);
      };
      commitLocal([{ intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice }]);
      commitLocal([
        {
          intent: "task.create_in_section",
          task: createTask({ id: T as never, title: "T", createdBy: alice }).task,
          parent: SECTION,
          after: null,
        },
      ]);
      expect(
        commitLocal([{ intent: "task.set_title", id: T as never, title: "T2" }]),
      ).toMatchObject({ nodeIds: [T], origin: "local" });
    });
  });

  describe("a throwing nodes-changed listener (REVIEW-20261015-03)", () => {
    /** Two listeners around one that throws, with an error handler: what each saw. */
    function watched(p: SharedSectionsDataProfile, error: unknown = new Error("listener bug")) {
      const first: SectionsNodesChanged[] = [];
      const last: SectionsNodesChanged[] = [];
      const failures: SectionsListenerFailure[] = [];
      p.onNodesChanged((e) => first.push(e));
      p.onNodesChanged(() => {
        throw error;
      });
      p.onNodesChanged((e) => last.push(e));
      p.onListenerError((f) => failures.push(f));
      return { first, last, failures };
    }

    it("remote apply: the unit is merged, every other listener gets the event, the error is reported", () => {
      const { changes } = written();
      const p = bobProfile();
      const { first, last, failures } = watched(p);
      const r = p.apply(unit(1), changes[0] as never);
      expect(r.merged.map(toHex)).toEqual([toHex(unit(1).unitId)]);
      expect(p.has(unit(1).unitId)).toBe(true);
      expect(p.replica.snapshot().title).toMatchObject({ value: "S" });
      expect(first.map((e) => e.nodeIds)).toEqual([[SECTION]]);
      expect(last).toEqual(first);
      expect(failures).toHaveLength(1);
      expect(failures[0]?.event).toBe(first[0]);
      expect(failures[0]?.error).toMatchObject({ message: "listener bug" });
      // The next unit merges and is delivered as usual.
      p.applyBatch(changes.slice(1).map((c, i) => ({ unit: unit(i + 2), value: c })));
      expect(p.replica.snapshot().order.map((e) => e.id)).toEqual([T, X]);
      expect(last.map((e) => e.origin)).toEqual(["remote", "remote"]);
      expect(failures).toHaveLength(2);
    });

    it("local committed: the units are recorded and the event delivered", () => {
      const p = new SharedSectionsDataProfile(SectionReplica.empty({ resource, principal: alice }));
      const { last, failures } = watched(p);
      const staged = p
        .commitBinding(alice)
        .stage([{ intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice }]);
      staged?.apply();
      expect(() => staged?.committed([unit(1).unitId])).not.toThrow();
      expect(p.has(unit(1).unitId)).toBe(true);
      expect(p.checkpoint().units.map((u) => toHex(u.unitId))).toEqual([toHex(unit(1).unitId)]);
      expect(last).toMatchObject([{ nodeIds: [SECTION], origin: "local" }]);
      expect(failures.map((f) => f.event.origin)).toEqual(["local"]);
      // recordLocal, the other local path.
      const next = p.replica.stage([{ intent: "section.set_title", title: "S2" }]);
      next?.apply();
      p.recordLocal(unit(2).unitId, next?.change as never);
      expect(p.has(unit(2).unitId)).toBe(true);
      expect(last.at(-1)).toMatchObject({ nodeIds: [SECTION], origin: "local" });
      expect(failures).toHaveLength(2);
    });

    it("rebuild: exclude, reset and a loaded Snapshot finish their work", () => {
      const { r, changes } = written();
      const p = bobProfile();
      p.applyBatch(changes.map((c, i) => ({ unit: unit(i + 1), value: c })));
      const { last, failures } = watched(p);
      const out = p.exclude([unit(2).unitId]);
      expect(out.pending.map(toHex)).toEqual([toHex(unit(3).unitId)]);
      expect(p.replica.snapshot().order).toEqual([]);
      expect(last.at(-1)).toMatchObject({ nodeIds: [T, X].sort(), origin: "rebuild" });
      p.reset();
      expect(p.has(unit(1).unitId)).toBe(false);
      expect(last.at(-1)?.origin).toBe("rebuild");
      const loaded = p.loadSnapshot(r.save());
      expect(loaded.nodeIds).toEqual([SECTION, T, X].sort());
      expect(p.replica.snapshot().order.map((e) => e.id)).toEqual([T, X]);
      expect(last.at(-1)).toMatchObject({ nodeIds: [SECTION, T, X].sort(), origin: "remote" });
      expect(failures.map((f) => f.event.origin)).toEqual(["rebuild", "rebuild", "remote"]);
    });

    it("a throwing error handler is not reported again, and a re-entrant failure does not recurse", () => {
      const { changes } = written();
      const p = bobProfile();
      const seen: SectionsNodesChanged[] = [];
      let handled = 0;
      p.onNodesChanged(() => {
        throw new Error("listener bug");
      });
      p.onNodesChanged((e) => seen.push(e));
      p.onListenerError(() => {
        handled++;
        // A handler that changes the model again, and throws.
        if (handled === 1) p.apply(unit(2), changes[1] as never);
        throw new Error("handler bug");
      });
      expect(() => p.apply(unit(1), changes[0] as never)).not.toThrow();
      expect(p.has(unit(2).unitId)).toBe(true);
      expect(seen.map((e) => e.nodeIds)).toEqual([[SECTION], [T]]);
      expect(handled).toBe(1);
    });

    it("without a handler, the error goes to reportError where the runtime has one", () => {
      const { changes } = written();
      const p = bobProfile();
      const reported: unknown[] = [];
      const g = globalThis as { reportError?: (e: unknown) => void };
      const had = g.reportError;
      g.reportError = (e) => reported.push(e);
      try {
        p.onNodesChanged(() => {
          throw new Error("listener bug");
        });
        p.apply(unit(1), changes[0] as never);
      } finally {
        if (had === undefined) delete g.reportError;
        else g.reportError = had;
      }
      expect(p.has(unit(1).unitId)).toBe(true);
      expect(reported.map((e) => (e as Error).message)).toEqual(["listener bug"]);
    });

    it("an engine trap is thrown on once every listener has had the event (unchanged policy)", () => {
      const { changes } = written();
      const p = bobProfile();
      const trap = Object.assign(new Error("wasm trap: unreachable"), { name: "RuntimeError" });
      const { last, failures } = watched(p, trap);
      expect(() => p.apply(unit(1), changes[0] as never)).toThrow(trap);
      expect(p.has(unit(1).unitId)).toBe(true);
      expect(last.map((e) => e.nodeIds)).toEqual([[SECTION]]);
      expect(failures).toEqual([]);
    });
  });
});
