// The section writer (LFCP-02-012): section and creation intents, Task
// field intents on section Tasks, batches as one change, and the refusals
// before commit. The corpus comparison (SS01, SS11) runs in
// conformance/shared-sections/authoring.test.ts.

import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange, checkChangeActor } from "../src/admission/index.js";
import { createTask, SCALAR_FIELDS } from "../src/index.js";
import {
  AUTHORING_BUDGET,
  deriveSectionActorId,
  type SectionIntent,
  SectionIntentError,
  SectionReplica,
} from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const bob = principalId(new Uint8Array(32).fill(2));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const T = id(2);
const P = id(3);
const X = id(4);
const Y = id(5);

const create: SectionIntent = {
  intent: "section.create",
  sectionId: SECTION,
  title: "Joint launch",
  createdBy: alice,
};
const task = (n: string, title = "Prepare contract") =>
  createTask({ id: n as never, title, createdBy: alice }).task;
const content: SectionIntent[] = [
  { intent: "task.create_in_section", task: task(T), parent: SECTION, after: null },
  {
    intent: "paragraph.create",
    id: P,
    parent: T,
    after: null,
    text: "Draft contract",
    createdBy: alice,
  },
  { intent: "item.create", id: X, parent: SECTION, after: T, text: "Group X", createdBy: alice },
  { intent: "item.create", id: Y, parent: SECTION, after: X, text: "Group Y", createdBy: alice },
];

type View = {
  section: { title: string; ready?: boolean; children: string[] };
  nodes: Record<string, { kind: string; text?: string; children: string[]; placement: string }>;
  placements: Record<string, { node_id: string; parent_id: string }>;
  objects: Record<string, { title: string; status: string; extensions: Record<string, unknown> }>;
};
const view = (r: SectionReplica) => r.toJSON() as unknown as View;
/** The node IDs a children list emits, in order. */
const order = (r: SectionReplica, lane: string[]) =>
  lane.map((p) => view(r).placements[p]?.node_id);

function refusal(fn: () => unknown): SectionIntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof SectionIntentError) return e;
    throw e;
  }
  throw new Error("not refused");
}

function built(): SectionReplica {
  const r = SectionReplica.empty({ resource, principal: alice });
  r.commit([create, ...content]);
  return r;
}

describe("SectionReplica: creation (§4, §6, §11)", () => {
  it("creates a ready section in one change of the §2 actor", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    const c = r.commit([create]);
    expect(c?.seq).toBe(1);
    expect(c?.affectedNodeIds).toEqual([SECTION]);
    const checked = checkChange(c?.change as Uint8Array);
    expect(checkChangeActor(checked, toHex(deriveSectionActorId(resource, alice))).hash).toBe(
      c?.hash,
    );
    expect(c?.modelRevision).toBe(r.revision());
    const v = r.validate();
    expect([v.state, v.sectionId, v.problems]).toEqual(["ready", SECTION, []]);
  });

  it("commits a batch of intents as one change, nested and in order (SS01's shape)", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    const c = r.commit([create, ...content]);
    expect(r.changes()).toHaveLength(1);
    expect(c?.intents).toEqual([
      "section.create",
      "task.create_in_section",
      "paragraph.create",
      "item.create",
      "item.create",
    ]);
    expect(c?.affectedNodeIds).toEqual([SECTION, T, P, X, Y].sort());
    const v = r.validate();
    expect([v.state, v.nodes.size, v.placements.size, v.objects.size]).toEqual(["ready", 0, 0, 0]);
    const s = view(r);
    expect(order(r, s.section.children)).toEqual([T, X, Y]);
    expect(order(r, s.nodes[T]?.children ?? [])).toEqual([P]);
    expect(s.nodes[P]?.text).toBe("Draft contract");
    expect(s.objects[T]?.title).toBe("Prepare contract");
  });

  it("keeps Task strings scalar and node bodies Text (§2, §4.2)", () => {
    const r = built();
    const doc = SectionReplica.fromSave(r.save(), { resource, principal: bob }, "local-state");
    expect(doc.validate().nodes.size).toBe(0);
    // validateSection reports Text in a Task field or a scalar body as INVALID_FIELD_TYPE.
    expect(doc.validate().objects.size).toBe(0);
  });

  it("inserts right after the given visible sibling, or first (§6)", () => {
    const r = built();
    const Z = id(6);
    const W = id(7);
    r.commit([
      { intent: "item.create", id: Z, parent: SECTION, after: T, text: "Z", createdBy: alice },
      { intent: "item.create", id: W, parent: SECTION, after: null, text: "W", createdBy: alice },
    ]);
    expect(order(r, view(r).section.children)).toEqual([W, T, Z, X, Y]);
  });

  it("edits a section Task's fields through the SOP intents (SS03, SS11)", () => {
    const r = built();
    const before = view(r).nodes[P]?.text;
    const c = r.commit([
      { intent: "task.set_status", id: T as never, status: "done" },
      { intent: "task.set_title", id: T as never, title: "Sign contract" },
    ]);
    expect(c?.affectedNodeIds).toEqual([T]);
    expect(view(r).objects[T]).toMatchObject({ status: "done", title: "Sign contract" });
    expect(view(r).nodes[P]?.text).toBe(before);
  });

  it("views a section Task as SharedObjectsReplica.task does (SOP §99)", () => {
    const base = built();
    const a = SectionReplica.fromSave(base.save(), { resource, principal: alice }, "local-state");
    const b = SectionReplica.fromSave(base.save(), { resource, principal: bob }, "local-state");
    a.commit([{ intent: "task.set_status", id: T as never, status: "done" }]);
    b.commit([
      { intent: "task.set_status", id: T as never, status: "cancelled" },
      { intent: "task.add_tag", id: T as never, tag: "legal" },
    ]);
    const { replica: merged } = SectionReplica.fromChanges([...a.changes(), ...b.changes()], {
      resource,
      principal: alice,
    });
    const v = merged.task(T);
    expect(v).toMatchObject({ id: T, status: "ready", problems: [], tags: ["legal"] });
    expect(v?.task?.title).toBe("Prepare contract");
    expect(v?.fields.status).toMatchObject({ values: ["cancelled", "done"], conflicted: true });
    expect(v?.fields.title).toEqual({
      value: "Prepare contract",
      values: ["Prepare contract"],
      conflicted: false,
    });
    expect(v?.fields.due).toEqual({ value: undefined, values: [], conflicted: false });
    expect(Object.keys(v?.fields ?? {})).toEqual([...SCALAR_FIELDS]);
    expect(merged.task(P)).toBeUndefined(); // a paragraph has no Task
    expect(merged.task(id(999))).toBeUndefined();
  });

  it("creates and then edits a Task in one batch", () => {
    const r = built();
    const U = id(8);
    r.commit([
      { intent: "task.create_in_section", task: task(U, "New"), parent: X, after: null },
      { intent: "task.set_title", id: U as never, title: "Renamed" },
    ]);
    expect(view(r).objects[U]?.title).toBe("Renamed");
    expect(r.changes()).toHaveLength(2);
  });

  it("sets the title, and writes ready once at the end of an import (§12.1)", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    r.commit([{ ...create, ready: false }]);
    expect(r.validate().state).toBe("importing");
    r.commit([...content, { intent: "section.set_title", title: "Renamed" }]);
    expect(r.validate().state).toBe("importing");
    r.commit([{ intent: "section.mark_ready" }]);
    expect(r.validate().state).toBe("ready");
    expect(view(r).section.title).toBe("Renamed");
    expect(refusal(() => r.commit([{ intent: "section.mark_ready" }])).code).toBe("SECTION_EXISTS");
  });

  it("commits 128 Tasks, 128 paragraphs and 8,192 characters in one change (§16.3)", () => {
    const r = built();
    const intents: SectionIntent[] = [];
    for (let k = 0; k < 128; k++) {
      const t = id(2000 + 2 * k);
      intents.push({
        intent: "task.create_in_section",
        task: task(t, `Task ${k}`),
        parent: SECTION,
        after: null,
      });
      intents.push({
        intent: "paragraph.create",
        id: id(2001 + 2 * k),
        parent: t,
        after: null,
        text: "x".repeat(64),
        createdBy: alice,
      });
    }
    const c = r.commit(intents);
    expect(c?.affectedNodeIds).toHaveLength(256);
    const v = r.validate();
    expect([v.state, v.nodes.size, v.objects.size]).toEqual(["ready", 0, 0]);
  });
});

describe("SectionReplica: refusals before commit (SDK-SECTIONS-INTEGRATION-01 §3.6)", () => {
  const cases: [string, (r: SectionReplica) => SectionIntent[], string][] = [
    [
      "a node ID already used by a node",
      () => [
        { intent: "item.create", id: X, parent: SECTION, after: null, text: "", createdBy: alice },
      ],
      "ID_IN_USE",
    ],
    [
      "a node ID equal to the section ID",
      () => [
        {
          intent: "item.create",
          id: SECTION,
          parent: SECTION,
          after: null,
          text: "",
          createdBy: alice,
        },
      ],
      "ID_IN_USE",
    ],
    [
      "a node ID equal to a PlacementId",
      (r) => [
        {
          intent: "item.create",
          id: view(r).nodes[X]?.placement as string,
          parent: SECTION,
          after: null,
          text: "",
          createdBy: alice,
        },
      ],
      "ID_IN_USE",
    ],
    [
      "a non-canonical node ID",
      () => [
        {
          intent: "item.create",
          id: id(9).toUpperCase(),
          parent: SECTION,
          after: null,
          text: "",
          createdBy: alice,
        },
      ],
      "INVALID_INTENT",
    ],
    [
      "a paragraph parent",
      () => [
        { intent: "item.create", id: id(9), parent: P, after: null, text: "", createdBy: alice },
      ],
      "INVALID_PARENT",
    ],
    [
      "a missing parent",
      () => [
        {
          intent: "item.create",
          id: id(9),
          parent: id(99),
          after: null,
          text: "",
          createdBy: alice,
        },
      ],
      "INVALID_PARENT",
    ],
    [
      "a predecessor under another parent",
      () => [
        { intent: "item.create", id: id(9), parent: SECTION, after: P, text: "", createdBy: alice },
      ],
      "INVALID_PREDECESSOR",
    ],
    [
      "list_style on a paragraph",
      () => [
        {
          intent: "paragraph.create",
          id: id(9),
          parent: SECTION,
          after: null,
          text: "",
          createdBy: alice,
          listStyle: "ordered",
        },
      ],
      "INVALID_INTENT",
    ],
    [
      "text with a lone surrogate",
      () => [
        {
          intent: "item.create",
          id: id(9),
          parent: SECTION,
          after: null,
          text: "a\uD800",
          createdBy: alice,
        },
      ],
      "INVALID_INTENT",
    ],
    ["a second section.create", () => [create], "SECTION_EXISTS"],
  ];
  for (const [what, intents, code] of cases)
    it(`refuses ${what}: ${code}`, () => {
      const r = built();
      const before = r.revision();
      expect(refusal(() => r.commit(intents(r))).code).toBe(code);
      expect(r.revision()).toBe(before);
    });

  it("refuses the whole batch when one intent is refused, with its index", () => {
    const r = built();
    const before = r.revision();
    const e = refusal(() =>
      r.commit([
        {
          intent: "item.create",
          id: id(9),
          parent: SECTION,
          after: null,
          text: "ok",
          createdBy: alice,
        },
        { intent: "item.create", id: id(10), parent: P, after: null, text: "no", createdBy: alice },
      ]),
    );
    expect([e.code, e.intentIndex, e.nodeId]).toEqual(["INVALID_PARENT", 1, P]);
    expect(r.revision()).toBe(before);
    expect(r.changes()).toHaveLength(1);
  });

  it("refuses children under a deleted Task (§6)", () => {
    const r = built();
    r.commit([{ intent: "task.delete", id: T as never }]);
    expect(
      refusal(() =>
        r.commit([
          { intent: "item.create", id: id(9), parent: T, after: null, text: "", createdBy: alice },
        ]),
      ).code,
    ).toBe("INVALID_PARENT");
  });

  it("refuses a write before section.create, and another writer during an import", () => {
    const empty = SectionReplica.empty({ resource, principal: alice });
    expect(refusal(() => empty.commit(content)).code).toBe("SECTION_INVALID");
    const r = SectionReplica.empty({ resource, principal: alice });
    r.commit([{ ...create, ready: false }]);
    const b = SectionReplica.fromSave(r.save(), { resource, principal: bob }, "local-state");
    expect(refusal(() => b.commit(content)).code).toBe("SECTION_IMPORTING");
    expect(refusal(() => b.commit([{ intent: "section.mark_ready" }])).code).toBe(
      "SECTION_IMPORTING",
    );
  });

  it("splits a batch over the §16.2 node budget into several changes, one batch (§12)", () => {
    const r = built();
    const many: SectionIntent[] = Array.from(
      { length: AUTHORING_BUDGET.createdNodes + 1 },
      (_, i) => ({
        intent: "item.create",
        id: id(1000 + i),
        parent: SECTION,
        after: null,
        text: "",
        createdBy: alice,
      }),
    );
    const c = r.commit(many);
    expect(c?.parts).toHaveLength(2);
    expect(c?.hash).toBe(c?.parts.at(-1)?.hash);
    expect(c?.affectedNodeIds).toHaveLength(AUTHORING_BUDGET.createdNodes + 1);
    const other = SectionReplica.empty({ resource, principal: bob });
    expect(other.receiveChanges(r.changes()).refused).toEqual([]);
    expect(other.revision()).toBe(r.revision());
  });

  it("writes a long text in runs within the Text budget (§12.3)", () => {
    const r = built();
    const long = "ж".repeat(20_000);
    const c = r.commit([
      {
        intent: "paragraph.create",
        id: id(1500),
        parent: SECTION,
        after: null,
        text: long,
        createdBy: alice,
      },
    ]);
    expect(c?.parts).toHaveLength(3);
    expect(view(r).nodes[id(1500)]?.text).toBe(long);
    const e = r.commit([
      {
        intent: "text.edit",
        id: P,
        base: r.revision(),
        edits: [{ index: 5, deleteCount: 1, insert: "😀".repeat(9000) }],
      },
    ]);
    expect(e?.parts).toHaveLength(2);
    expect(view(r).nodes[P]?.text).toBe(`Draft${"😀".repeat(9000)}contract`);
    expect(
      SectionReplica.empty({ resource, principal: bob }).receiveChanges(r.changes()).refused,
    ).toEqual([]);
  });

  it("writes ready only in the last change of an import (§12.1)", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    const tasks: SectionIntent[] = Array.from({ length: 300 }, (_, k) => ({
      intent: "task.create_in_section",
      task: task(id(3000 + k), `Task ${k}`),
      parent: SECTION,
      after: null,
    }));
    const c = r.commit([create, ...tasks]);
    expect(c?.parts.length).toBe(2);
    const first = SectionReplica.empty({ resource, principal: bob });
    first.receiveChanges([c?.parts[0]?.change as Uint8Array]);
    expect(first.validate().state).toBe("importing");
    first.receiveChanges([c?.parts[1]?.change as Uint8Array]);
    expect(first.validate().state).toBe("ready");
    expect(first.tree().tree).toHaveLength(300);
  });
});

describe("SectionReplica: moves (§5, §6)", () => {
  /** Every PlacementId of every children list, in order: lists are insert-only. */
  const lanes = (r: SectionReplica) => {
    const s = view(r);
    return [s.section.children, ...Object.values(s.nodes).map((n) => n.children)].flat();
  };
  const isSubsequence = (before: string[], after: string[]) => {
    let i = 0;
    for (const x of after) if (x === before[i]) i++;
    return i === before.length;
  };

  it("moves a subtree with a fresh slot; the node, its Task and its children keep their identity", () => {
    const r = built();
    const before = view(r);
    const oldSlot = before.nodes[T]?.placement as string;
    const oldLanes = lanes(r);
    const c = r.commit([{ intent: "node.move", id: T, parent: X, after: null }]);
    expect(c?.affectedNodeIds).toEqual([T]);
    const after = view(r);
    expect(after.nodes[T]?.placement).not.toBe(oldSlot);
    expect(after.placements[after.nodes[T]?.placement as string]).toMatchObject({
      node_id: T,
      parent_id: X,
    });
    // The old slot stays in the section's list and in placements, unchanged.
    expect(after.section.children).toContain(oldSlot);
    expect(after.placements[oldSlot]).toEqual(before.placements[oldSlot]);
    expect(isSubsequence(oldLanes, lanes(r))).toBe(true);
    expect(after.nodes[T]?.children).toEqual(before.nodes[T]?.children);
    expect(after.objects[T]).toEqual(before.objects[T]);
    expect(r.validate().nodes.size).toBe(0);
  });

  it("reorders among siblings and keeps every historical slot (SS09's shape)", () => {
    const r = built();
    r.commit([{ intent: "node.move", id: T, parent: X, after: null }]);
    r.commit([{ intent: "node.move", id: T, parent: Y, after: null }]);
    r.commit([{ intent: "node.move", id: T, parent: SECTION, after: Y }]);
    const s = view(r);
    expect(Object.keys(s.placements)).toHaveLength(7);
    // The section's list holds T's first slot and its last one; only the
    // selected one names T as current.
    const selected = s.nodes[T]?.placement as string;
    expect(s.section.children.at(-1)).toBe(selected);
    expect(order(r, s.section.children)).toEqual([T, X, Y, T]);
  });

  it("refuses a move under itself, under a descendant, or after itself", () => {
    const r = built();
    const before = r.revision();
    expect(
      refusal(() => r.commit([{ intent: "node.move", id: T, parent: T, after: null }])).code,
    ).toBe("INVALID_PARENT");
    const U = id(20);
    r.commit([{ intent: "item.create", id: U, parent: T, after: P, text: "u", createdBy: alice }]);
    expect(
      refusal(() => r.commit([{ intent: "node.move", id: T, parent: U, after: null }])).code,
    ).toBe("INVALID_PARENT");
    expect(
      refusal(() => r.commit([{ intent: "node.move", id: X, parent: SECTION, after: X }])).code,
    ).toBe("INVALID_PREDECESSOR");
    expect(r.revision()).not.toBe(before);
    expect(
      refusal(() => r.commit([{ intent: "node.move", id: id(99), parent: SECTION, after: null }]))
        .code,
    ).toBe("UNKNOWN_NODE");
  });

  it("moves a node created earlier in the same batch", () => {
    const r = built();
    const U = id(21);
    r.commit([
      { intent: "item.create", id: U, parent: SECTION, after: null, text: "u", createdBy: alice },
      { intent: "node.move", id: U, parent: X, after: null },
    ]);
    const s = view(r);
    expect(s.placements[s.nodes[U]?.placement as string]?.parent_id).toBe(X);
    expect(r.changes()).toHaveLength(2);
  });

  it("sets the list style of task and item nodes only (§4.2)", () => {
    const r = built();
    r.commit([
      { intent: "node.set_list_style", id: X, listStyle: "ordered" },
      { intent: "node.set_list_style", id: T, listStyle: "ordered" },
    ]);
    expect(
      (r.toJSON() as { nodes: Record<string, { list_style: string }> }).nodes[X]?.list_style,
    ).toBe("ordered");
    expect(
      refusal(() => r.commit([{ intent: "node.set_list_style", id: P, listStyle: "ordered" }]))
        .code,
    ).toBe("INVALID_INTENT");
  });

  it("converges on one sibling order for concurrent inserts, in any merge order (§6)", () => {
    const base = built();
    const a = SectionReplica.fromSave(base.save(), { resource, principal: alice }, "local-state");
    const b = SectionReplica.fromSave(base.save(), { resource, principal: bob }, "local-state");
    a.commit([
      {
        intent: "paragraph.create",
        id: id(30),
        parent: SECTION,
        after: T,
        text: "A",
        createdBy: alice,
      },
    ]);
    b.commit([
      {
        intent: "paragraph.create",
        id: id(31),
        parent: SECTION,
        after: T,
        text: "B",
        createdBy: bob,
      },
    ]);
    const ab = SectionReplica.fromChanges([...a.changes(), ...b.changes()], {
      resource,
      principal: alice,
    });
    const ba = SectionReplica.fromChanges([...b.changes().reverse(), ...a.changes()], {
      resource,
      principal: bob,
    });
    expect(ab.unapplied).toEqual([]);
    const orderOf = (r: SectionReplica) => order(r, view(r).section.children);
    expect(orderOf(ab.replica)).toEqual(orderOf(ba.replica));
    expect(orderOf(ab.replica)).toEqual(expect.arrayContaining([T, id(30), id(31), X, Y]));
    expect(ab.replica.validate().nodes.size).toBe(0);
  });
});

describe("SectionReplica: tree and resolution (§7, §8)", () => {
  /** Two writers move T to different parents concurrently (SS04's shape). */
  function conflicted(): SectionReplica {
    const base = built();
    const a = SectionReplica.fromSave(base.save(), { resource, principal: alice }, "local-state");
    const b = SectionReplica.fromSave(base.save(), { resource, principal: bob }, "local-state");
    a.commit([{ intent: "node.move", id: T, parent: X, after: null }]);
    b.commit([{ intent: "node.move", id: T, parent: Y, after: null }]);
    return SectionReplica.fromChanges([...a.changes(), ...b.changes()], {
      resource,
      principal: alice,
    }).replica;
  }

  it("reports a placement conflict with its candidates and blocks the subtree", () => {
    const r = conflicted();
    const t = r.tree();
    expect(t.classification).toBe("STRUCTURAL_ATTENTION");
    expect(t.recovery).toEqual(
      [
        { id: T, code: "PLACEMENT_CONFLICT" },
        { id: P, code: "BLOCKED_PARENT" },
      ].sort((x, y) => (x.id < y.id ? -1 : 1)),
    );
    expect(
      t.candidates
        .get(T)
        ?.map((c) => c.parent)
        .sort(),
    ).toEqual([X, Y].sort());
    expect(t.tree.map((e) => e.id)).toEqual([X, Y]);
    expect(
      refusal(() => r.commit([{ intent: "node.move", id: T, parent: SECTION, after: null }])).code,
    ).toBe("NODE_IN_CONFLICT");
    r.commit([{ intent: "node.resolve_placement", id: T, parent: SECTION, after: null }]);
    expect(r.tree().classification).toBe("VALID");
    expect(r.tree().tree.map((e) => e.id)).toEqual([T, P, X, Y]);
  });

  // 1,000 levels: far beyond any real section, deep enough to break a recursive walk.
  it("derives a deep chain without recursion", () => {
    const r = built();
    let parent = X;
    for (let batch = 0; batch < 4; batch++) {
      const intents: SectionIntent[] = [];
      for (let k = 0; k < 250; k++) {
        const n = id(10_000 + batch * 250 + k);
        intents.push({
          intent: "item.create",
          id: n,
          parent,
          after: null,
          text: "",
          createdBy: alice,
        });
        parent = n;
      }
      r.commit(intents);
    }
    const t = r.tree();
    expect(t.classification).toBe("VALID");
    expect(t.tree).toHaveLength(4 + 1000);
    expect(Math.max(...t.tree.map((e) => e.depth))).toBe(1000);
  }, 30_000);

  it("blocks every member of a long cycle and their descendants, and nothing else", () => {
    // A cycle no writer makes: built directly, as concurrent moves could.
    const r = built();
    const ring = Array.from({ length: 50 }, (_, k) => id(20_000 + k));
    const intents: SectionIntent[] = [];
    let after: string | null = Y;
    for (const n of ring) {
      intents.push({
        intent: "item.create",
        id: n,
        parent: SECTION,
        after,
        text: "",
        createdBy: alice,
      });
      after = n;
    }
    r.commit(intents);
    // Concurrent moves, each valid alone, close the ring: writer k puts ring[k] under ring[k+1].
    const save = r.save();
    const branches = ring.map((n, k) => {
      const w = SectionReplica.fromSave(
        save,
        { resource, principal: principalId(new Uint8Array(32).fill(100 + k)) },
        "local-state",
      );
      w.commit([
        { intent: "node.move", id: n, parent: ring[(k + 1) % ring.length] as string, after: null },
      ]);
      return w.changes().at(-1) as Uint8Array;
    });
    const merged = SectionReplica.fromChanges([...r.changes(), ...branches], {
      resource,
      principal: alice,
    }).replica;
    const t = merged.tree();
    expect(t.classification).toBe("STRUCTURAL_ATTENTION");
    expect(t.recovery.map((x) => x.code)).toEqual(ring.map(() => "PARENT_CYCLE"));
    expect(t.tree.map((e) => e.id)).toEqual([T, P, X, Y]);
    // Resolution: move one member back to the section; the ring unwinds into a chain.
    merged.commit([
      {
        intent: "structure.resolve",
        moves: [{ id: ring[0] as string, parent: SECTION, after: Y }],
      },
    ]);
    expect(merged.tree().classification).toBe("VALID");
    expect(merged.tree().tree).toHaveLength(4 + 50);
  });
});

describe("SectionReplica: lifecycle (§9)", () => {
  type Life = {
    nodes: Record<string, { lifecycle: string }>;
    objects: Record<string, { lifecycle: string }>;
  };
  const life = (r: SectionReplica) => r.toJSON() as unknown as Life;

  it("deletes a Task through its Task and hides its subtree without rewriting it", () => {
    const r = built();
    r.commit([{ intent: "node.delete", id: T }]);
    expect(life(r).objects[T]?.lifecycle).toBe("deleted");
    expect(life(r).nodes[T]?.lifecycle).toBe("active");
    expect(life(r).nodes[P]?.lifecycle).toBe("active");
    const t = r.tree();
    expect(t.hidden).toEqual([T, P].sort());
    expect(t.tree.map((e) => e.id)).toEqual([X, Y]);
    expect(t.classification).toBe("VALID");
  });

  it("deletes a paragraph or item through its own lifecycle", () => {
    const r = built();
    r.commit([{ intent: "node.delete", id: X }]);
    expect(life(r).nodes[X]?.lifecycle).toBe("deleted");
    expect(r.tree().hidden).toEqual([X]);
  });

  it("keeps a child hidden while an ancestor is deleted, and shows it on the ancestor's restore", () => {
    const r = built();
    r.commit([{ intent: "node.delete", id: T }]);
    r.commit([{ intent: "node.restore", id: P }]);
    expect(r.tree().hidden).toEqual([T, P].sort());
    r.commit([{ intent: "node.restore", id: T }]);
    expect(r.tree().hidden).toEqual([]);
    expect(r.tree().tree.map((e) => e.id)).toEqual([T, P, X, Y]);
  });

  it("writes an explicit restore even when the node is already active", () => {
    const r = built();
    const before = r.revision();
    const c = r.commit([{ intent: "node.restore", id: X }]);
    expect(c).not.toBeNull();
    expect(r.revision()).not.toBe(before);
    expect(life(r).nodes[X]?.lifecycle).toBe("active");
  });

  it("reading the tree writes nothing", () => {
    const r = built();
    r.commit([{ intent: "node.delete", id: T }]);
    const before = r.revision();
    r.tree();
    r.validate();
    expect(r.revision()).toBe(before);
  });

  it("refuses an unknown node", () => {
    expect(refusal(() => built().commit([{ intent: "node.delete", id: id(99) }])).code).toBe(
      "UNKNOWN_NODE",
    );
  });
});

describe("SectionReplica: Text, split and join (§10)", () => {
  const text = (r: SectionReplica, n: string) => view(r).nodes[n]?.text;
  const edit = (
    r: SectionReplica,
    n: string,
    index: number,
    deleteCount: number,
    insert: string,
  ): SectionIntent => ({
    intent: "text.edit",
    id: n,
    base: r.revision(),
    edits: [{ index, deleteCount, insert }],
  });

  it("edits Text in Unicode scalar positions, emoji and Cyrillic included", () => {
    const r = built();
    r.commit([edit(r, P, 0, 14, "А😀Б")]);
    r.commit([edit(r, P, 2, 0, "!")]);
    expect(text(r, P)).toBe("А😀!Б");
    r.commit([
      {
        intent: "text.edit",
        id: P,
        base: r.revision(),
        edits: [
          { index: 0, deleteCount: 1, insert: "Я" },
          { index: 3, deleteCount: 0, insert: "?" },
        ],
      },
    ]);
    expect(text(r, P)).toBe("Я😀!?Б");
  });

  it("rebases an edit from an older base onto concurrent changes", () => {
    const r = built();
    const base = r.revision();
    r.commit([edit(r, P, 0, 0, "New ")]);
    // Written against the base, after "Draft": lands after "Draft" in the current Text.
    r.commit([
      { intent: "text.edit", id: P, base, edits: [{ index: 5, deleteCount: 0, insert: "ed" }] },
    ]);
    expect(text(r, P)).toBe("New Drafted contract");
  });

  it("refuses STALE_BASE when the deleted range changed, or the base is unknown", () => {
    const r = built();
    const base = r.revision();
    r.commit([edit(r, P, 6, 0, "big ")]);
    const before = r.revision();
    const stale = refusal(() =>
      r.commit([
        { intent: "text.edit", id: P, base, edits: [{ index: 0, deleteCount: 14, insert: "x" }] },
      ]),
    );
    expect([stale.code, stale.nodeId]).toEqual(["STALE_BASE", P]);
    expect(
      refusal(() =>
        r.commit([
          {
            intent: "text.edit",
            id: P,
            base: "00".repeat(32),
            edits: [{ index: 0, deleteCount: 0, insert: "x" }],
          },
        ]),
      ).code,
    ).toBe("STALE_BASE");
    expect(r.revision()).toBe(before);
  });

  it("refuses Text edits on a task node and edits out of order", () => {
    const r = built();
    expect(refusal(() => r.commit([edit(r, T, 0, 0, "x")])).code).toBe("INVALID_INTENT");
    expect(
      refusal(() =>
        r.commit([
          {
            intent: "text.edit",
            id: P,
            base: r.revision(),
            edits: [
              { index: 5, deleteCount: 0, insert: "a" },
              { index: 1, deleteCount: 0, insert: "b" },
            ],
          },
        ]),
      ).code,
    ).toBe("INVALID_INTENT");
  });

  it("splits an item: the prefix and its children stay, the suffix gets a new item after it", () => {
    const r = built();
    const C = id(40);
    const N = id(41);
    r.commit([
      {
        intent: "paragraph.create",
        id: C,
        parent: X,
        after: null,
        text: "child",
        createdBy: alice,
      },
    ]);
    r.commit([{ intent: "node.set_list_style", id: X, listStyle: "ordered" }]);
    r.commit([
      { intent: "item.split", id: X, base: r.revision(), at: 5, newId: N, createdBy: alice },
    ]);
    expect(text(r, X)).toBe("Group");
    expect(text(r, N)).toBe(" X");
    const t = r.tree().tree.map((e) => e.id);
    expect(t).toEqual([T, P, X, C, N, Y]);
    expect(
      (r.toJSON() as { nodes: Record<string, { list_style?: string }> }).nodes[N]?.list_style,
    ).toBe("ordered");
    expect(
      refusal(() =>
        r.commit([
          {
            intent: "paragraph.split",
            id: X,
            base: r.revision(),
            at: 1,
            newId: id(42),
            createdBy: alice,
          },
        ]),
      ).code,
    ).toBe("INVALID_INTENT");
  });

  it("joins adjacent childless nodes of one kind, and refuses the rest", () => {
    const r = built();
    r.commit([{ intent: "node.join", id: X, second: Y, separator: " / " }]);
    expect(text(r, X)).toBe("Group X / Group Y");
    expect(r.tree().hidden).toEqual([Y]);
    const s = built();
    expect(refusal(() => s.commit([{ intent: "node.join", id: Y, second: X }])).code).toBe(
      "INVALID_INTENT",
    );
    expect(refusal(() => s.commit([{ intent: "node.join", id: P, second: X }])).code).toBe(
      "INVALID_INTENT",
    );
    s.commit([
      {
        intent: "paragraph.create",
        id: id(43),
        parent: X,
        after: null,
        text: "c",
        createdBy: alice,
      },
    ]);
    expect(refusal(() => s.commit([{ intent: "node.join", id: X, second: Y }])).code).toBe(
      "INVALID_INTENT",
    );
  });

  it("never turns a Task's scalar fields into Text", () => {
    const r = built();
    r.commit([edit(r, P, 0, 0, "x"), { intent: "task.set_title", id: T as never, title: "Title" }]);
    expect(r.validate().objects.size).toBe(0);
    expect(r.validate().nodes.size).toBe(0);
  });
});

describe("SectionReplica: snapshot", () => {
  it("reads the title, nodes, order and problems on one revision", () => {
    const r = built();
    r.commit([{ intent: "node.delete", id: T }]);
    const s = r.snapshot();
    expect(s.revision).toBe(r.revision());
    expect(s.classification).toBe("VALID");
    expect(s.title).toEqual({ value: "Joint launch", conflicts: [] });
    expect(s.nodes[T]).toEqual({
      kind: "task",
      parent: SECTION,
      listStyle: "bullet",
      taskId: T,
      deleted: true,
      hidden: true,
    });
    expect(s.nodes[P]).toEqual({
      kind: "paragraph",
      parent: T,
      text: "Draft contract",
      deleted: false,
      hidden: true,
    });
    expect(s.nodes[X]).toMatchObject({
      kind: "item",
      text: "Group X",
      deleted: false,
      hidden: false,
    });
    expect(s.order.map((e) => e.id)).toEqual([X, Y]);
    expect(s.problems.recovery).toEqual([]);
  });

  it("shows a concurrent title as a conflict", () => {
    const base = built();
    const a = SectionReplica.fromSave(base.save(), { resource, principal: alice }, "local-state");
    const b = SectionReplica.fromSave(base.save(), { resource, principal: bob }, "local-state");
    a.commit([{ intent: "section.set_title", title: "A" }]);
    b.commit([{ intent: "section.set_title", title: "B" }]);
    const m = SectionReplica.fromChanges([...a.changes(), ...b.changes()], {
      resource,
      principal: alice,
    }).replica;
    expect(m.snapshot().title.conflicts).toEqual(["A", "B"]);
  });
});

describe("SectionReplica: staged batches", () => {
  it("changes nothing until apply, and keeps the replica usable when never applied", () => {
    const r = built();
    const before = r.revision();
    const staged = r.stage([{ intent: "section.set_title", title: "Staged" }]);
    expect(staged?.change.modelRevision).not.toBe(before);
    expect(r.revision()).toBe(before);
    expect((r.toJSON() as { section: { title: string } }).section.title).toBe("Joint launch");
    // Dropped: the replica writes on as if it had never been staged.
    r.commit([{ intent: "section.set_title", title: "Other" }]);
    expect((r.toJSON() as { section: { title: string } }).section.title).toBe("Other");
    expect(() => staged?.apply()).toThrow("stage it again");
  });

  it("reverts an applied batch while nothing came after it", () => {
    const r = built();
    const before = r.revision();
    const staged = r.stage([{ intent: "section.set_title", title: "Staged" }]);
    staged?.apply();
    staged?.revert();
    expect(r.revision()).toBe(before);
    r.commit([{ intent: "section.set_title", title: "After" }]);
    expect(r.changes()).toHaveLength(2);
    const again = r.stage([{ intent: "section.set_title", title: "Late" }]);
    again?.apply();
    r.commit([{ intent: "section.set_title", title: "Later" }]);
    expect(() => again?.revert()).toThrow("cannot be reverted");
  });

  it("adopts the staged change on apply, once", () => {
    const r = built();
    const staged = r.stage([{ intent: "section.set_title", title: "Staged" }]);
    staged?.apply();
    staged?.apply();
    expect(r.revision()).toBe(staged?.change.modelRevision);
    expect(r.changes()).toHaveLength(2);
  });

  it("does not hold its own changes as taken sequences when it receives them back", () => {
    const r = built();
    const c = r.commit([{ intent: "section.set_title", title: "Mine" }]);
    const out = r.receiveChanges([c?.change as Uint8Array]);
    expect(out.duplicates).toEqual([c?.hash]);
    expect(out.refused).toEqual([]);
  });
});
