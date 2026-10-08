// The section writer (LFCP-02-012): section and creation intents, Task
// field intents on section Tasks, batches as one change, and the refusals
// before commit. The corpus comparison (SS01, SS11) runs in
// conformance/shared-sections/authoring.test.ts.

import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange, checkChangeActor } from "../src/admission/index.js";
import { createTask } from "../src/index.js";
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

  it("refuses a batch over the §16.2 node budget", () => {
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
    const e = refusal(() => r.commit(many));
    expect([e.code, e.intentIndex]).toEqual(["OVER_BUDGET", AUTHORING_BUDGET.createdNodes]);
  });
});
