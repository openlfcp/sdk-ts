// Section admission (LFCP-02-017, SHARED-SECTIONS-PROFILE-01 §14.1): rules
// A1–A5 and §12.1 on hand-crafted malicious changes, their precedence, and
// that a refused change is never merged and holds the changes after it.

import * as A from "@automerge/automerge";
import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask } from "../src/index.js";
import { deriveSectionActorId, type SectionIntent, SectionReplica } from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const bob = principalId(new Uint8Array(32).fill(2));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const [SECTION, T, P, X] = [id(1), id(2), id(3), id(4)];
const S = (s: string) => new A.ImmutableString(s);
// biome-ignore lint/suspicious/noExplicitAny: crafted changes write arbitrary shapes
type Doc = Record<string, any>;

function section(): SectionReplica {
  const r = SectionReplica.empty({ resource, principal: alice });
  const intents: SectionIntent[] = [
    { intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice },
    {
      intent: "task.create_in_section",
      task: createTask({ id: T as never, title: "T", createdBy: alice }).task,
      parent: SECTION,
      after: null,
    },
    { intent: "paragraph.create", id: P, parent: T, after: null, text: "para", createdBy: alice },
    { intent: "item.create", id: X, parent: SECTION, after: T, text: "x", createdBy: alice },
  ];
  r.commit(intents);
  return r;
}

/** A change Bob's actor writes on top of `r`, with raw Automerge. */
function crafted(r: SectionReplica, fn: (d: Doc) => void, who = bob): Uint8Array {
  const actor = toHex(deriveSectionActorId(resource, who));
  const doc = A.change(A.load<Doc>(r.save(), { actor }), { time: 0 }, fn);
  return A.getLastLocalChange(doc) as Uint8Array;
}

/** The diagnostic a fresh receiver of `r`'s history gives `bytes`, or null when admitted. */
function admit(r: SectionReplica, bytes: Uint8Array, signer = bob): string | null {
  const receiver = SectionReplica.fromChanges(r.changes(), { resource, principal: alice }).replica;
  const before = receiver.revision();
  const out = receiver.receiveChanges([{ bytes, signer }]);
  expect(out.waiting).toEqual([]);
  const refused = out.refused[0];
  if (refused !== undefined) {
    expect(receiver.revision()).toBe(before);
    return refused.diagnostic;
  }
  return null;
}

const placementOf = (d: Doc, n: string) => String(d.nodes[n].placement);

describe("section admission (§14.1)", () => {
  const cases: [string, (d: Doc) => void, string][] = [
    ["A4: a root container replaced", (d) => (d.nodes = {}), "CONTAINER_REPLACED"],
    ["A4: a node map deleted", (d) => delete d.nodes[X], "CONTAINER_REPLACED"],
    ["A4: a node's Text replaced", (d) => (d.nodes[P].text = "new"), "CONTAINER_REPLACED"],
    ["A4: a node's children replaced", (d) => (d.nodes[T].children = []), "CONTAINER_REPLACED"],
    ["A1: a slot deleted", (d) => d.section.children.splice(0, 1), "CHILDREN_LIST_MUTATED"],
    ["A1: a slot replaced", (d) => (d.section.children[0] = S(id(50))), "CHILDREN_LIST_MUTATED"],
    [
      "A2: an existing placement inserted again",
      (d) => d.section.children.push(S(placementOf(d, X))),
      "PLACEMENT_NOT_ATOMIC",
    ],
    [
      "A2: a placement created but not inserted",
      (d) => {
        d.placements[id(51)] = {
          id: S(id(51)),
          node_id: S(X),
          parent_id: S(SECTION),
          created_by: S("p:x"),
        };
        d.nodes[X].placement = S(id(51));
      },
      "PLACEMENT_NOT_ATOMIC",
    ],
    [
      "A2: a placement inserted under another parent",
      (d) => {
        d.placements[id(52)] = {
          id: S(id(52)),
          node_id: S(X),
          parent_id: S(T),
          created_by: S("p:x"),
        };
        d.section.children.push(S(id(52)));
        d.nodes[X].placement = S(id(52));
      },
      "PLACEMENT_NOT_ATOMIC",
    ],
    [
      "A2: a placement its node does not select",
      (d) => {
        d.placements[id(53)] = {
          id: S(id(53)),
          node_id: S(X),
          parent_id: S(SECTION),
          created_by: S("p:x"),
        };
        d.section.children.push(S(id(53)));
      },
      "PLACEMENT_NOT_ATOMIC",
    ],
    [
      "A3: a placement's parent changed",
      (d) => (d.placements[placementOf(d, X)].parent_id = S(T)),
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "A3: a node's kind changed",
      (d) => (d.nodes[X].kind = S("paragraph")),
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "A3: a Task's type changed",
      (d) => (d.objects[T].type = S("note")),
      "IMMUTABLE_FIELD_MUTATED",
    ],
    ["A3: the section ID changed", (d) => (d.section.id = S(id(54))), "IMMUTABLE_FIELD_MUTATED"],
    ["§12.1: ready deleted", (d) => delete d.section.ready, "IMMUTABLE_FIELD_MUTATED"],
    ["§12.1: ready written false", (d) => (d.section.ready = false), "IMMUTABLE_FIELD_MUTATED"],
    [
      "A5: a Task title written as Text",
      (d) => (d.objects[T].title = "text"),
      "INVALID_FIELD_TYPE",
    ],
    [
      "A5: a node field written as Text",
      (d) => (d.nodes[X].list_style = "ordered"),
      "INVALID_FIELD_TYPE",
    ],
    [
      "A5: a children entry that is not a scalar string",
      (d) => d.nodes[T].children.push(7),
      "INVALID_FIELD_TYPE",
    ],
    [
      "precedence: A4 before A5 in one change",
      (d) => {
        d.objects[T].title = "text";
        d.nodes = {};
      },
      "CONTAINER_REPLACED",
    ],
  ];
  for (const [what, fn, diagnostic] of cases)
    it(`refuses ${what}: ${diagnostic}`, () => {
      const r = section();
      expect(admit(r, crafted(r, fn))).toBe(diagnostic);
    });

  it("admits valid edits written by hand: a title, a Text insert, an extension", () => {
    const r = section();
    expect(
      admit(
        r,
        crafted(r, (d) => (d.objects[T].title = S("New"))),
      ),
    ).toBeNull();
    expect(
      admit(
        r,
        crafted(r, (d) => A.splice(d as never, ["nodes", P, "text"], 0, 0, "x")),
      ),
    ).toBeNull();
    expect(
      admit(
        r,
        crafted(r, (d) => (d.nodes[X].extensions["com.example"] = { v: S("1") })),
      ),
    ).toBeNull();
  });

  it("refuses ready written by another actor, and admits it from the creator during an import", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    r.commit([
      { intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice, ready: false },
    ]);
    expect(
      admit(
        r,
        crafted(r, (d) => (d.section.ready = true)),
      ),
    ).toBe("IMMUTABLE_FIELD_MUTATED");
    expect(
      admit(
        r,
        crafted(r, (d) => (d.section.ready = true), alice),
        alice,
      ),
    ).toBeNull();
  });

  it("refuses a change of another signer's actor, and holds what depends on a refused change", () => {
    const r = section();
    const bad = crafted(r, (d) => d.section.children.splice(0, 1));
    expect(admit(r, bad, alice)).toBe("CHANGE_ACTOR_MISMATCH");
    const actor = toHex(deriveSectionActorId(resource, bob));
    const badDoc = A.applyChanges(A.load<Doc>(r.save(), { actor }), [bad])[0];
    const next = A.getLastLocalChange(
      A.change(badDoc, { time: 0 }, (d) => (d.objects[T].title = S("After"))),
    ) as Uint8Array;
    const receiver = SectionReplica.fromChanges(r.changes(), {
      resource,
      principal: alice,
    }).replica;
    const out = receiver.receiveChanges([
      { bytes: bad, signer: bob },
      { bytes: next, signer: bob },
    ]);
    expect(out.refused.map((x) => x.diagnostic)).toEqual(["CHILDREN_LIST_MUTATED"]);
    expect(out.waiting).toEqual([A.decodeChange(next).hash]);
    expect((receiver.toJSON() as Doc).objects[T].title).toBe("T");
  });

  it("admits this SDK's own writer's changes, every intent included", () => {
    const r = section();
    const before = r.changes().length;
    r.commit([{ intent: "node.move", id: P, parent: X, after: null }]);
    r.commit([{ intent: "node.delete", id: X }]);
    r.commit([{ intent: "node.restore", id: X }]);
    r.commit([
      {
        intent: "text.edit",
        id: P,
        base: r.revision(),
        edits: [{ index: 0, deleteCount: 1, insert: "P" }],
      },
    ]);
    r.commit([
      {
        intent: "paragraph.split",
        id: P,
        base: r.revision(),
        at: 2,
        newId: id(60),
        createdBy: alice,
      },
    ]);
    r.commit([{ intent: "node.join", id: P, second: id(60) }]);
    const receiver = SectionReplica.empty({ resource, principal: bob });
    const out = receiver.receiveChanges(r.changes());
    expect(out.refused).toEqual([]);
    expect(out.admitted).toHaveLength(before + 6);
    expect(receiver.revision()).toBe(r.revision());
  });
});
