// sectionEnd (504, spike B-001 gap G9): where an application without a
// Markdown editor appends a node — after the last visible top-level node,
// never after a nested one or a deleted one.

import { parseObjectId, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask } from "../src/index.js";
import { type SectionIntent, SectionReplica, sectionEnd } from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(9));
const alice = principalId(new Uint8Array(32).fill(1));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const para = (n: number, parent: string, after: string | null): SectionIntent => ({
  intent: "paragraph.create",
  id: id(n),
  parent,
  after,
  text: `p${n}`,
  createdBy: alice,
});

describe("sectionEnd", () => {
  it("is first in an empty section, then after the last visible top-level node", () => {
    const r = SectionReplica.empty({ resource, principal: alice });
    r.commit([{ intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice }]);
    expect(sectionEnd(r.snapshot(), SECTION)).toEqual({ parent: SECTION, after: null });

    const task = createTask({ id: parseObjectId(id(20)), title: "t", createdBy: alice }).task;
    r.commit([
      para(10, SECTION, null),
      { intent: "task.create_in_section", task, parent: SECTION, after: id(10) },
      // A child of the Task: nested, not top-level.
      {
        intent: "item.create",
        id: id(21),
        parent: id(20),
        after: null,
        text: "sub",
        createdBy: alice,
      },
      para(11, SECTION, id(20)),
    ]);
    expect(sectionEnd(r.snapshot(), SECTION)).toEqual({ parent: SECTION, after: id(11) });

    // A deleted last node is not visible: the end is before it.
    r.commit([{ intent: "node.delete", id: id(11) }]);
    expect(sectionEnd(r.snapshot(), SECTION)).toEqual({ parent: SECTION, after: id(20) });

    // Appending there puts the new Task last.
    const next = createTask({ id: parseObjectId(id(30)), title: "last", createdBy: alice }).task;
    r.commit([
      { intent: "task.create_in_section", task: next, ...sectionEnd(r.snapshot(), SECTION) },
    ]);
    const top = r
      .snapshot()
      .order.filter((e) => e.depth === 0)
      .map((e) => e.id);
    expect(top).toEqual([id(10), id(20), id(30)]);
  });
});
