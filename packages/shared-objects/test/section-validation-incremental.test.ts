// LFCP-02-068 remediation: validateSection keeps a validation per revision
// and validates a later revision incrementally (only the entities its
// changes touched are read again). Here, on seeded random histories of
// valid and invalid writes, concurrent edits, collisions and deletions,
// every revision's validation equals a validation in full.

import * as A from "@automerge/automerge";
import { principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask } from "../src/index.js";
import { SectionReplica, validateSection } from "../src/sections/index.js";
import { type SectionValidation, validateSectionInFull } from "../src/sections/schema.js";

// biome-ignore lint/suspicious/noExplicitAny: random edits write arbitrary, often invalid shapes
type Doc = Record<string, any>;
const S = (s: string) => new A.ImmutableString(s);
const me = principalId(new Uint8Array(32).fill(3));
const R = resourceId(new Uint8Array(32).fill(5));
const uid = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = uid(1);

/** A deterministic generator (mulberry32). */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A valid section of `w` Tasks, each with a paragraph, written through the SDK. */
function start(w: number): A.Doc<Doc> {
  const replica = SectionReplica.empty({ resource: R, principal: me });
  replica.commit([{ intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: me }]);
  const intents = [];
  for (let k = 0; k < w; k++) {
    intents.push({
      intent: "task.create_in_section" as const,
      task: createTask({ id: uid(100 + k) as never, title: `Task ${k}`, createdBy: me }).task,
      parent: SECTION,
      after: null,
    });
    intents.push({
      intent: "paragraph.create" as const,
      id: uid(500 + k),
      parent: uid(100 + k),
      after: null,
      text: `Notes ${k}`,
      createdBy: me,
    });
  }
  replica.commit(intents);
  return A.load<Doc>(replica.save());
}

const view = (v: SectionValidation) => ({
  state: v.state,
  problems: v.problems,
  sectionId: v.sectionId,
  nodes: [...v.nodes],
  placements: [...v.placements],
  objects: [...v.objects],
  collisions: v.collisions,
  collided: v.collided,
});

type Edit = (d: Doc, pick: <T>(xs: readonly T[]) => T) => void;
const keys = (o: unknown) => Object.keys((o ?? {}) as object);
const EDITS: readonly Edit[] = [
  // Ordinary writes.
  (d, pick) => {
    // Collaborative Text reads as a string; a scalar written over it does not.
    const k = pick(keys(d.nodes).filter((n) => typeof d.nodes[n].text === "string"));
    if (k !== undefined) A.splice(d, ["nodes", k, "text"], 0, 0, "x");
  },
  (d, pick) => {
    const k = pick(keys(d.objects));
    if (k !== undefined) d.objects[k].status = S(pick(["todo", "done", "in_progress"]));
  },
  (d, pick) => {
    const k = pick(keys(d.nodes));
    if (k !== undefined) d.nodes[k].lifecycle = S(pick(["active", "deleted"]));
  },
  // Invalid writes.
  (d, pick) => {
    const k = pick(keys(d.nodes));
    if (k !== undefined) d.nodes[k].kind = S(pick(["task", "paragraph", "bogus"]));
  },
  (d, pick) => {
    const k = pick(keys(d.nodes));
    if (k !== undefined) d.nodes[k].created_by = S(pick(["p:bad", "nobody"]));
  },
  (d, pick) => {
    const k = pick(keys(d.nodes).filter((n) => d.nodes[n].text !== undefined));
    if (k !== undefined) d.nodes[k].text = S("now a scalar");
  },
  (d, pick) => {
    const k = pick(keys(d.placements));
    if (k !== undefined) d.placements[k].parent_id = S(pick([...keys(d.nodes), uid(9999)]));
  },
  (d, pick) => {
    const k = pick(keys(d.nodes));
    if (k !== undefined) d.nodes[k].placement = S(pick([...keys(d.placements), uid(9998)]));
  },
  (d, pick) => {
    const k = pick(keys(d.objects));
    if (k !== undefined) d.objects[k].title = pick(["collaborative", S("fine")]);
  },
  // Deletions and new entities.
  (d, pick) => {
    const k = pick(keys(d.nodes));
    if (k !== undefined) delete d.nodes[k];
  },
  (d, pick) => {
    const k = pick(keys(d.placements));
    if (k !== undefined) delete d.placements[k];
  },
  (d) => {
    const n = uid(2000 + keys(d.nodes).length);
    d.nodes[n] = {
      id: S(n),
      kind: S("paragraph"),
      created_by: S("p:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
      lifecycle: S("active"),
      placement: S(uid(9997)),
      children: [],
      extensions: {},
      text: "new",
    };
  },
  (d) => {
    d.section.title = S(`Plan ${Math.random() < 2 ? "v2" : ""}`);
  },
];

/** One step: a local edit, or two concurrent edits merged (a conflict or a collision). */
function step(doc: A.Doc<Doc>, next: () => number): A.Doc<Doc> {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)] as T;
  const edit = pick(EDITS);
  if (next() < 0.7) return A.change(doc, { time: 0 }, (d) => edit(d, pick));
  const left = A.change(A.clone(doc), { time: 0 }, (d) => edit(d, pick));
  const right = A.change(A.clone(doc), { time: 0 }, (d) => {
    if (next() < 0.5) pick(EDITS)(d, pick);
    else {
      // The same new key on both sides: a collision.
      const k = pick([...keys(d.nodes), uid(3000)]);
      d.nodes[k] = { id: S(k), kind: S("raw"), text: "concurrent" };
    }
  });
  return A.merge(left, right);
}

describe("incremental section validation", () => {
  for (const seed of [1, 2, 3, 4])
    it(`equals a validation in full at every revision (seed ${seed})`, () => {
      const next = rng(seed);
      let doc = start(6);
      expect(view(validateSection(doc))).toEqual(view(validateSectionInFull(doc)));
      for (let i = 0; i < 120; i++) {
        doc = step(doc, next);
        expect(view(validateSection(doc)), `step ${i}`).toEqual(view(validateSectionInFull(doc)));
      }
    });

  it("validates a revision of another document in full, not from an unrelated base", () => {
    const a = start(3);
    const b = start(4);
    expect(view(validateSection(a))).toEqual(view(validateSectionInFull(a)));
    expect(view(validateSection(b))).toEqual(view(validateSectionInFull(b)));
    const a2 = A.change(a, { time: 0 }, (d) => {
      d.nodes[uid(100)].kind = S("bogus");
    });
    expect(view(validateSection(a2))).toEqual(view(validateSectionInFull(a2)));
  });
});
