// Authoring through the sdk-ts section writer (LFCP-02-012) against the
// shared sections reference corpus at the baseline in spec.lock:
//
// - SS01: the creator's genesis and its initial content, written through
//   section.create, the creation intents and section.mark_ready with the
//   corpus's identities, reach the reference state exactly, as logical JSON
//   (identical bytes are not required: SHARED-SECTIONS-TEST-VECTORS-01 §5);
// - SS03 (the Task half) and SS11: Task field intents on a section Task
//   reach the expected Task and leave the child paragraph untouched;
// - SS18: an unknown node extension survives a Task edit by this writer;
// - SS09: three moves of one Task reach the reference state, historical
//   slots included; SS02: two writers' concurrent inserts after one Task
//   merge to the reference state, sibling order included;
// - SS15 and SS26: C's explicit resolution of a placement conflict and of a
//   parent cycle, authored on the merged branches, reaches the reference
//   state and a VALID tree;
// - SS07, SS08, SS24, SS25 and SS27: deletion and restoration written by
//   this writer on two branches (and C's resolution) reach the reference
//   state, hidden nodes and retained concurrent edits included;
// - SS06, SS14, SS16, SS17, SS40 and SS47 to SS51: Text edits, splits and
//   joins written through the Text intents (LFCP-02-016) reach the
//   reference state, concurrent ones included.

import { fromHex, principalId, resourceId, toHex } from "@openlfcp/core";
import { createTask } from "@openlfcp/shared-objects";
import { type SectionIntent, SectionReplica } from "@openlfcp/shared-objects/sections";
import { describe, expect, it } from "vitest";
import { openSpec } from "../spec.mjs";

const CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

interface Bytes {
  readonly base64: string;
}
interface Case {
  readonly id: string;
  readonly base_changes: readonly Bytes[];
  readonly branches: { readonly A: readonly Bytes[]; readonly B: readonly Bytes[] };
  readonly expected: {
    readonly texts: Readonly<Record<string, string>>;
    readonly tasks: Readonly<Record<string, Record<string, unknown>>>;
  };
  readonly reference_snapshot: Bytes;
}
interface Suite {
  readonly identities: {
    readonly resource_hex: string;
    readonly ids: Readonly<Record<string, string>>;
    readonly actors: Readonly<
      Record<string, { readonly principal_hex: string; readonly actor_hex: string }>
    >;
  };
  readonly cases: readonly Case[];
}
type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
interface State {
  section: { title: string; created_by: string; children: string[] };
  placements: Record<string, { node_id: string; parent_id: string }>;
  nodes: Record<string, { placement: string; text?: string; extensions: Record<string, Json> }>;
  objects: Record<string, { title: string; created_by: string }>;
}

const suite = openSpec().readJson(CORPUS) as Suite;
const bytes = (b: Bytes) => Uint8Array.from(atob(b.base64), (c) => c.charCodeAt(0));
const kase = (id: string) => suite.cases.find((c) => c.id === id) as Case;
const ids = suite.identities.ids as Record<string, string>;
const resource = resourceId(fromHex(suite.identities.resource_hex));
const principal = (name: string) =>
  principalId(fromHex((suite.identities.actors[name] as { principal_hex: string }).principal_hex));
const A_ = { resource, principal: principal("A") };
const reference = (id: string) => SectionReplica.fromSave(bytes(kase(id).reference_snapshot), A_);

/** JSON with object keys sorted, so that states compare whatever their history. */
function canonical(v: Json): Json {
  if (Array.isArray(v)) return v.map(canonical);
  if (v !== null && typeof v === "object")
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, canonical(v[k] as Json)]),
    );
  return v;
}

/** SS01's document, authored by this writer with the corpus's identities and placements. */
function authorSS01(): SectionReplica {
  const ref = reference("SS01").toJSON() as unknown as State;
  const slot = (node: string) => (ref.nodes[node] as { placement: string }).placement;
  const text = (node: string) => (ref.nodes[node] as { text: string }).text;
  const A = principal("A");
  const r = SectionReplica.empty(A_);
  r.commit([
    {
      intent: "section.create",
      sectionId: ids.section as string,
      title: ref.section.title,
      createdBy: A,
      ready: false,
    },
  ]);
  const node = (
    intent: "paragraph.create" | "item.create",
    id: string,
    parent: string,
    after: string | null,
  ): SectionIntent => ({
    intent,
    id,
    parent,
    after,
    text: text(id),
    createdBy: A,
    placementId: slot(id),
  });
  const task = ids.task as string;
  r.commit([
    {
      intent: "task.create_in_section",
      task: createTask({
        id: task as never,
        title: (ref.objects[task] as { title: string }).title,
        createdBy: A,
      }).task,
      parent: ids.section as string,
      after: null,
      placementId: slot(task),
    },
    node("paragraph.create", ids.para as string, task, null),
    node("item.create", ids.x as string, ids.section as string, task),
    node("item.create", ids.y as string, ids.section as string, ids.x as string),
    { intent: "section.mark_ready" },
  ]);
  return r;
}

describe("authoring the shared sections corpus (LFCP-02-012)", () => {
  it("writes with the corpus actor of its Principal (§2)", () => {
    expect(toHex(SectionReplica.empty(A_).actorId)).toBe(suite.identities.actors.A?.actor_hex);
  });

  it("SS01: genesis and initial content reach the reference state", () => {
    const authored = authorSS01();
    expect(authored.validate().state).toBe("ready");
    expect(canonical(authored.toJSON() as Json)).toEqual(
      canonical(reference("SS01").toJSON() as Json),
    );
  });

  it("SS11 and SS03: a Task field edit updates the Task, not its child content", () => {
    const task = ids.task as string;
    const para = ids.para as string;
    for (const [id, intent] of [
      [
        "SS11",
        {
          intent: "task.set_title",
          id: task,
          title: kase("SS11").expected.tasks[task]?.title as string,
        },
      ],
      ["SS03", { intent: "task.set_status", id: task, status: "done" }],
    ] as const) {
      const r = authorSS01();
      r.commit([intent as unknown as SectionIntent]);
      const s = r.toJSON() as unknown as State;
      const expected = kase(id).expected.tasks[task] as Record<string, unknown>;
      expect(s.objects[task]).toMatchObject(
        id === "SS11" ? { title: expected.title } : { status: expected.status },
      );
      expect(s.nodes[para]?.text).toBe(kase("SS01").expected.texts[para]);
    }
  });

  it("SS18: an unknown node extension survives this writer's Task edit", () => {
    const r = reference("SS18");
    const para = ids.para as string;
    const before = (r.toJSON() as unknown as State).nodes[para]?.extensions;
    expect(before).toHaveProperty(["com.example.future"]);
    r.commit([{ intent: "task.set_title", id: ids.task as never, title: "Edited" }]);
    expect((r.toJSON() as unknown as State).nodes[para]?.extensions).toEqual(before);
    expect(r.validate().nodes.size).toBe(0);
  });

  it("SS09: repeated moves keep one identity and every historical slot", () => {
    const ref = reference("SS09").toJSON() as unknown as State;
    const task = ids.task as string;
    const first = (reference("SS01").toJSON() as unknown as State).nodes[task]?.placement;
    const slotUnder = (parent: string) =>
      Object.entries(ref.placements).find(
        ([pid, p]) => p.node_id === task && p.parent_id === parent && pid !== first,
      )?.[0] as string;
    const r = authorSS01();
    r.commit([
      {
        intent: "node.move",
        id: task,
        parent: ids.x as string,
        after: null,
        placementId: slotUnder(ids.x as string),
      },
    ]);
    r.commit([
      {
        intent: "node.move",
        id: task,
        parent: ids.y as string,
        after: null,
        placementId: slotUnder(ids.y as string),
      },
    ]);
    r.commit([
      {
        intent: "node.move",
        id: task,
        parent: ids.section as string,
        after: ids.y as string,
        placementId: slotUnder(ids.section as string),
      },
    ]);
    expect(canonical(r.toJSON() as Json)).toEqual(canonical(ref as unknown as Json));
  });

  it("SS02: concurrent inserts after one Task merge to the reference order", () => {
    const ref = reference("SS02").toJSON() as unknown as State;
    const task = ids.task as string;
    const insert = (who: "A" | "B", node: string) => {
      const r = SectionReplica.fromSave(
        authorSS01().save(),
        { resource, principal: principal(who) },
        "local-state",
      );
      r.commit([
        {
          intent: "paragraph.create",
          id: node,
          parent: ids.section as string,
          after: task,
          text: ref.nodes[node]?.text as string,
          createdBy: principal(who),
          placementId: ref.nodes[node]?.placement as string,
        },
      ]);
      return r.changes().at(-1) as Uint8Array;
    };
    const base = authorSS01().changes();
    const a = insert("A", ids.a as string);
    const b = insert("B", ids.b as string);
    const merged = SectionReplica.fromChanges([...base, b, a], A_);
    expect(merged.unapplied).toEqual([]);
    const got = merged.replica.toJSON() as unknown as State;
    expect(got.section.children).toEqual(ref.section.children);
    expect(canonical(got as unknown as Json)).toEqual(canonical(ref as unknown as Json));
  });

  for (const [id, mover, parent, after] of [
    ["SS15", "task", "section", null],
    ["SS26", "x", "section", "task"],
  ] as const)
    it(`${id}: C's explicit resolution reaches the reference state`, () => {
      const c = kase(id);
      const ref = reference(id).toJSON() as unknown as State;
      const node = ids[mover] as string;
      const target = ids[parent] as string;
      // C's fresh slot: the reference placement of the node under the target that no branch wrote.
      const merged = SectionReplica.fromChanges(
        [...c.base_changes, ...c.branches.A, ...c.branches.B].map(bytes),
        { resource, principal: principal("C") },
      );
      expect(merged.unapplied).toEqual([]);
      expect(merged.replica.tree().classification).toBe("STRUCTURAL_ATTENTION");
      const known = new Set(Object.keys((merged.replica.toJSON() as unknown as State).placements));
      const slot = Object.entries(ref.placements).find(
        ([pid, p]) => p.node_id === node && p.parent_id === target && !known.has(pid),
      )?.[0] as string;
      const move = {
        id: node,
        parent: target,
        after: after === null ? null : (ids[after] as string),
        placementId: slot,
      };
      merged.replica.commit([
        id === "SS15"
          ? { intent: "node.resolve_placement", ...move }
          : { intent: "structure.resolve", moves: [move] },
      ]);
      expect(merged.replica.tree().classification).toBe("VALID");
      expect(canonical(merged.replica.toJSON() as Json)).toEqual(canonical(ref as unknown as Json));
    });

  describe("lifecycle (LFCP-02-015)", () => {
    const task = ids.task as string;
    const para = ids.para as string;
    /** A placement of `node` in the reference state of `id` that SS01 does not have. */
    const newSlot = (id: string, node: string) => {
      const before = new Set(
        Object.keys((reference("SS01").toJSON() as unknown as State).placements),
      );
      const ref = reference(id).toJSON() as unknown as State;
      return Object.entries(ref.placements).find(
        ([pid, p]) => p.node_id === node && !before.has(pid),
      )?.[0] as string;
    };
    const cases: Record<
      string,
      { base?: SectionIntent[]; a: SectionIntent[]; b: SectionIntent[]; after?: SectionIntent[] }
    > = {
      SS07: {
        a: [{ intent: "node.delete", id: task }],
        b: [
          {
            intent: "node.move",
            id: para,
            parent: ids.section as string,
            after: ids.y as string,
            placementId: newSlot("SS07", para),
          },
        ],
      },
      SS08: { a: [{ intent: "node.delete", id: task }], b: [{ intent: "node.restore", id: task }] },
      SS24: {
        a: [{ intent: "node.delete", id: task }],
        b: [
          {
            intent: "paragraph.create",
            id: ids.extra as string,
            parent: task,
            after: para,
            text: "Retained new child",
            createdBy: principal("B"),
            placementId: newSlot("SS24", ids.extra as string),
          },
        ],
      },
      SS25: {
        base: [
          { intent: "node.delete", id: task },
          { intent: "node.delete", id: para },
        ],
        a: [{ intent: "node.restore", id: task }],
        b: [],
      },
      SS27: {
        a: [{ intent: "node.delete", id: task }],
        b: [{ intent: "node.restore", id: task }],
        after: [{ intent: "node.restore", id: task }],
      },
    };
    for (const [id, steps] of Object.entries(cases))
      it(`${id}: written through the lifecycle intents, reaches the reference state`, () => {
        const start = authorSS01();
        if (steps.base) start.commit(steps.base);
        const branch = (who: "A" | "B", intents: SectionIntent[]) => {
          const r = SectionReplica.fromSave(
            start.save(),
            { resource, principal: principal(who) },
            "local-state",
          );
          if (intents.length > 0) r.commit(intents);
          return r.changes();
        };
        const merged = SectionReplica.fromChanges(
          [...branch("A", steps.a), ...branch("B", steps.b)],
          { resource, principal: principal("C") },
        ).replica;
        if (steps.after) merged.commit(steps.after);
        const ref = reference(id);
        expect(canonical(merged.toJSON() as Json)).toEqual(canonical(ref.toJSON() as Json));
        const got = merged.tree();
        const want = ref.tree();
        expect([
          got.classification,
          got.tree,
          got.hidden,
          got.recovery,
          got.retainedConcurrentEdits,
        ]).toEqual([
          want.classification,
          want.tree,
          want.hidden,
          want.recovery,
          want.retainedConcurrentEdits,
        ]);
      });
  });

  describe("Text, split and join (LFCP-02-016)", () => {
    const task = ids.task as string;
    const para = ids.para as string;
    const extra = ids.extra as string;
    type Step = (r: SectionReplica) => SectionIntent[];
    /** The placement of `node` in case `id`'s reference state. */
    const slotOf = (id: string, node: string) =>
      (reference(id).toJSON() as unknown as State).nodes[node]?.placement as string;
    const edit =
      (node: string, index: number, deleteCount: number, insert: string): Step =>
      (r) => [
        {
          intent: "text.edit",
          id: node,
          base: r.revision(),
          edits: [{ index, deleteCount, insert }],
        },
      ];
    const length = (r: SectionReplica, node: string) =>
      Array.from((r.toJSON() as unknown as State).nodes[node]?.text ?? "").length;
    const split =
      (id: string, at: number, newId: string): Step =>
      (r) => [
        {
          intent: "paragraph.split",
          id: para,
          base: r.revision(),
          at,
          newId,
          createdBy: principal("A"),
          placementId: slotOf(id, newId),
        },
      ];
    const join: Step = () => [{ intent: "node.join", id: para, second: extra }];
    const joinBase =
      (id: string): Step =>
      () => [
        {
          intent: "paragraph.create",
          id: extra,
          parent: task,
          after: para,
          text: "Second note",
          createdBy: principal("A"),
          placementId: slotOf(id, extra),
        },
      ];
    const alphabet = Array.from("абвгдеж😀");
    const long = (n: number) =>
      Array.from({ length: n }, (_, k) => alphabet[k % alphabet.length]).join("");
    const cases: Record<string, { base?: Step; a: Step[]; b?: Step[] }> = {
      SS06: {
        a: [() => [{ intent: "node.delete", id: task }]],
        b: [edit(para, 0, 0, "Retained ")],
      },
      SS14: {
        base: (r) => edit(para, 0, length(r, para), "А😀Б")(r),
        a: [edit(para, 2, 0, "!")],
        b: [edit(para, 0, 0, "Я: ")],
      },
      SS16: { a: [split("SS16", 6, extra)] },
      SS17: { base: joinBase("SS17"), a: [join] },
      SS47: { a: [split("SS47", 6, ids.a as string)], b: [split("SS47", 5, ids.b as string)] },
      SS48: { a: [split("SS48", 6, ids.a as string)], b: [edit(para, 14, 0, " v2")] },
      SS49: { base: joinBase("SS49"), a: [join], b: [edit(extra, 11, 0, "!")] },
      SS50: { base: joinBase("SS50"), a: [join], b: [join] },
      SS51: { base: joinBase("SS51"), a: [split("SS51", 6, ids.a as string)], b: [join] },
    };
    const run = (steps: { base?: Step; a: Step[]; b?: Step[] }) => {
      const start = authorSS01();
      if (steps.base) start.commit(steps.base(start));
      const branch = (who: "A" | "B", list: Step[]) => {
        const r = SectionReplica.fromSave(
          start.save(),
          { resource, principal: principal(who) },
          "local-state",
        );
        for (const step of list) r.commit(step(r));
        return r.changes();
      };
      return SectionReplica.fromChanges([...branch("A", steps.a), ...branch("B", steps.b ?? [])], {
        resource,
        principal: principal("C"),
      }).replica;
    };
    for (const [id, steps] of Object.entries(cases))
      it(`${id}: written through the Text intents, reaches the reference state`, () => {
        const merged = run(steps);
        const ref = reference(id);
        expect(canonical(merged.toJSON() as Json)).toEqual(canonical(ref.toJSON() as Json));
        const got = merged.tree();
        const want = ref.tree();
        expect([
          got.classification,
          got.tree,
          got.hidden,
          got.recovery,
          got.retainedConcurrentEdits,
        ]).toEqual([
          want.classification,
          want.tree,
          want.hidden,
          want.recovery,
          want.retainedConcurrentEdits,
        ]);
      });

    it("SS40: a 20,000-character insertion in three runs within the Text budget", () => {
      const ref = reference("SS40").toJSON() as unknown as State;
      const inserted = Array.from(ref.nodes[para]?.text ?? "").slice(14);
      const r = authorSS01();
      for (let at = 0; at < inserted.length; at += 8192)
        r.commit(edit(para, 14 + at, 0, inserted.slice(at, at + 8192).join(""))(r));
      expect(r.changes()).toHaveLength(2 + 3);
      expect(canonical(r.toJSON() as Json)).toEqual(canonical(ref as unknown as Json));
      expect(() => r.commit(edit(para, 0, 0, long(8193))(r))).toThrow(
        expect.objectContaining({ code: "OVER_BUDGET" }),
      );
    });
  });
});
