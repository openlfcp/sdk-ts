// Authoring through the sdk-ts section writer (LFCP-02-012) against the
// shared sections reference corpus at the baseline in spec.lock:
//
// - SS01: the creator's genesis and its initial content, written through
//   section.create, the creation intents and section.mark_ready with the
//   corpus's identities, reach the reference state exactly, as logical JSON
//   (identical bytes are not required: SHARED-SECTIONS-TEST-VECTORS-01 §5);
// - SS03 (the Task half) and SS11: Task field intents on a section Task
//   reach the expected Task and leave the child paragraph untouched;
// - SS18: an unknown node extension survives a Task edit by this writer.

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
  section: { title: string; created_by: string };
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
});
