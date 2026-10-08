// The shared sections reference corpus (SHARED-SECTIONS-TEST-VECTORS-01,
// Working Draft) through the sdk-ts section schema (LFCP-02-011), read at
// the development pin in spec-sections.lock. For every case:
//
// - the reference snapshot loads, and replaying the case's changes without
//   the ones refused at admission and held behind them reaches its heads;
// - schema validation never changes the document, and reports exactly the
//   invalid nodes the corpus expects (§14.2), with no section-level problem,
//   in the state the classification implies (IMPORTING, §12.1);
// - Task strings are scalar strings and paragraph/item bodies are Text.
//
// SS01 and SS18 are checked in detail. The effective tree, structural
// facts and admission are later tasks (LFCP-02-013..017).

import { fromHex, principalId, resourceId, toHex } from "@openlfcp/core";
import { checkChange, checkChangeActor } from "@openlfcp/shared-objects/admission";
import {
  deriveSectionActorId,
  SECTIONS_PROFILE_ID,
  SectionDocument,
} from "@openlfcp/shared-objects/sections";
import { describe, expect, it } from "vitest";
import { openSpecSections } from "../spec.mjs";

const CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

interface Bytes {
  readonly base64: string;
  readonly sha256: string;
  readonly length: number;
}
interface Change extends Bytes {
  readonly change_hash: string;
  readonly actor: string;
  readonly seq: number;
  readonly deps: readonly string[];
}
interface Case {
  readonly id: string;
  readonly base_changes: readonly Change[];
  readonly branches: { readonly A: readonly Change[]; readonly B: readonly Change[] };
  readonly after_merge: readonly Change[];
  readonly expected: {
    readonly classification: string;
    readonly invalid: readonly { readonly id: string; readonly diagnostic: string }[];
    readonly refused: readonly { readonly change: string; readonly diagnostic: string }[];
    readonly held: readonly (string | { readonly change: string })[];
    readonly texts: Readonly<Record<string, string>>;
    readonly tasks: Readonly<Record<string, Record<string, unknown>>>;
  };
  readonly expected_heads: readonly string[];
  readonly reference_snapshot: Bytes;
}
interface Suite {
  readonly profile: string;
  readonly identities: {
    readonly resource_hex: string;
    readonly ids: Readonly<Record<string, string>>;
    readonly actors: Readonly<
      Record<string, { readonly principal_hex: string; readonly actor_hex: string }>
    >;
  };
  readonly cases: readonly Case[];
}

const suite = openSpecSections().readJson(CORPUS) as Suite;
const bytes = (b: Bytes) => Uint8Array.from(atob(b.base64), (c) => c.charCodeAt(0));
const load = (c: Case) => SectionDocument.fromSave(bytes(c.reference_snapshot));
const heldHash = (h: string | { readonly change: string }) =>
  typeof h === "string" ? h : h.change;

/** The case's admitted changes: all but the refused ones and those held behind them. */
function admitted(c: Case): Change[] {
  const out = new Set([
    ...c.expected.refused.map((r) => r.change),
    ...c.expected.held.map(heldHash),
  ]);
  return [...c.base_changes, ...c.branches.A, ...c.branches.B, ...c.after_merge].filter(
    (ch) => !out.has(ch.change_hash),
  );
}

describe("shared sections corpus (dev pin, pre-baseline)", () => {
  it("is the profile this module implements, on the pinned engine", () => {
    expect(suite.profile).toBe(SECTIONS_PROFILE_ID);
    expect(suite.cases.length).toBeGreaterThanOrEqual(41);
  });

  it("derives every fixture actor with the section domain (§2)", () => {
    const resource = resourceId(fromHex(suite.identities.resource_hex));
    for (const a of Object.values(suite.identities.actors))
      expect(toHex(deriveSectionActorId(resource, principalId(fromHex(a.principal_hex))))).toBe(
        a.actor_hex,
      );
  });

  it("binds every change to its author's section actor (§2, SOP §8)", () => {
    const actors = new Set(Object.values(suite.identities.actors).map((a) => a.actor_hex));
    for (const c of suite.cases)
      for (const ch of admitted(c)) {
        expect(actors.has(ch.actor), `${c.id} ${ch.change_hash}`).toBe(true);
        expect(checkChangeActor(checkChange(bytes(ch)), ch.actor).hash).toBe(ch.change_hash);
      }
  });

  for (const c of suite.cases)
    it(`${c.id}: schema validation matches the corpus`, () => {
      const doc = load(c);
      const heads = [...c.expected_heads].sort();
      expect(doc.heads()).toEqual(heads);
      const { document: replayed, unapplied } = SectionDocument.fromChanges(admitted(c).map(bytes));
      expect(unapplied).toEqual([]);
      expect(replayed.heads()).toEqual(heads);

      const before = doc.save();
      const v = doc.validate();
      expect(doc.save()).toEqual(before);
      expect(v.problems).toEqual([]);
      expect(v.collisions).toEqual([]);
      expect(v.state).toBe(c.expected.classification === "IMPORTING" ? "importing" : "ready");
      expect(v.placements.size).toBe(0);
      expect(v.objects.size).toBe(0);
      expect(
        [...v.nodes]
          .map(([id, p]) => ({ id, diagnostic: p.diagnostic }))
          .sort((a, b) => a.id.localeCompare(b.id)),
      ).toEqual(c.expected.invalid);
      expect(replayed.validate()).toEqual(v);
    });

  it("SS01: Task fields are scalars in objects, the paragraph is node Text (§2, §4.2)", () => {
    const c = suite.cases.find((x) => x.id === "SS01") as Case;
    const task = suite.identities.ids.task as string;
    const para = suite.identities.ids.para as string;
    const doc = load(c);
    for (const field of ["id", "type", "created_by", "lifecycle", "title", "status", "priority"])
      expect(doc.valueTypes(["objects", task, field]), field).toEqual(["str"]);
    expect(doc.valueTypes(["nodes", para, "text"])).toEqual(["text"]);
    expect(doc.valueTypes(["nodes", task, "text"])).toEqual([]);
    expect(doc.valueTypes(["nodes", task, "task_id"])).toEqual(["str"]);
    expect(doc.valueTypes(["section", "children"])).toEqual(["list"]);
    expect(doc.valueTypes(["section", "ready"])).toEqual(["boolean"]);
    const json = doc.toJSON() as {
      objects: Record<string, { title: string }>;
      nodes: Record<string, { text?: string; task_id?: string }>;
    };
    expect(json.nodes[para]?.text).toBe(c.expected.texts[para]);
    expect(json.objects[task]?.title).toBe(c.expected.tasks[task]?.title);
    expect(json.nodes[task]?.task_id).toBe(task);
  });

  it("SS18: an unknown node extension survives an unrelated edit and a reload", () => {
    const c = suite.cases.find((x) => x.id === "SS18") as Case;
    const para = suite.identities.ids.para as string;
    const path = ["nodes", para, "extensions", "com.example.future", "value"];
    const doc = load(c);
    expect(doc.valueTypes(path)).toEqual(["str"]);
    expect(doc.validate().nodes.size).toBe(0);
    const reloaded = SectionDocument.fromSave(doc.save(), "local-state");
    expect(reloaded.valueTypes(path)).toEqual(["str"]);
    const json = reloaded.toJSON() as {
      nodes: Record<string, { extensions: Record<string, { value: string }> }>;
    };
    expect(json.nodes[para]?.extensions["com.example.future"]?.value).toBe("keep-me");
  });
});
