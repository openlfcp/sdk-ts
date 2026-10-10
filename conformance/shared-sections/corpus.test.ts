// The shared sections reference corpus (SHARED-SECTIONS-TEST-VECTORS-01,
// Working Draft) through the sdk-ts section schema (LFCP-02-011), read at
// the spec baseline pinned in spec.lock. For every case:
//
// - the reference snapshot loads (within the SOP §13.1 floor, or is refused
//   when the case says it is past it), and replaying the case's changes without
//   the ones refused at admission and held behind them reaches its heads;
// - schema validation never changes the document, and reports exactly the
//   invalid nodes the corpus expects (§14.2), with no section-level problem,
//   in the state the classification implies (IMPORTING, §12.1);
// - Task strings are scalar strings and paragraph/item bodies are Text;
// - the effective tree, hidden nodes, recovery facts and classification
//   are the corpus's (LFCP-02-014);
// - received through SectionReplica.receiveChanges, every change is
//   admitted or refused (§14.1) and held as the corpus says (LFCP-02-017).
//
// SS01 and SS18 are checked in detail. The effective tree, structural
// facts and admission are later tasks (LFCP-02-013..017).

import { fromHex, principalId, resourceId, toHex } from "@openlfcp/core";
import { checkChange, checkChangeActor } from "@openlfcp/shared-objects/admission";
import {
  deriveSectionActorId,
  SECTIONS_PROFILE_ID,
  SectionDocument,
  SectionReplica,
} from "@openlfcp/shared-objects/sections";
import { describe, expect, it } from "vitest";
import { openSpec } from "../spec.mjs";
import { readSectionsCorpus, withPending } from "./corpus-format.mjs";

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
  /** The fixture Principal that signs the Data Unit, for an injected change. */
  readonly signer?: string;
}
interface Case {
  readonly id: string;
  readonly base_changes: readonly Change[];
  readonly branches: { readonly A: readonly Change[]; readonly B: readonly Change[] };
  readonly after_merge: readonly Change[];
  readonly expected: {
    readonly classification: string;
    readonly collisions?: readonly string[];
    /** SOP §13.1: whether the reference snapshot is within the floor (SS55, SS56). */
    readonly snapshot?: { readonly rows: number; readonly within_floor: boolean };
    readonly invalid: readonly { readonly id: string; readonly diagnostic: string }[];
    /** §14.1: a refused change is named only when it is one readable type 1 change chunk. */
    readonly refused: readonly { readonly change?: string; readonly diagnostic: string }[];
    readonly held: readonly (string | { readonly change: string })[];
    readonly tree: readonly { id: string; parent: string; depth: number; kind: string }[];
    readonly hidden: readonly string[];
    readonly recovery: readonly { id: string; code: string }[];
    readonly retainedConcurrentEdits: readonly string[];
    readonly scalarConflicts: readonly { id: string; field: string; values: readonly string[] }[];
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

const suite = readSectionsCorpus(openSpec()) as Suite;
const resource = resourceId(fromHex(suite.identities.resource_hex));
const principal = (name: string) =>
  principalId(fromHex((suite.identities.actors[name] as { principal_hex: string }).principal_hex));
const bytes = (b: Bytes) => Uint8Array.from(atob(b.base64), (c) => c.charCodeAt(0));
const load = (c: Case) => SectionDocument.fromSave(bytes(c.reference_snapshot));
const heldHash = (h: string | { readonly change: string }) =>
  typeof h === "string" ? h : h.change;

/**
 * The case's admitted changes: all but the refused ones and those held
 * behind them. A refused change the corpus does not name (§14.1: not one
 * readable type 1 change chunk, SS44's compressed one) is never admitted.
 */
function admitted(c: Case): Change[] {
  const out = new Set([
    ...c.expected.refused.flatMap((r) => (r.change === undefined ? [] : [r.change])),
    ...c.expected.held.map(heldHash),
  ]);
  return [...c.base_changes, ...c.branches.A, ...c.branches.B, ...c.after_merge].filter(
    (ch) => !out.has(ch.change_hash) && bytes(ch)[8] === 1,
  );
}

describe("shared sections corpus", () => {
  it("is the profile this module implements, on the pinned engine", () => {
    expect(suite.profile).toBe(SECTIONS_PROFILE_ID);
    expect(suite.cases.length).toBeGreaterThanOrEqual(41);
  });

  it("derives every fixture actor with the section domain (§2)", () => {
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
    // Every change of every case is decoded, SS55's and SS56's 64 large ones
    // included: several seconds on a CI runner.
  }, 30_000);

  for (const c of suite.cases)
    it(
      `${c.id}: schema validation matches the corpus`,
      () =>
        withPending(c.id, () => {
          // SOP §13.1: a Snapshot past the floor is refused by a receiver with
          // floor limits, which then rebuilds from the units (SS56).
          const snapshot = bytes(c.reference_snapshot);
          if (c.expected.snapshot?.within_floor === false)
            expect(() => SectionDocument.fromSave(snapshot)).toThrow(
              expect.objectContaining({
                code: "PROFILE_INVALID",
                diagnostic: "INVALID_AUTOMERGE_BYTES",
              }),
            );
          const doc =
            c.expected.snapshot?.within_floor === false
              ? SectionDocument.fromSave(snapshot, "local-state")
              : SectionDocument.fromSave(snapshot);
          const heads = [...c.expected_heads].sort();
          expect(doc.heads()).toEqual(heads);
          const { document: replayed, unapplied } = SectionDocument.fromChanges(
            admitted(c).map(bytes),
          );
          expect(unapplied).toEqual([]);
          expect(replayed.heads()).toEqual(heads);

          const before = doc.save();
          const v = doc.validate();
          expect(doc.save()).toEqual(before);
          // A PROFILE_INVALID reference snapshot has no valid root (SS65: a
          // section created with ready false is refused, so its base is the
          // genesis alone); every other case's snapshot is a valid section.
          if (c.expected.classification === "PROFILE_INVALID")
            expect(v.problems.length).toBeGreaterThan(0);
          else expect(v.problems).toEqual([]);
          // §14.2: collisions are reported apart; a collided node is not validated.
          expect(v.collisions).toEqual(c.expected.collisions ?? []);
          expect(v.state).toBe(
            c.expected.classification === "IMPORTING"
              ? "importing"
              : c.expected.classification === "PROFILE_INVALID"
                ? "invalid"
                : "ready",
          );
          expect(v.placements.size).toBe(0);
          expect(v.objects.size).toBe(0);
          expect(
            [...v.nodes]
              .map(([id, p]) => ({ id, diagnostic: p.diagnostic }))
              .sort((a, b) => a.id.localeCompare(b.id)),
          ).toEqual(c.expected.invalid);
          expect(replayed.validate()).toEqual(v);

          // §7, §9, §14.3: the effective tree and the structural facts (LFCP-02-014).
          const t = doc.tree();
          expect(t.classification).toBe(c.expected.classification);
          expect(t.tree).toEqual(c.expected.tree);
          expect(t.hidden).toEqual(c.expected.hidden);
          expect(t.recovery).toEqual(c.expected.recovery);
          expect(t.invalid).toEqual(c.expected.invalid);
          expect(t.collisions).toEqual(c.expected.collisions ?? []);
          expect(t.retainedConcurrentEdits).toEqual(c.expected.retainedConcurrentEdits);
          expect(t.scalarConflicts).toEqual(c.expected.scalarConflicts);
          expect(replayed.tree().tree).toEqual(t.tree);

          // §14.1 (LFCP-02-017): every change, injected ones included, received
          // through the production admission. The refused ones and the ones held
          // behind them are the corpus's; the rest reach its heads and tree.
          const all = [...c.base_changes, ...c.branches.A, ...c.branches.B, ...c.after_merge];
          const receiver = SectionReplica.empty({ resource, principal: principal("C") });
          const r = receiver.receiveChanges(
            all.map((ch) => ({
              bytes: bytes(ch),
              ...(ch.signer === undefined ? {} : { signer: principal(ch.signer) }),
            })),
          );
          expect(
            r.refused
              .filter((x) => !x.held)
              // The SDK's own name for each refused change (§14.1), none for an unnamed one.
              .map((x) =>
                x.hash === undefined
                  ? { diagnostic: x.diagnostic }
                  : { change: x.hash, diagnostic: x.diagnostic },
              ),
          ).toEqual(c.expected.refused);
          expect([...r.waiting].sort()).toEqual(c.expected.held.map(heldHash).sort());
          expect(receiver.revision()).toBe(heads.join(","));
          expect(receiver.tree().tree).toEqual(t.tree);
          // SS55 and SS56 replay 64 changes of 8,192 Text operations several ways.
        }),
      30_000,
    );

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
