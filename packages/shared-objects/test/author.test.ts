import * as A from "@automerge/automerge";
import { type ObjectId, principalId, resourceId } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import {
  admitBatch,
  admitChange,
  type CheckedChange,
  checkCanonicalChange,
  checkChange,
  type DocumentSequences,
} from "../src/admission/index.js";
import {
  createTask,
  type LocalChange,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "../src/index.js";
import { ACTOR } from "./support/automerge-docs.js";

// SHARED-OBJECTS-PROFILE-01 §14.1 (finding D5): the extra bytes after a
// change's columns are free (§11.3 rule 4), but automerge 0.12 reads an
// author from their start — an unsigned LEB128 1, a length L, then L bytes —
// and asserts the change's sequence number is 1. A receiver detects the
// author (checkCanonicalChange) and refuses, before the engine, a later
// change that carries one, with INVALID_AUTOMERGE_BYTES. SS70 runs the whole
// path against a real authored change in conformance.

/** Shortest-form unsigned LEB128, as the chunk length field is written. */
function uleb(n: number): number[] {
  const out: number[] = [];
  let x = n;
  do {
    let b = x & 0x7f;
    x >>>= 7;
    if (x !== 0) b |= 0x80;
    out.push(b);
  } while (x !== 0);
  return out;
}

/**
 * The change chunk `bytes` with `extra` appended after its columns, its length
 * and checksum recomputed (the method the spec generator uses for SS70). The
 * result is a valid change chunk, so checkChange accepts it and it is refused
 * only by the author rule.
 */
function withExtra(bytes: Uint8Array, extra: number[]): Uint8Array {
  let pos = 9; // magic (4), checksum (4), chunk type (1)
  while ((bytes[pos++] as number) & 0x80); // the chunk length LEB128, any width
  const body = [...bytes.subarray(pos), ...extra];
  const len = uleb(body.length);
  const sum = sha256(Uint8Array.from([1, ...len, ...body])).subarray(0, 4);
  return Uint8Array.from([...bytes.subarray(0, 4), ...sum, 1, ...len, ...body]);
}

/** An Automerge author: count 1, a length, then that many bytes. */
const author = (payload: number): number[] => [
  1,
  ...uleb(payload),
  ...new Array(payload).fill(0xab),
];

const CHANGES = (() => {
  let d: A.Doc<Record<string, unknown>> = A.init({ actor: ACTOR });
  d = A.change(d, (x) => {
    x.a = 1;
  });
  d = A.change(d, (x) => {
    x.b = 2;
  });
  d = A.change(d, (x) => {
    x.c = 3;
  });
  return A.getAllChanges(d);
})();

describe("§14.1 an Automerge author belongs only in the first change (D5)", () => {
  it("detects an author in a change's extra bytes, regardless of its sequence", () => {
    expect(CHANGES).toHaveLength(3);
    for (const bytes of CHANGES) expect(checkCanonicalChange(bytes).beginsWithAuthor).toBe(false);

    const first = checkCanonicalChange(withExtra(CHANGES[0] as Uint8Array, author(5)));
    expect(first.seq).toBe(1);
    expect(first.beginsWithAuthor).toBe(true);

    const third = checkCanonicalChange(withExtra(CHANGES[2] as Uint8Array, author(3)));
    expect(third.seq).toBe(3);
    expect(third.beginsWithAuthor).toBe(true);
  });

  it("free extra bytes that are not an author are not read as one", () => {
    const third = CHANGES[2] as Uint8Array;
    // Count 2 (not 1): automerge does not write an author this way.
    expect(checkCanonicalChange(withExtra(third, [2, 1, 0xab])).beginsWithAuthor).toBe(false);
    // Count 1 but the length runs past the extra bytes.
    expect(checkCanonicalChange(withExtra(third, [1, 9, 0xab])).beginsWithAuthor).toBe(false);
    // Count 1 and a length of zero: an author with an empty blob.
    expect(checkCanonicalChange(withExtra(third, [1, 0])).beginsWithAuthor).toBe(true);
  });

  const checked = (over: Partial<CheckedChange>): CheckedChange =>
    Object.freeze({
      bytes: new Uint8Array(),
      hash: "h",
      actor: ACTOR,
      seq: 1,
      deps: [],
      otherActors: [],
      beginsWithAuthor: false,
      ...over,
    });

  it("refuses a later authored change (admitChange), admits one without an author", () => {
    const doc: DocumentSequences = {
      hasChange: () => false,
      latestSeq: (a) => (a === ACTOR ? 2 : 0),
    };

    const refused = admitChange(checked({ seq: 3, beginsWithAuthor: true, hash: "h3" }), doc);
    expect(refused.kind).toBe("invalid");
    if (refused.kind === "invalid")
      expect(refused.error.diagnostic).toBe("INVALID_AUTOMERGE_BYTES");

    expect(admitChange(checked({ seq: 3, beginsWithAuthor: false, hash: "h3" }), doc).kind).toBe(
      "next",
    );
  });

  it("admits an author in the actor's first change (admitChange)", () => {
    const fresh: DocumentSequences = { hasChange: () => false, latestSeq: () => 0 };
    expect(admitChange(checked({ seq: 1, beginsWithAuthor: true }), fresh).kind).toBe("next");
  });

  it("refuses a later authored change in a batch (admitBatch)", () => {
    const doc: DocumentSequences = {
      hasChange: (h) => h === "h2",
      latestSeq: (a) => (a === ACTOR ? 2 : 0),
    };
    const r = admitBatch(
      [checked({ seq: 3, beginsWithAuthor: true, hash: "h3", deps: ["h2"] })],
      doc,
    );
    expect(r.admitted).toHaveLength(0);
    expect(r.refused).toHaveLength(1);
    expect(r.refused[0]?.change.hash).toBe("h3");
    expect(r.refused[0]?.held).toBe(false);
    expect(r.refused[0]?.error).toMatchObject({
      code: "PROFILE_INVALID",
      diagnostic: "INVALID_AUTOMERGE_BYTES",
    });
  });

  it("leaves the replica intact: after refusing an authored change the honest one applies and converges", () => {
    const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
    const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
    const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
    const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
    const invalidBytes = expect.objectContaining({
      code: "PROFILE_INVALID",
      diagnostic: "INVALID_AUTOMERGE_BYTES",
    });

    // Alice makes three changes: the root (seq 1), the Task (seq 2), a title edit (seq 3).
    const { replica: aliceR, change: init } = SharedObjectsReplica.create({
      resource: RESOURCE,
      principal: ALICE,
    });
    const create = aliceR.apply(
      createTask({ id: ID, title: "Draft", createdBy: ALICE }).intent,
    ) as LocalChange;
    const third = aliceR.apply(
      setTitle(aliceR.task(ID)?.task as Task, "Final").intent,
    ) as LocalChange;
    expect(third.seq).toBe(3);

    // Alice's third change, carrying an author (count 1, length 2, two bytes).
    const authored = withExtra(third.change, author(2));
    const parsed = checkChange(authored);
    expect(parsed.seq).toBe(3);
    expect(parsed.beginsWithAuthor).toBe(true);

    // Carol holds Alice's first two changes.
    const carol = SharedObjectsReplica.fromChanges([init.change, create.change], {
      resource: RESOURCE,
      principal: CAROL,
    }).replica;
    const before = JSON.stringify(carol.root());

    // The authored third change is refused before the engine, on both receive paths.
    expect(() => carol.receiveChange(authored)).toThrow(invalidBytes);
    const batch = carol.receiveChanges([authored]);
    expect(batch.applied).toHaveLength(0);
    expect(batch.refused.map((r) => r.error)).toEqual([invalidBytes]);
    // The engine never saw it: the document is unchanged.
    expect(JSON.stringify(carol.root())).toBe(before);

    // The honest third change still applies, and Carol converges with Alice.
    const ok = carol.receiveChanges([third.change]);
    expect(ok.applied).toHaveLength(1);
    expect(carol.task(ID)?.task?.title).toBe("Final");
    const reference = SharedObjectsReplica.fromChanges([init.change, create.change, third.change], {
      resource: RESOURCE,
      principal: ALICE,
    }).replica;
    expect(JSON.stringify(carol.root())).toBe(JSON.stringify(reference.root()));

    // The replica is still fully usable: a local write goes through and saves loadably.
    carol.apply(setTitle(carol.task(ID)?.task as Task, "Carol").intent);
    expect(
      SharedObjectsReplica.fromSave(carol.save(), { resource: RESOURCE, principal: CAROL }).task(ID)
        ?.task?.title,
    ).toBe("Carol");
  });
});
