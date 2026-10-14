// A section's replica keeps one Automerge document (#7): the forks a batch
// is validated and made on are freed explicitly, on every exit (committed,
// staged and dropped after apply, refused, reverted, a failed apply), and a
// failed apply leaves the replica exactly as it was, rebuilt from the
// changes held before the batch with the replica's §2 actor.

import * as Real from "@automerge/automerge";
import { principalId, resourceId, toHex } from "@openlfcp/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTask } from "../src/index.js";
import { type SectionIntent, SectionIntentError, SectionReplica } from "../src/sections/index.js";

const probe = vi.hoisted(() => ({
  clones: new Set<unknown>(),
  freed: new Set<unknown>(),
  failApply: false,
}));

vi.mock("@automerge/automerge", async (importOriginal) => {
  const A = await importOriginal<typeof Real>();
  return {
    ...A,
    clone: (doc: Real.Doc<unknown>, opts?: unknown) => {
      const c = A.clone(doc, opts as never);
      probe.clones.add(c);
      return c;
    },
    // A.change returns the same document under a new proxy: tracked as one.
    change: (doc: Real.Doc<unknown>, ...rest: unknown[]) => {
      const next = (A.change as (...a: unknown[]) => Real.Doc<unknown>)(doc, ...rest);
      if (probe.clones.has(doc)) probe.clones.add(next);
      return next;
    },
    free: (doc: Real.Doc<unknown>) => {
      probe.freed.add(doc);
      A.free(doc);
    },
    applyChanges: (doc: Real.Doc<unknown>, changes: Uint8Array[], ...rest: unknown[]) => {
      if (probe.failApply) {
        probe.failApply = false;
        throw new Error("injected: the engine aborted");
      }
      return (A.applyChanges as (...a: unknown[]) => unknown)(doc, changes, ...rest);
    },
  };
});

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);

/** A replica with `n` Tasks. */
function replica(n: number): SectionReplica {
  const r = SectionReplica.empty({ resource, principal: alice });
  r.commit([{ intent: "section.create", sectionId: SECTION, title: "Plan", createdBy: alice }]);
  for (let i = 0; i < n; i++)
    r.commit([
      {
        intent: "task.create_in_section",
        task: createTask({ id: id(100 + i) as never, title: `t${i}`, createdBy: alice }).task,
        parent: SECTION,
        after: null,
      } as SectionIntent,
    ]);
  return r;
}
const retitle = (i: number, title: string) =>
  [{ intent: "task.set_title", id: id(100 + i) as never, title }] as SectionIntent[];

beforeEach(() => {
  probe.clones.clear();
  probe.freed.clear();
  probe.failApply = false;
});

describe("a section replica frees what it forks", () => {
  it("a commit frees both forks (validation, the batch's changes)", () => {
    const r = replica(5);
    probe.clones.clear();
    probe.freed.clear();
    r.commit(retitle(1, "one"));
    // Two forks (scratch, work), each freed through its last proxy.
    expect(probe.freed.size).toBe(2);
    expect([...probe.freed].every((d) => probe.clones.has(d))).toBe(true);
  });

  it("refused, dropped, reverted, and failed applies free them too", () => {
    const r = replica(5);
    const freedAfter = (f: () => void) => {
      probe.clones.clear();
      probe.freed.clear();
      try {
        f();
      } catch {
        // refused or failed: still freed
      }
      return probe.freed.size;
    };
    // Refused in validation: only the validation's fork was made.
    expect(freedAfter(() => r.commit([{ intent: "node.delete", id: id(9999) }]))).toBe(1);
    // Staged, applied, reverted.
    expect(
      freedAfter(() => {
        const s = r.stage(retitle(2, "two"));
        s?.apply();
        s?.revert();
      }),
    ).toBe(2);
    // A failed apply.
    expect(
      freedAfter(() => {
        const s = r.stage(retitle(3, "three"));
        probe.failApply = true;
        s?.apply();
      }),
    ).toBe(2);
  });

  it("the replica's document stays one: over many commits, nothing it forked stays unfreed", () => {
    const r = replica(20);
    probe.clones.clear();
    probe.freed.clear();
    for (let i = 0; i < 200; i++) r.commit(retitle(i % 20, `x${i}`));
    expect(probe.freed.size).toBe(400);
  });
});

describe("a failed apply leaves the replica as it was", () => {
  it("rebuilt from the changes before the batch, with its §2 actor; then it commits on", () => {
    const r = replica(3);
    const before = { revision: r.revision(), seq: r.actorSeq, changes: r.changes().length };
    const s = r.stage(retitle(0, "lost"));
    if (s === null) throw new Error("no batch");
    probe.failApply = true;
    expect(() => s.apply()).toThrow("injected");
    expect(r.revision()).toBe(before.revision);
    expect(r.actorSeq).toBe(before.seq);
    expect(r.changes().length).toBe(before.changes);
    expect(
      (r.toJSON() as { objects: Record<string, { title: string }> }).objects[id(100)]?.title,
    ).toBe("t0");
    // Applied again: refused, staged again: fine.
    expect(() => s.apply()).toThrow("stage it again");
    const c = r.commit(retitle(0, "kept"));
    expect(c?.parts[0]?.seq).toBe(before.seq + 1);
    // The change is the replica's §2 actor's.
    expect(Real.decodeChange(c?.parts[0]?.change as Uint8Array).actor).toBe(toHex(r.actorId));
  });

  it("revert after apply: the same revision, sequence and changes as before the batch", () => {
    const r = replica(3);
    const before = {
      revision: r.revision(),
      seq: r.actorSeq,
      changes: r.changes().map((c) => toHex(c)),
    };
    const s = r.stage(retitle(1, "undone"));
    s?.apply();
    expect(r.revision()).not.toBe(before.revision);
    s?.revert();
    expect(r.revision()).toBe(before.revision);
    expect(r.actorSeq).toBe(before.seq);
    expect(
      r
        .changes()
        .map((c) => toHex(c))
        .sort(),
    ).toEqual([...before.changes].sort());
    // Applied after the replica changed: refused.
    const t = r.stage(retitle(2, "late"));
    r.commit(retitle(0, "meanwhile"));
    expect(() => t?.apply()).toThrow("stage it again");
  });

  it("a refused batch leaves the replica untouched", () => {
    const r = replica(2);
    const before = r.revision();
    expect(() => r.commit([{ intent: "node.delete", id: id(9999) }])).toThrow(SectionIntentError);
    expect(r.revision()).toBe(before);
  });
});
