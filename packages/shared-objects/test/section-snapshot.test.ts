// Section Snapshots and restart continuation (LFCP-02-028): a Snapshot is
// admitted change by change (SHARED-SECTIONS-PROFILE-01 §14.1), loaded
// under local work, continued with the exact units after it; the actor
// continues from a full Snapshot (SS12, SS28).

import * as A from "@automerge/automerge";
import { type DataUnitId, dataUnitId, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { type CheckedChange, checkChange } from "../src/admission/index.js";
import {
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const bob = principalId(new Uint8Array(32).fill(2));
const carol = principalId(new Uint8Array(32).fill(3));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
let unitSeq = 0;
const unit = (): { unitId: DataUnitId } => {
  unitSeq += 1;
  const b = new Uint8Array(32);
  new DataView(b.buffer).setUint32(0, unitSeq);
  return { unitId: dataUnitId(b) };
};
const item = (n: number, text: string, by = alice): SectionIntent => ({
  intent: "item.create",
  id: id(n),
  parent: SECTION,
  after: null,
  text,
  createdBy: by,
});

/**
 * A history with concurrency: Alice creates the section and two items,
 * Bob and Alice then edit the title concurrently and add items. Returns
 * every change in causal order.
 */
function history(): CheckedChange[] {
  const a = SectionReplica.empty({ resource, principal: alice });
  const out: CheckedChange[] = [];
  const commit = (r: SectionReplica, intents: SectionIntent[]) => {
    const c = r.commit(intents);
    for (const p of c?.parts ?? []) out.push(checkChange(p.change));
  };
  commit(a, [{ intent: "section.create", sectionId: SECTION, title: "S", createdBy: alice }]);
  commit(a, [item(10, "one")]);
  commit(a, [item(11, "two")]);
  const b = SectionReplica.empty({ resource, principal: bob });
  b.receiveChanges(out.map((c) => c.bytes));
  commit(a, [{ intent: "section.set_title", title: "Alice's" }]);
  commit(b, [{ intent: "section.set_title", title: "Bob's" }, item(12, "three", bob)]);
  a.receiveChanges(out.map((c) => c.bytes));
  commit(a, [item(13, "four")]);
  return out;
}

const profileOf = (principal = carol) =>
  new SharedSectionsDataProfile(SectionReplica.empty({ resource, principal }));

/** The save of the document holding exactly `changes`. */
const saveOf = (changes: readonly CheckedChange[]) =>
  SectionReplica.fromChanges(
    changes.map((c) => c.bytes),
    { resource, principal: carol },
  ).replica.save();

describe("section Snapshots (LFCP-02-028)", () => {
  it("loads a Snapshot, then the units after it, to the state of a full replay (SS12)", () => {
    const all = history();
    const full = profileOf();
    for (const c of all) full.apply(unit(), c);
    for (const cut of [1, 3, 5, all.length]) {
      const p = profileOf();
      p.loadSnapshot(saveOf(all.slice(0, cut)));
      for (const c of all.slice(cut)) p.apply(unit(), c);
      expect(p.replica.snapshot()).toEqual(full.replica.snapshot());
      expect(p.replica.snapshot().title.conflicts).toEqual(["Alice's", "Bob's"]);
    }
  });

  it("accepts the units a Snapshot already holds as duplicates", () => {
    const all = history();
    const p = profileOf();
    p.loadSnapshot(saveOf(all));
    const before = p.replica.revision();
    for (const c of all) expect(p.apply(unit(), c).pending).toBeUndefined();
    expect(p.replica.revision()).toBe(before);
  });

  it("keeps a tail unit waiting until the unit it depends on arrives", () => {
    const all = history();
    const p = profileOf();
    p.loadSnapshot(saveOf(all.slice(0, 3)));
    const last = all.at(-1) as CheckedChange;
    const waiting = unit();
    expect(p.apply(waiting, last).pending).toBeDefined();
    expect(p.replica.snapshot().nodes[id(13)]).toBeUndefined();
    for (const c of all.slice(3, -1)) p.apply(unit(), c);
    expect(p.pendingUnits()).toEqual([]);
    expect(p.replica.snapshot().nodes[id(13)]?.text).toBe("four");
  });

  it("keeps local work the Snapshot lacks", () => {
    const all = history();
    const base = SectionReplica.empty({ resource, principal: carol });
    base.receiveChanges(all.slice(0, 3).map((c) => c.bytes));
    const p = new SharedSectionsDataProfile(base);
    p.replica.commit([item(20, "local", carol)]);
    p.loadSnapshot(saveOf(all));
    expect(p.replica.snapshot().nodes[id(20)]?.text).toBe("local");
    expect(p.replica.snapshot().nodes[id(13)]?.text).toBe("four");
  });

  it("rejects a Snapshot holding a change admission refuses, and changes nothing", () => {
    const all = history();
    // A change that deletes from section.children (A1), made beside the profile.
    let doc = A.load<Record<string, unknown>>(saveOf(all.slice(0, 3)), {
      actor: "aa".repeat(16),
    });
    doc = A.change(doc, (d) => {
      (d.section as { children: unknown[] }).children.splice(0, 1);
    });
    const p = profileOf();
    p.loadSnapshot(saveOf(all.slice(0, 2)));
    const before = p.replica.revision();
    expect(() => p.loadSnapshot(A.save(doc))).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHILDREN_LIST_MUTATED" }),
    );
    expect(p.replica.revision()).toBe(before);
  });

  it("continues the actor from a full Snapshot of its own history (SS28)", () => {
    const all = history();
    // Alice lost her local state: a new device of hers loads a full Snapshot.
    const p = profileOf(alice);
    p.loadSnapshot(saveOf(all));
    const seq = p.replica.actorSeq;
    expect(seq).toBeGreaterThan(0);
    expect(p.replica.writable).toBe(true);
    const next = p.replica.commit([item(30, "after", alice)]);
    const c = checkChange(next?.parts[0]?.change as Uint8Array);
    expect(c.seq).toBe(seq + 1);
    // Another replica admits it after the same history: no sequence reused.
    const other = SectionReplica.empty({ resource, principal: bob });
    other.receiveChanges(all.map((x) => x.bytes));
    expect(other.receiveChanges([c.bytes]).refused).toEqual([]);
    expect(other.snapshot().nodes[id(30)]?.text).toBe("after");
  });

  it("publishes its state through the Snapshot codec, which loads to the same state", () => {
    const all = history();
    const p = profileOf();
    for (const c of all) p.apply(unit(), c);
    const binding = p.snapshotBinding();
    const plaintext = binding.codec.encode(binding.current());
    const q = profileOf(bob);
    q.snapshotBinding().load(q.snapshotCodec().decode(plaintext));
    expect(q.replica.snapshot()).toEqual(p.replica.snapshot());
  });
});
