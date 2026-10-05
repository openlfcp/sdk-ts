import * as A from "@automerge/automerge";
import {
  type DataUnitId,
  dataUnitId,
  type ObjectId,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  checkChange,
  createTask,
  deriveActorId,
  frameProfilePayload,
  type LocalChange,
  type ObjectChange,
  PROFILE_ID,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  type Task,
} from "../src/index.js";

// The Shared Objects handler alone (no LFCP); the Data Unit path end to end
// is conformance/shared-objects/data-unit-apply.test.ts.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const BOB = principalId(Uint8Array.from({ length: 32 }, (_, i) => 64 + i));
const ID_A = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const ID_B = "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId;
const unit = (n: number): { unitId: DataUnitId } => ({
  unitId: dataUnitId(new Uint8Array(32).fill(n)),
});
const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });

function source() {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const a = replica.apply(
    createTask({ id: ID_A, title: "A", createdBy: ALICE }).intent,
  ) as LocalChange;
  const b = replica.apply(
    createTask({ id: ID_B, title: "B", createdBy: ALICE }).intent,
  ) as LocalChange;
  return { replica, init, a, b };
}

const taskOf = (r: SharedObjectsReplica, id: ObjectId): Task => r.task(id)?.task as Task;

describe("SharedObjectsDataProfile", () => {
  it("decodes only §11 plaintext of the signer's §8 actor (SO-SEC1)", () => {
    const { init } = source();
    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    const alice = profile.codecFor({ resourceId: RESOURCE, actor: ALICE });
    expect(alice.decode(init.plaintext).hash).toBe(init.hash);
    expect(alice.encode(checkChange(init.change))).toEqual(init.plaintext);
    const bob = profile.codecFor({ resourceId: RESOURCE, actor: BOB });
    expect(() => bob.decode(init.plaintext)).toThrow(/SO-SEC1/);
    expect(() => bob.encode(checkChange(init.change))).toThrow(/SO-SEC1/);
    expect(() => alice.decode(frameProfilePayload(Uint8Array.of(1)))).toThrow(
      expect.objectContaining({ code: "PROFILE_FRAMING" }),
    );
  });

  it("buffers a change until its dependencies merge, then merges both", () => {
    const { init, a } = source();
    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    const early = profile.apply(unit(2), checkChange(a.change));
    expect(early.merged).toEqual([]);
    expect(early.pending).toMatch(/waiting/);
    expect(profile.pendingUnits()).toEqual([unit(2).unitId]);
    const r = profile.apply(unit(1), checkChange(init.change));
    expect(r.merged.map(toHex)).toEqual([unit(1).unitId, unit(2).unitId].map(toHex));
    expect(r.objects).toEqual([ID_A]);
    expect(profile.pendingUnits()).toEqual([]);
  });

  it("isolates a profile-invalid object: diagnostics only, the others stay usable (§77)", () => {
    const { replica, init, a, b } = source();
    // Another implementation writes an invalid status into Task A.
    let doc = A.load<Record<string, unknown>>(replica.save(), {
      actor: toHex(deriveActorId(RESOURCE, BOB)),
    });
    doc = A.change(doc, { time: 0 }, (d) => {
      (
        (d.objects as Record<string, Record<string, unknown>>)[ID_A] as Record<string, unknown>
      ).status = new A.ImmutableString("waiting");
    });
    const bad = A.getLastLocalChange(doc) as Uint8Array;

    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    for (const [i, c] of [init, a, b].entries()) profile.apply(unit(i + 1), checkChange(c.change));
    const r = profile.apply(unit(9), checkChange(bad));
    expect(r.merged).toEqual([unit(9).unitId]);
    expect(r.diagnostics).toEqual([
      expect.objectContaining({
        objectId: ID_A,
        code: "PROFILE_INVALID",
        diagnostic: "INVALID_ENUM_VALUE",
        pointer: `/objects/${ID_A}/status`,
      }),
    ]);
    const r2 = profile.replica;
    expect(r2.task(ID_A)?.status).toBe("profile_invalid");
    expect(r2.getObject(ID_A)).toMatchObject({ status: "waiting" }); // the document is preserved
    expect(r2.task(ID_B)?.status).toBe("ready");
    expect(r2.apply(setStatus(taskOf(r2, ID_B), "done").intent)).not.toBeNull();
  });

  // PROVISIONAL (G-EP7)
  it("excludes merged units by rebuilding, re-buffers their dependents and notifies", () => {
    const { init, a, b } = source();
    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    for (const [i, c] of [init, a, b].entries()) profile.apply(unit(i + 1), checkChange(c.change));
    const before = profile.replica;
    const seen: ObjectChange[] = [];
    profile.onObjectChanged((c) => seen.push(c));
    const r = profile.exclude([unit(2).unitId]);
    expect(profile.replica).not.toBe(before);
    expect(profile.replica.objectIds()).toEqual([]);
    // b was written after a in one history, so it builds on a and waits again.
    expect(r.pending).toEqual([unit(3).unitId]);
    expect(profile.pendingUnits()).toEqual([unit(3).unitId]);
    expect(seen.map((c) => [c.objectId, c.origin])).toEqual([
      [ID_A, "rebuild"],
      [ID_B, "rebuild"],
    ]);
    expect(profile.exclude([unit(2).unitId])).toEqual({ objects: [], pending: [] });
    expect(profile.dataProfile).toBe(PROFILE_ID);
  });

  it("checkpoints and restores the replica, its unit refs and the §9 sequence", () => {
    const { init, a, b } = source();
    const profile = new SharedObjectsDataProfile(SharedObjectsReplica.empty(opts(BOB)));
    for (const [i, c] of [init, a, b].entries()) profile.apply(unit(i + 1), checkChange(c.change));
    const local = profile.replica.apply(setStatus(taskOf(profile.replica, ID_B), "done").intent);
    expect(local?.seq).toBe(1);
    const cp = profile.checkpoint();
    expect([cp.dataProfile, cp.actorSeq, cp.units.length]).toEqual([PROFILE_ID, 1, 3]);

    const restored = SharedObjectsDataProfile.restore(cp, opts(BOB));
    expect(restored.replica.root()).toEqual(profile.replica.root());
    expect(restored.replica.writable).toBe(true);
    expect(
      restored.replica.apply(setStatus(taskOf(restored.replica, ID_A), "done").intent)?.seq,
    ).toBe(2);
    // Unit refs survive: G-EP7 can still exclude a unit merged before the checkpoint.
    // Bob's later local writes build on it, so they leave with it (both Tasks change).
    expect(restored.exclude([unit(3).unitId]).objects).toEqual([ID_A, ID_B]);
    expect(restored.replica.objectIds()).toEqual([ID_A]);

    // A checkpoint ahead of its state (a lost write) blocks local writes (§9).
    const ahead = SharedObjectsDataProfile.restore({ ...cp, actorSeq: 5 }, opts(BOB));
    expect(ahead.replica.writable).toBe(false);
    expect(() =>
      SharedObjectsDataProfile.restore(
        { ...cp, units: [{ unitId: unit(9).unitId, ref: "00".repeat(32) }] },
        opts(BOB),
      ),
    ).toThrow(expect.objectContaining({ code: "PROFILE_INVALID" }));
    expect(() => SharedObjectsDataProfile.restore({ ...cp, dataProfile: "x" }, opts(BOB))).toThrow(
      expect.objectContaining({ code: "DATA_PROFILE_MISMATCH" }),
    );
  });
});
