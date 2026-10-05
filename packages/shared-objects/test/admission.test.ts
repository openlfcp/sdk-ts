import * as A from "@automerge/automerge";
import { type ObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import { deflateSync } from "fflate";
import { describe, expect, it } from "vitest";
import {
  createTask,
  deriveActorId,
  frameSnapshot,
  type LocalChange,
  SharedObjectsReplica,
  SNAPSHOT_LIMITS_FLOOR,
  setTitle,
  type Task,
} from "../src/index.js";

// SHARED-OBJECTS-PROFILE-01 §11.1, §13.1 and §30 (SPEC-PATCH-07) through the
// replica: what is refused before the Automerge engine, the writer's own
// limit. Synthetic values only.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
const STRANGER = "cc".repeat(32);
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });
const aliceActor = () => toHex(deriveActorId(RESOURCE, ALICE));

const invalidBytes = expect.objectContaining({
  code: "PROFILE_INVALID",
  diagnostic: "INVALID_AUTOMERGE_BYTES",
});

function alice() {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const create = replica.apply(
    createTask({ id: ID, title: "Draft", createdBy: ALICE }).intent,
  ) as LocalChange;
  return { replica, init, create };
}

/** Alice's next change re-encoded with `mutate` applied to its decoded form. */
function forged(
  replica: SharedObjectsReplica,
  mutate: (c: A.DecodedChange) => A.DecodedChange,
): Uint8Array {
  const fork = SharedObjectsReplica.fromChanges(replica.changes(), opts()).replica;
  const next = fork.apply(setTitle(fork.task(ID)?.task as Task, "Next").intent) as LocalChange;
  const { hash: _, ...decoded } = mutate(A.decodeChange(next.change));
  return A.encodeChange(decoded as never);
}

describe("receive: refused before the engine (§11.1)", () => {
  it("refuses a change that names an actor the document does not know, on both paths", () => {
    const a = alice();
    const carol = SharedObjectsReplica.fromChanges(
      [a.init.change, a.create.change],
      opts(CAROL),
    ).replica;
    const before = JSON.stringify(carol.root());
    const bad = forged(a.replica, (c) => ({
      ...c,
      ops: c.ops.map((o) => ({ ...o, pred: [...o.pred, `1@${STRANGER}`] })),
    }));
    expect(() => carol.receiveChange(bad)).toThrow(invalidBytes);
    const batch = carol.receiveChanges([bad]);
    expect(batch.refused.map((r) => r.error)).toEqual([invalidBytes]);
    expect(JSON.stringify(carol.root())).toBe(before);
    // The document is still usable and saves loadably.
    carol.apply(setTitle(carol.task(ID)?.task as Task, "Carol").intent);
    expect(SharedObjectsReplica.fromSave(carol.save(), opts(CAROL)).task(ID)?.task?.title).toBe(
      "Carol",
    );
  });

  it("refuses the measured bombs fast through the public receive path (memory: conformance)", () => {
    const a = alice();
    const bomb = forged(a.replica, (c) => ({
      ...c,
      ops: Array.from({ length: 1_000_000 }, () => ({
        action: "set",
        obj: "_root",
        key: "k",
        value: null,
        pred: [],
      })) as never,
    }));
    expect(bomb.length).toBeLessThan(300);
    const compressed = Uint8Array.from(a.create.change);
    compressed[8] = 2;
    const t = performance.now();
    expect(() => a.replica.receiveChange(bomb)).toThrow(invalidBytes);
    expect(() => a.replica.receiveChange(compressed)).toThrow(invalidBytes);
    expect(performance.now() - t).toBeLessThan(100);
  });
});

describe("the writer's own limit (§11.1)", () => {
  it("refuses an intent over the change limits with a clear error, and keeps working", () => {
    const a = alice();
    const tags = Array.from({ length: 20_000 }, (_, i) => `t${i}`);
    expect(() =>
      a.replica.apply(createTask({ title: "Bulk", createdBy: ALICE, tags }).intent),
    ).toThrow(expect.objectContaining({ code: "CHANGE_TOO_LARGE" }));
    expect(a.replica.objectIds()).toEqual([ID]);
    const next = a.replica.apply(
      setTitle(a.replica.task(ID)?.task as Task, "After").intent,
    ) as LocalChange;
    expect(next.seq).toBe(3);
    expect(a.replica.task(ID)?.task?.title).toBe("After");
    // A transaction at a size the profile allows still goes through.
    const fine = Array.from({ length: 1_000 }, (_, i) => `f${i}`);
    expect(
      a.replica.apply(createTask({ title: "Many tags", createdBy: ALICE, tags: fine }).intent),
    ).not.toBeNull();
  });
});

describe("Snapshots (§13.1)", () => {
  it("refuses a save over the floor before loading it, but restores local state of any size", () => {
    const data = deflateSync(new Uint8Array(SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes + 1));
    const leb = (n: number) => {
      const out: number[] = [];
      do {
        let b = n & 0x7f;
        n = Math.floor(n / 128);
        if (n > 0) b |= 0x80;
        out.push(b);
      } while (n > 0);
      return out;
    };
    const body = [0, 0, 0, 1, ...leb((5 << 4) | 0x08 | 7), ...leb(data.length), ...data];
    const save = Uint8Array.from([
      0x85,
      0x6f,
      0x4a,
      0x83,
      0,
      0,
      0,
      0,
      0,
      ...leb(body.length),
      ...body,
    ]);
    expect(() => SharedObjectsReplica.fromSnapshot(frameSnapshot(save), opts())).toThrow(
      invalidBytes,
    );
    expect(() => alice().replica.mergeSave(save)).toThrow(invalidBytes);
    // Local persisted state is this device's own: not limited.
    const a = alice();
    expect(
      SharedObjectsReplica.fromSave(a.replica.save(), opts(), "local-state").objectIds(),
    ).toEqual([ID]);
  });
});
