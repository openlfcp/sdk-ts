import * as A from "@automerge/automerge";
import { LfcpError, type ObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  addTag,
  assign,
  cancel,
  checkChange,
  clearDue,
  complete,
  createTask,
  deleteTask,
  deriveActorId,
  frameChange,
  frameProfilePayload,
  frameSnapshot,
  type LocalChange,
  ObjectIdCollisionError,
  PROFILE_ID,
  ProfileError,
  principalRef,
  type SharedObjectsReplica as Replica,
  removeTag,
  reopen,
  resolveFieldConflict,
  restoreTask,
  SharedObjectsReplica,
  setDue,
  setStatus,
  setTitle,
  type Task,
  unassign,
  unframeChange,
  unframeSnapshot,
} from "../src/index.js";

// Synthetic values only; the published vectors and the reference Automerge
// corpus run in the conformance runner.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const BOB = principalId(Uint8Array.from({ length: 32 }, (_, i) => 64 + i));
const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const OTHER_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId;

const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });

/** Alice's new Resource with one Task. */
function aliceWithTask(extra: Partial<Parameters<typeof createTask>[0]> = {}) {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const { intent } = createTask({
    id: ID,
    title: "Prepare API contract",
    createdBy: ALICE,
    ...extra,
  });
  const create = replica.apply(intent) as LocalChange;
  return { replica, init, create };
}

/** A replica of `principal` holding exactly `source`'s changes. */
const fork = (source: Replica, principal: typeof ALICE): Replica =>
  SharedObjectsReplica.fromChanges(source.changes(), opts(principal)).replica;

const taskOf = (r: Replica): Task => {
  const task = r.task(ID)?.task;
  if (task === undefined) throw new Error("no valid Task");
  return task;
};

/** Exchanges every change both ways. */
function sync(...replicas: Replica[]): void {
  for (const to of replicas)
    for (const from of replicas)
      if (to !== from) for (const c of from.changes()) to.receiveChange(c);
}

const fieldValues = (r: Replica, field: Parameters<typeof resolveFieldConflict>[1]) =>
  r.task(ID)?.fields[field].values;

describe("actor and root", () => {
  it("writes as the §8 actor of (Resource, Principal), sequence by sequence", () => {
    const { replica, init, create } = aliceWithTask();
    expect(replica.actorId).toEqual(deriveActorId(RESOURCE, ALICE));
    expect(checkChange(init.change).actor).toBe(toHex(deriveActorId(RESOURCE, ALICE)));
    expect([init.seq, create.seq]).toEqual([1, 2]);
    expect(replica.actorSeq).toBe(2);
  });

  it("initializes the root in one change with scalar strings (§16, G-SC3)", () => {
    const { replica, change } = SharedObjectsReplica.create(opts());
    expect(replica.root()).toEqual({ profile: PROFILE_ID, objects: {}, extensions: {} });
    expect(replica.changes()).toHaveLength(1);
    const decoded = A.decodeChange(change.change);
    expect([decoded.message, decoded.time]).toEqual(["profile.init", 0]);
    expect(replica.validate().valid).toBe(true);
  });

  it("refuses intents before the root exists", () => {
    const empty = SharedObjectsReplica.empty(opts());
    expect(() => empty.apply(createTask({ id: ID, title: "x", createdBy: ALICE }).intent)).toThrow(
      ProfileError,
    );
  });
});

describe("intents", () => {
  it("creates the whole Task in one change named after the intent (§53)", () => {
    const { replica, create } = aliceWithTask({ tags: ["backend"] });
    expect(replica.changes()).toHaveLength(2);
    expect(A.decodeChange(create.change).message).toBe("task.create");
    expect(replica.getObject(ID)).toMatchObject({
      id: ID,
      title: "Prepare API contract",
      status: "todo",
    });
    expect(replica.task(ID)?.status).toBe("ready");
    expect(replica.task(ID)?.tags).toEqual(["backend"]);
    expect(create.objects).toEqual([
      expect.objectContaining({ objectId: ID, objectType: "task", origin: "local" }),
    ]);
  });

  it("sets the title and status as single changes", () => {
    const { replica } = aliceWithTask();
    const t = replica.apply(setTitle(taskOf(replica), "Final").intent) as LocalChange;
    const s = replica.apply(setStatus(taskOf(replica), "in_progress").intent) as LocalChange;
    expect([t.seq, s.seq]).toEqual([3, 4]);
    expect(t.objects[0]?.fields).toEqual(["title"]);
    expect(taskOf(replica)).toMatchObject({ title: "Final", status: "in_progress" });
  });

  it("completes atomically: status and completion date in one change (§63)", () => {
    const { replica } = aliceWithTask();
    const done = replica.apply(complete(taskOf(replica), "2026-10-08").intent) as LocalChange;
    expect(done.objects[0]?.fields).toEqual(["completion_date", "status"]);
    expect(replica.changes()).toHaveLength(3);
    replica.apply(reopen(taskOf(replica)).intent);
    expect(taskOf(replica).status).toBe("todo");
    expect("completion_date" in taskOf(replica)).toBe(false);
  });

  it("returns null for an intent that changes nothing", () => {
    const { replica } = aliceWithTask();
    expect(replica.apply(clearDue(taskOf(replica)).intent)).toBeNull();
    expect(replica.apply(removeTag(taskOf(replica), "absent").intent)).toBeNull();
    expect(replica.changes()).toHaveLength(2);
  });

  it("validates before writing and refuses unknown objects and collisions", () => {
    const { replica } = aliceWithTask();
    const bad = { intent: "task.set_status", id: ID, status: "waiting" } as const;
    expect(() => replica.apply(bad as never)).toThrow(ProfileError);
    expect(() => replica.apply({ intent: "task.restore", id: OTHER_ID })).toThrow(ProfileError);
    expect(() =>
      replica.apply(createTask({ id: ID, title: "again", createdBy: ALICE }).intent),
    ).toThrow(ObjectIdCollisionError);
    expect(replica.changes()).toHaveLength(2);
  });

  it("writes an unchanged value as a real change (G-SC4)", () => {
    const { replica } = aliceWithTask();
    const again = replica.apply(restoreTask(taskOf(replica)).intent);
    expect(again).not.toBeNull();
    expect(taskOf(replica).lifecycle).toBe("active");
  });
});

describe("concurrency", () => {
  it("merges independent fields without conflict (§49)", () => {
    const { replica: a } = aliceWithTask();
    const b = fork(a, BOB);
    a.apply(complete(taskOf(a), "2026-10-08").intent);
    b.apply(setTitle(taskOf(b), "Prepare final API contract").intent);
    sync(a, b);
    expect(taskOf(a)).toMatchObject({ status: "done", title: "Prepare final API contract" });
    expect(a.conflicts()).toEqual({});
    expect(a.root()).toEqual(b.root());
  });

  it("keeps done vs cancelled conflicted and resolves it causally (§47, §48, §69)", () => {
    const { replica: a } = aliceWithTask();
    const b = fork(a, BOB);
    a.apply(complete(taskOf(a), "2026-10-08").intent);
    const cancelled = b.apply(cancel(taskOf(b)).intent) as LocalChange;
    const received = a.receive(cancelled.plaintext);
    expect(received.status).toBe("applied");
    if (received.status === "applied")
      expect(received.objects[0]).toMatchObject({
        conflictsAppeared: ["status"],
        origin: "remote",
      });
    expect(a.conflicts()).toEqual({ [ID]: { status: ["cancelled", "done"] } });
    expect(a.task(ID)?.fields.status).toMatchObject({
      conflicted: true,
      values: ["cancelled", "done"],
    });

    const c = fork(a, CAROL);
    const resolved = c.apply(resolveFieldConflict(ID, "status", "done")) as LocalChange;
    expect(resolved.objects[0]?.conflictsDisappeared).toEqual(["status"]);
    a.receive(resolved.plaintext);
    sync(a, b); // b gets Alice's completion and Carol's resolution
    for (const r of [a, b, c]) {
      expect(r.conflicts()).toEqual({});
      expect(fieldValues(r, "status")).toEqual(["done"]);
    }
  });

  it("resolves a conflict onto the visible value (G-SC4) and clears a date conflict with null", () => {
    const { replica: a } = aliceWithTask();
    const b = fork(a, BOB);
    a.apply(setDue(taskOf(a), "2026-10-10").intent);
    b.apply(setDue(taskOf(b), "2026-10-12").intent);
    sync(a, b);
    expect(fieldValues(a, "due")).toEqual(["2026-10-10", "2026-10-12"]);
    const visible = a.task(ID)?.fields.due.value as string;
    a.apply(resolveFieldConflict(ID, "due", visible));
    expect(fieldValues(a, "due")).toEqual([visible]);
    sync(a, b);
    a.apply(resolveFieldConflict(ID, "due", null));
    expect(fieldValues(a, "due")).toEqual([]);
    expect(() => resolveFieldConflict(ID, "title", null)).toThrow(LfcpError);
  });

  it("unions concurrent tag additions and lets a concurrent re-add win over removal (§41)", () => {
    const { replica: a } = aliceWithTask({ tags: ["backend"] });
    const b = fork(a, BOB);
    a.apply(addTag(taskOf(a), "urgent").intent);
    b.apply(addTag(taskOf(b), "docs").intent);
    sync(a, b);
    expect(a.task(ID)?.tags).toEqual(["backend", "docs", "urgent"]);
    a.apply(removeTag(taskOf(a), "backend").intent);
    b.apply(addTag(taskOf(b), "backend").intent);
    sync(a, b);
    expect(a.task(ID)?.tags).toEqual(["backend", "docs", "urgent"]);
    expect(b.root()).toEqual(a.root());
  });

  it("lets a concurrent assignment win over unassignment (§43)", () => {
    const { replica: a } = aliceWithTask({ assignees: [BOB] });
    const c = fork(a, CAROL);
    a.apply(unassign(taskOf(a), BOB).intent);
    c.apply(assign(taskOf(c), BOB).intent);
    sync(a, c);
    expect(a.task(ID)?.assignees).toEqual([principalRef(BOB)]);
  });

  it("keeps a concurrent edit under the tombstone and reveals it on restore (§51, §110)", () => {
    const { replica: a } = aliceWithTask();
    const b = fork(a, BOB);
    a.apply(deleteTask(taskOf(a)).intent);
    b.apply(setTitle(taskOf(b), "Final API contract").intent);
    sync(a, b);
    expect(taskOf(a)).toMatchObject({ lifecycle: "deleted", title: "Final API contract" });
    expect(a.objectIds()).toEqual([ID]);
    a.apply(restoreTask(taskOf(a)).intent);
    expect(taskOf(a)).toMatchObject({ lifecycle: "active", title: "Final API contract" });
  });

  it("conflicts delete against restore (§52)", () => {
    const { replica: a } = aliceWithTask();
    const b = fork(a, BOB);
    a.apply(deleteTask(taskOf(a)).intent);
    b.apply(restoreTask(taskOf(b)).intent);
    sync(a, b);
    expect(a.conflicts()).toEqual({ [ID]: { lifecycle: ["active", "deleted"] } });
  });

  it("reports concurrent creations under one Object ID as OBJECT_ID_COLLISION (§21)", () => {
    const { replica: a } = SharedObjectsReplica.create(opts());
    const b = fork(a, BOB);
    a.apply(createTask({ id: ID, title: "A", createdBy: ALICE }).intent);
    b.apply(createTask({ id: ID, title: "B", createdBy: BOB }).intent);
    sync(a, b);
    expect(a.collisions()).toEqual([ID]);
    expect(a.validate().collisions).toEqual([ID]);
    expect(a.task(ID)?.status).toBe("object_id_collision");
    expect(() => a.apply({ intent: "task.delete", id: ID })).toThrow(ObjectIdCollisionError);
  });
});

describe("unknown data (§70-§72)", () => {
  /** A replica whose Task carries an unknown field and extension, plus an unknown object type, written by another client. */
  function withUnknowns(): Replica {
    const { replica } = aliceWithTask();
    let doc = A.load<Record<string, unknown>>(replica.save(), { actor: "ee".repeat(32) });
    doc = A.change(doc, { time: 0 }, (d) => {
      const objects = d.objects as Record<string, Record<string, unknown>>;
      const task = objects[ID] as Record<string, unknown>;
      task.x_future_scalar = new A.ImmutableString("future-value");
      (task.extensions as Record<string, unknown>)["com.example.tracker"] = {
        ticket: new A.ImmutableString("ABC-42"),
      };
      objects[OTHER_ID] = {
        id: new A.ImmutableString(OTHER_ID),
        type: new A.ImmutableString("com.example.poll"),
        lifecycle: new A.ImmutableString("active"),
        created_by: new A.ImmutableString(principalRef(BOB)),
        extensions: {},
        answers: { yes: 1 },
      };
      (d.extensions as Record<string, unknown>)["com.example.root"] = { on: true };
    });
    return SharedObjectsReplica.fromSave(A.save(doc), opts());
  }

  it("keeps unknown fields, extensions and object types across known-field writes", () => {
    const r = withUnknowns();
    const before = r.root() as Record<string, Record<string, Record<string, unknown>>>;
    r.apply(setStatus(taskOf(r), "in_progress").intent);
    r.apply(addTag(taskOf(r), "x").intent);
    const after = r.root() as typeof before;
    expect(after.objects?.[ID]).toMatchObject({
      x_future_scalar: "future-value",
      extensions: { "com.example.tracker": { ticket: "ABC-42" } },
      status: "in_progress",
    });
    expect(after.objects?.[OTHER_ID]).toEqual(before.objects?.[OTHER_ID]);
    expect(after.extensions).toEqual(before.extensions);
    expect(r.task(OTHER_ID)).toBeUndefined();
    expect(r.validate().valid).toBe(true);
  });
});

describe("collaborative Text is not a profile string (G-SC3)", () => {
  it("reports a Text title as INVALID_FIELD_TYPE and refuses other writes until repaired", () => {
    const { replica } = aliceWithTask();
    let doc = A.load<Record<string, unknown>>(replica.save(), { actor: "ee".repeat(32) });
    doc = A.change(doc, { time: 0 }, (d) => {
      (
        (d.objects as Record<string, Record<string, unknown>>)[ID] as Record<string, unknown>
      ).title = "a Text title";
    });
    const r = SharedObjectsReplica.fromSave(A.save(doc), opts());
    expect(r.validate().problems).toEqual([
      expect.objectContaining({
        diagnostic: "INVALID_FIELD_TYPE",
        pointer: `/objects/${ID}/title`,
      }),
    ]);
    expect(r.task(ID)?.status).toBe("profile_invalid");
    expect(() => r.apply({ intent: "task.set_status", id: ID, status: "done" })).toThrow(
      ProfileError,
    );
    r.apply({ intent: "task.set_title", id: ID, title: "a scalar title" });
    expect(r.validate().valid).toBe(true);
  });
});

describe("one diagnostic per field, in §74.1 table order (SOG-2)", () => {
  const write = (save: Uint8Array, actor: string, status: unknown) =>
    A.change(A.load<Record<string, unknown>>(save, { actor }), { time: 0 }, (d) => {
      (
        (d.objects as Record<string, Record<string, unknown>>)[ID] as Record<string, unknown>
      ).status = status;
    });
  const problemsOf = (r: SharedObjectsReplica) =>
    r.validate().problems.map((p) => `${p.diagnostic} ${p.pointer}`);

  it("a Text value that is also not a status is INVALID_FIELD_TYPE only", () => {
    const { replica } = aliceWithTask();
    const r = SharedObjectsReplica.fromSave(
      A.save(write(replica.save(), "ee".repeat(32), "bogus")),
      opts(),
    );
    expect(problemsOf(r)).toEqual([`INVALID_FIELD_TYPE /objects/${ID}/status`]);
    expect(r.task(ID)?.status).toBe("profile_invalid");
  });

  it("a conflicted field gets the first diagnostic over all its values (§45)", () => {
    const { replica } = aliceWithTask();
    const save = replica.save();
    const number = write(save, "ee".repeat(32), 42); // INVALID_ENUM_VALUE
    const text = write(save, "ff".repeat(32), "done"); // INVALID_FIELD_TYPE
    const r = SharedObjectsReplica.fromSave(A.save(A.merge(number, text)), opts());
    expect(r.task(ID)?.fields.status?.conflicted).toBe(true);
    expect(problemsOf(r)).toEqual([`INVALID_FIELD_TYPE /objects/${ID}/status`]);
  });
});

describe("profile framing (§11, §13)", () => {
  it("frames one change exactly as [1, change] and reads it back", () => {
    const { create } = aliceWithTask();
    expect(create.plaintext).toEqual(frameProfilePayload(create.change));
    expect(frameChange(create.change)).toEqual(create.plaintext);
    expect(unframeChange(create.plaintext).hash).toBe(create.hash);
  });

  it("rejects invalid change plaintexts with PROFILE_FRAMING", () => {
    const { replica, init, create } = aliceWithTask();
    const code = (f: () => unknown) => {
      try {
        f();
      } catch (e) {
        return (e as LfcpError).code;
      }
      return "accepted";
    };
    const flipped = Uint8Array.from(create.change);
    flipped[5] = (flipped[5] as number) ^ 1; // a checksum byte: Automerge JS alone accepts it
    const cases: Record<string, Uint8Array> = {
      "not CBOR": Uint8Array.of(0xff),
      "framing version 2": Uint8Array.of(0x82, 0x02, 0x40),
      "three elements": Uint8Array.of(0x83, 0x01, 0x40, 0x40),
      "not Automerge": frameProfilePayload(Uint8Array.of(1, 2, 3)),
      "two concatenated changes": frameProfilePayload(
        Uint8Array.from([...init.change, ...create.change]),
      ),
      "a full save": frameProfilePayload(replica.save()),
      "a bad checksum": frameProfilePayload(flipped),
    };
    for (const [what, plaintext] of Object.entries(cases))
      expect([what, code(() => unframeChange(plaintext))]).toEqual([what, "PROFILE_FRAMING"]);
    expect(
      code(() =>
        SharedObjectsReplica.empty(opts(BOB)).receive(cases["a bad checksum"] as Uint8Array),
      ),
    ).toBe("PROFILE_FRAMING");
  });

  it("round-trips a Snapshot and accepts later changes (§13, §14)", () => {
    const { replica: a } = aliceWithTask();
    const plaintext = a.snapshot();
    expect(plaintext).toEqual(frameSnapshot(a.save()));
    const b = SharedObjectsReplica.fromSnapshot(plaintext, opts(BOB));
    expect(b.root()).toEqual(a.root());
    const later = a.apply(setStatus(taskOf(a), "in_progress").intent) as LocalChange;
    expect(b.receive(later.plaintext).status).toBe("applied");
    expect(taskOf(b).status).toBe("in_progress");
    const own = b.apply(setTitle(taskOf(b), "after snapshot").intent) as LocalChange;
    expect(a.receive(own.plaintext).status).toBe("applied");
    expect(a.root()).toEqual(b.root());
  });

  it("rejects a Snapshot that is not a full save", () => {
    const { create } = aliceWithTask();
    expect(() => unframeSnapshot(frameProfilePayload(create.change))).toThrow(/document/);
    expect(() => SharedObjectsReplica.fromSave(Uint8Array.of(1, 2, 3), opts())).toThrow(LfcpError);
  });
});

describe("receiving", () => {
  it("reports duplicates and missing dependencies without applying", () => {
    const { replica: a, init, create } = aliceWithTask();
    const b = SharedObjectsReplica.empty(opts(BOB));
    const early = b.receive(create.plaintext);
    expect(early).toMatchObject({ status: "missing_dependencies", missing: [init.hash] });
    expect(b.changes()).toHaveLength(0);
    expect(b.receive(init.plaintext).status).toBe("applied");
    expect(b.receive(create.plaintext).status).toBe("applied");
    expect(b.receive(create.plaintext).status).toBe("duplicate");
    expect(b.root()).toEqual(a.root());
  });

  it("rejects a second change under one actor sequence as ACTOR_EQUIVOCATION and stays usable", () => {
    const { replica: a } = aliceWithTask();
    const lost = SharedObjectsReplica.fromChanges(a.changes(), opts()).replica;
    const one = a.apply(setTitle(taskOf(a), "one").intent) as LocalChange;
    const two = lost.apply(setTitle(taskOf(lost), "two").intent) as LocalChange;
    expect(two.seq).toBe(one.seq);
    expect(() => a.receive(two.plaintext)).toThrow(
      expect.objectContaining({ code: "ACTOR_EQUIVOCATION" }),
    );
    expect(taskOf(a).title).toBe("one");
    expect(a.apply(setTitle(taskOf(a), "three").intent)?.seq).toBe(4);
  });
});

describe("actor state safety (§9)", () => {
  it("refuses local writes when the state is behind the persisted sequence", () => {
    const { replica: a } = aliceWithTask();
    const stale = SharedObjectsReplica.fromChanges(a.changes().slice(0, 1), {
      ...opts(),
      minSeq: 2,
    }).replica;
    expect(stale.writable).toBe(false);
    expect(() =>
      stale.apply(createTask({ id: OTHER_ID, title: "x", createdBy: ALICE }).intent),
    ).toThrow(expect.objectContaining({ code: "SEQUENCE_REUSE" }));
    const resumed = SharedObjectsReplica.fromSave(a.save(), { ...opts(), minSeq: 2 });
    expect(resumed.writable).toBe(true);
    expect(resumed.apply(setTitle(taskOf(resumed), "continued").intent)?.seq).toBe(3);
  });
});

// §14.1 (G-EP7)
describe("rebuild from an accepted change set (G-EP7)", () => {
  it("rebuilds without a change to the state built from the others", () => {
    const { replica: base } = aliceWithTask();
    const b = fork(base, BOB);
    const c = fork(base, CAROL);
    const changeB = b.apply(setTitle(taskOf(b), "from Bob").intent) as LocalChange;
    const changeC = c.apply(addTag(taskOf(c), "carol").intent) as LocalChange;
    const all = [...base.changes(), changeB.change, changeC.change];
    const full = SharedObjectsReplica.fromChanges([...all].reverse(), opts()).replica;
    expect(full.root()).toEqual(SharedObjectsReplica.fromChanges(all, opts()).replica.root());
    expect(taskOf(full)).toMatchObject({ title: "from Bob", tags: { carol: true } });

    const { replica: without, unapplied } = full.rebuildWithout([changeB.hash]);
    const fromAC = SharedObjectsReplica.fromChanges(
      [...base.changes(), changeC.change],
      opts(),
    ).replica;
    expect(unapplied).toEqual([]);
    expect(without.root()).toEqual(fromAC.root());
    expect(without.heads()).toEqual(fromAC.heads());
  });

  it("leaves dependents unapplied and blocks own-actor reuse", () => {
    const { replica: a, create } = aliceWithTask();
    const after = a.apply(setTitle(taskOf(a), "later").intent) as LocalChange;
    const { replica, unapplied } = a.rebuildWithout([create.hash]);
    expect(unapplied.map((u) => u.hash)).toEqual([after.hash]);
    expect(replica.objectIds()).toEqual([]);
    expect(replica.writable).toBe(false);
  });
});
