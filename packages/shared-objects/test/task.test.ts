import {
  isObjectId,
  LfcpError,
  type ObjectId,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  addTag,
  assign,
  cancel,
  clearDue,
  complete,
  createTask,
  deleteTask,
  deriveActorId,
  frameProfilePayload,
  isLocalDate,
  isNamespacedValue,
  isPrincipalRef,
  isReverseDomain,
  isUtcTimestamp,
  type Json,
  PROFILE_ID,
  ProfileError,
  parsePrincipalRef,
  parseTask,
  principalRef,
  removeTag,
  reopen,
  restoreTask,
  setDue,
  setPriority,
  setStatus,
  setTitle,
  taskToJson,
  unassign,
  unframeProfilePayload,
  validateRoot,
  validateTransition,
} from "../src/index.js";

// Synthetic values only; the published SHARED-OBJECTS-TEST-VECTORS-01 and
// the spec's contract fixtures run in the conformance runner.

const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId; // RFC 9562 A.6 example
const OTHER_ID = "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId;
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const BRUNO = principalId(Uint8Array.from({ length: 32 }, (_, i) => 100 + i));

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    if (e instanceof ProfileError)
      return `${e.code}/${e.problems.map((p) => p.diagnostic).join(",")}`;
    return e instanceof LfcpError ? e.code : String(e);
  }
  return undefined;
};

const newTask = () => createTask({ id: ID, title: "Prepare API contract", createdBy: ALICE }).task;

describe("createTask (§53, §60)", () => {
  it("creates an active Task with every required field and defaults", () => {
    const { task, intent } = createTask({
      title: "Write spec",
      createdBy: ALICE,
      createdAt: "2026-10-04T05:30:00Z",
    });
    expect(isObjectId(task.id)).toBe(true);
    expect(task).toMatchObject({
      type: "task",
      lifecycle: "active",
      created_by: principalRef(ALICE),
      created_at: "2026-10-04T05:30:00Z",
      title: "Write spec",
      status: "todo",
      priority: "normal",
      tags: {},
      assignees: {},
      extensions: {},
    });
    expect(intent).toEqual({ intent: "task.create", task });
    expect(Object.isFrozen(task)).toBe(true);
  });

  it("keeps tags and assignees as add-wins maps (key -> true), not arrays", () => {
    const { task } = createTask({
      id: ID,
      title: "t",
      createdBy: ALICE,
      tags: ["backend", "Backend"],
      assignees: [BRUNO],
    });
    expect(task.tags).toEqual({ backend: true, Backend: true }); // no case folding (§40)
    expect(task.assignees).toEqual({ [principalRef(BRUNO)]: true });
  });

  it("generates distinct UUIDv7 ids and refuses invalid input", () => {
    const a = createTask({ title: "a", createdBy: ALICE }).task.id;
    const b = createTask({ title: "b", createdBy: ALICE }).task.id;
    expect(a).not.toBe(b);
    expect(
      codeOf(() => createTask({ title: "a", createdBy: ALICE, id: "NOT-A-UUID" as ObjectId })),
    ).toBe("INVALID_UUIDV7");
    expect(codeOf(() => createTask({ title: "a", createdBy: ALICE, due: "2026-02-30" }))).toBe(
      "PROFILE_INVALID/INVALID_LOCAL_DATE",
    );
    expect(codeOf(() => createTask({ title: "a", createdBy: ALICE, tags: ["#x"] }))).toBe(
      "PROFILE_INVALID/INVALID_TAG",
    );
    expect(
      codeOf(() => createTask({ title: "a", createdBy: ALICE, createdAt: "2026-10-04 05:30" })),
    ).toBe("PROFILE_INVALID/INVALID_TIMESTAMP");
  });

  it("allows an empty title (§32)", () => {
    expect(createTask({ title: "", createdBy: ALICE }).task.title).toBe("");
  });
});

describe("intents (§59-§68)", () => {
  it("title, status, priority", () => {
    const t = newTask();
    expect(setTitle(t, "New").task.title).toBe("New");
    expect(setStatus(t, "in_progress")).toMatchObject({
      task: { status: "in_progress" },
      intent: { intent: "task.set_status", id: ID },
    });
    expect(setStatus(t, "x/com.example/waiting_review").task.status).toBe(
      "x/com.example/waiting_review",
    );
    expect(setPriority(t, "x/org.example.team/p0").task.priority).toBe("x/org.example.team/p0");
    expect(codeOf(() => setStatus(t, "waiting" as never))).toBe(
      "PROFILE_INVALID/INVALID_ENUM_VALUE",
    );
    expect(codeOf(() => setPriority(t, "x/Example/p0" as never))).toBe(
      "PROFILE_INVALID/INVALID_ENUM_VALUE",
    );
  });

  it("complete, reopen and cancel manage the completion date", () => {
    const done = complete(newTask(), "2026-10-08");
    expect(done.task).toMatchObject({ status: "done", completion_date: "2026-10-08" });
    expect(complete(newTask()).task).not.toHaveProperty("completion_date");
    expect(reopen(done.task).task).not.toHaveProperty("completion_date");
    expect(reopen(done.task).task.status).toBe("todo");
    expect(cancel(done.task).task).toMatchObject({ status: "cancelled" });
    expect(cancel(done.task).task).not.toHaveProperty("completion_date");
  });

  it("dates are validated before the change and cleared by deleting the property (§36, §66)", () => {
    const t = setDue(newTask(), "2028-02-29").task;
    expect(t.due).toBe("2028-02-29");
    expect(clearDue(t).task).not.toHaveProperty("due");
    expect(codeOf(() => setDue(newTask(), "2027-02-29"))).toBe(
      "PROFILE_INVALID/INVALID_LOCAL_DATE",
    );
  });

  it("tags: add sets true after NFC normalization, remove deletes the key", () => {
    const decomposed = "café";
    const t = addTag(newTask(), decomposed);
    expect(Object.keys(t.task.tags)).toEqual(["café"]);
    expect(removeTag(t.task, "café").task.tags).toEqual({});
    expect(codeOf(() => addTag(newTask(), ""))).toBe("PROFILE_INVALID/INVALID_TAG");
    expect(codeOf(() => addTag(newTask(), "#backend"))).toBe("PROFILE_INVALID/INVALID_TAG");
  });

  it("assignees: validated Principal references, add and remove", () => {
    const t = assign(newTask(), BRUNO).task;
    expect(t.assignees).toEqual({ [principalRef(BRUNO)]: true });
    expect(unassign(t, principalRef(BRUNO)).task.assignees).toEqual({});
    expect(codeOf(() => assign(newTask(), "p:short" as never))).toBe(
      "PROFILE_INVALID/INVALID_PRINCIPAL_REF",
    );
  });

  it("delete and restore write lifecycle only; the object stays (§54, §55)", () => {
    const deleted = deleteTask(setTitle(newTask(), "kept").task);
    expect(deleted.task).toMatchObject({ lifecycle: "deleted", title: "kept" });
    expect(restoreTask(deleted.task).task.lifecycle).toBe("active");
  });
});

describe("unknown data preservation (§70-§72)", () => {
  it("round-trips unknown fields and extension namespaces through an unrelated mutation", () => {
    const json = {
      ...(taskToJson(newTask()) as Record<string, Json>),
      x_future_scalar: "future-value",
      estimate: { hours: 3, confidence: [0.5, null, true] },
      extensions: { "com.example.tracker": { ticket: "ABC-42" } },
    };
    const parsed = parseTask(json);
    if (!parsed.valid) throw new Error(JSON.stringify(parsed.problems));
    const changed = setStatus(parsed.task, "in_progress").task;
    expect(taskToJson(changed)).toEqual({ ...json, status: "in_progress" });
  });
});

describe("parseTask and validation (§74, §74.1)", () => {
  const base = () => taskToJson(newTask()) as Record<string, Json>;
  const diagnostics = (obj: Json) => {
    const r = parseTask(obj);
    return r.valid ? [] : r.problems.map((p) => `${p.diagnostic} ${p.pointer}`);
  };

  it.each([
    ["title", 42, "INVALID_FIELD_TYPE /title"],
    ["lifecycle", "archived", "INVALID_ENUM_VALUE /lifecycle"],
    ["status", "x/com.example/a/b", "INVALID_ENUM_VALUE /status"],
    ["due", "2026-13-50", "INVALID_LOCAL_DATE /due"],
    ["due", 20261010, "INVALID_LOCAL_DATE /due"],
    ["tags", ["backend"], "INVALID_COLLECTION_REPRESENTATION /tags"],
    ["tags", { backend: false }, "INVALID_COLLECTION_REPRESENTATION /tags/backend"],
    ["tags", { "#x": true }, "INVALID_TAG /tags/#x"],
    ["assignees", { "not-a-principal": true }, "INVALID_PRINCIPAL_REF /assignees/not-a-principal"],
    ["created_by", "p:AAAA", "INVALID_PRINCIPAL_REF /created_by"],
    ["created_at", "2026-10-04T25:00:00Z", "INVALID_TIMESTAMP /created_at"],
    ["extensions", { Tracker: {} }, "INVALID_EXTENSION_NAMESPACE /extensions/Tracker"],
    ["id", OTHER_ID, "OBJECT_ID_MISMATCH /id"],
  ] as [string, Json, string][])("%s = %j -> %s", (field, value, expected) => {
    expect(parseTask({ ...base(), [field]: value }, ID).valid).toBe(false);
    const r = parseTask({ ...base(), [field]: value }, ID);
    expect(r.valid ? [] : r.problems.map((p) => `${p.diagnostic} ${p.pointer}`)).toContain(
      expected,
    );
  });

  it("reports one diagnostic per value, the first in §74.1 table order (SOG-2)", () => {
    // Not a UUIDv7 and not the objects key: INVALID_OBJECT_ID only.
    const r = parseTask({ ...base(), id: "not-a-uuid" }, ID);
    expect(r.valid ? [] : r.problems.map((p) => `${p.diagnostic} ${p.pointer}`)).toEqual([
      "INVALID_OBJECT_ID /id",
    ]);
  });

  it("reports a missing required field at the object", () => {
    const { priority: _drop, ...rest } = base();
    expect(diagnostics(rest)).toEqual(["MISSING_REQUIRED_FIELD "]);
  });

  it("treats null and missing dates alike (§36)", () => {
    expect(parseTask({ ...base(), due: null, scheduled: null }).valid).toBe(true);
  });
});

describe("validateRoot (§15, §17, §77)", () => {
  const task = taskToJson(newTask());
  const root = (objects: Record<string, Json>, extra: Record<string, Json> = {}) => ({
    profile: PROFILE_ID,
    objects,
    extensions: {},
    ...extra,
  });

  it("accepts an initial root, unknown top-level keys and unknown object types", () => {
    expect(validateRoot(root({})).valid).toBe(true);
    expect(validateRoot(root({}, { future_key: 1 })).valid).toBe(true);
    const poll = {
      id: OTHER_ID,
      type: "com.example.poll",
      lifecycle: "active",
      created_by: principalRef(ALICE),
      extensions: {},
      options: ["a"],
    };
    expect(validateRoot(root({ [ID]: task, [OTHER_ID]: poll })).valid).toBe(true);
  });

  it("isolates an invalid object (§77)", () => {
    const bad = { ...(task as Record<string, Json>), id: OTHER_ID, title: 1 };
    const r = validateRoot(root({ [ID]: task, [OTHER_ID]: bad }));
    expect(r.valid).toBe(false);
    expect(r.objects.get(ID)).toEqual([]);
    expect(r.objects.get(OTHER_ID)?.map((p) => p.diagnostic)).toEqual(["INVALID_FIELD_TYPE"]);
  });

  it("reports root problems as INVALID_ROOT", () => {
    expect(
      validateRoot({ profile: "other", objects: {}, extensions: {} }).problems.map((p) => [
        p.diagnostic,
        p.pointer,
      ]),
    ).toEqual([["INVALID_ROOT", "/profile"]]);
    expect(
      validateRoot({ profile: PROFILE_ID, objects: [], extensions: {} }).problems[0]?.pointer,
    ).toBe("/objects");
    expect(validateRoot([]).problems[0]?.diagnostic).toBe("INVALID_ROOT");
  });

  it("validateTransition reports changed immutable fields (§75)", () => {
    const before = root({ [ID]: task });
    const after = root({
      [ID]: { ...(task as Record<string, Json>), type: "decision", title: "x" },
    });
    expect(validateTransition(before, after).map((p) => [p.diagnostic, p.pointer])).toEqual([
      ["IMMUTABLE_FIELD_MUTATED", `/objects/${ID}/type`],
    ]);
    expect(
      validateTransition(before, root({ [ID]: { ...(task as Record<string, Json>), title: "x" } })),
    ).toEqual([]);
  });

  it("validateTransition puts IMMUTABLE_FIELD_MUTATED last (§74.1)", () => {
    const before = root({ [ID]: task });
    const { created_by: _drop, ...rest } = task as Record<string, Json>;
    // A changed id that is not a UUIDv7, a type that is not text, a removed created_by.
    const after = root({ [ID]: { ...rest, id: "not-a-uuid", type: 7 } });
    expect(validateTransition(before, after)).toEqual([]);
    expect(validateRoot(after).problems.map((p) => [p.diagnostic, p.pointer])).toEqual([
      ["MISSING_REQUIRED_FIELD", `/objects/${ID}`],
      ["INVALID_OBJECT_ID", `/objects/${ID}/id`],
      ["INVALID_FIELD_TYPE", `/objects/${ID}/type`],
    ]);
  });
});

describe("values", () => {
  it("Principal references are p: + canonical base64url of 32 bytes (§27)", () => {
    const ref = principalRef(ALICE);
    expect(ref).toBe("p:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
    expect(toHex(parsePrincipalRef(ref))).toBe(toHex(ALICE));
    expect(isPrincipalRef(ref)).toBe(true);
    expect(isPrincipalRef(`${ref.slice(0, -1)}h`)).toBe(false); // non-canonical trailing bits
    expect(isPrincipalRef(ref.slice(0, -2))).toBe(false); // 31 bytes
    expect(isPrincipalRef(ref.slice(2))).toBe(false);
  });

  it("dates, timestamps, reverse domains and namespaced values", () => {
    expect([
      isLocalDate("2000-02-29"),
      isLocalDate("1900-02-29"),
      isLocalDate("2026-04-31"),
    ]).toEqual([true, false, false]);
    expect([
      isUtcTimestamp("2016-12-31T23:59:60Z"),
      isUtcTimestamp("2026-10-04T24:00:00Z"),
      isUtcTimestamp("2026-10-04T05:30:00+00:00"),
    ]).toEqual([true, false, false]);
    expect([
      isReverseDomain("com.example"),
      isReverseDomain("example"),
      isReverseDomain("com.-x"),
      isReverseDomain("Com.example"),
    ]).toEqual([true, false, false, false]);
    expect([
      isNamespacedValue("x/com.example/waiting review"),
      isNamespacedValue("x/com.example/"),
      isNamespacedValue("x/com.example/a/b"),
    ]).toEqual([true, false, false]);
  });

  it("derives a 32-byte actor ID per (Resource, Principal) (§8)", () => {
    const r1 = resourceId(new Uint8Array(32).fill(1));
    const r2 = resourceId(new Uint8Array(32).fill(2));
    const a = deriveActorId(r1, ALICE);
    expect(a).toHaveLength(32);
    expect(toHex(a)).not.toBe(toHex(deriveActorId(r2, ALICE)));
    expect(toHex(a)).not.toBe(toHex(deriveActorId(r1, BRUNO)));
  });

  it("frames and unframes profile plaintexts as [1, bstr] (§11, §13)", () => {
    for (const n of [0, 5, 23, 24, 255, 256, 70000]) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => i & 0xff);
      expect(toHex(unframeProfilePayload(frameProfilePayload(bytes)))).toBe(toHex(bytes));
    }
    expect(toHex(frameProfilePayload(Uint8Array.of(0xaa)))).toBe("820141aa");
    for (const bad of ["830141aa", "820241aa", "820141aa00", "8201580101", "820101", "8201"]) {
      expect(
        codeOf(() =>
          unframeProfilePayload(
            Uint8Array.from(bad.match(/../g) ?? [], (h) => Number.parseInt(h, 16)),
          ),
        ),
      ).toBe("PROFILE_INVALID");
    }
  });
});
