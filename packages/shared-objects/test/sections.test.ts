// SHARED-SECTIONS-PROFILE-01 dispatch, actor binding and schema validation
// (LFCP-02-011): the scalar/Text, type and actor negatives, and the legacy
// Shared Objects dispatch regression. The corpus cases (SS01, SS18 and the
// rest) run in conformance/shared-sections.

import * as A from "@automerge/automerge";
import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange, checkChangeActor } from "../src/admission/index.js";
import { deriveActorId, PROFILE_ID, principalRef, validateRoot } from "../src/index.js";
import {
  deriveSectionActorId,
  profileModel,
  SECTIONS_PROFILE_ID,
  SectionDocument,
  SUPPORTED_DATA_PROFILES,
  taskRefModel,
  validateSection,
} from "../src/sections/index.js";

const resource = resourceId(new Uint8Array(32).fill(7));
const alice = principalId(new Uint8Array(32).fill(1));
const ALICE = principalRef(alice);
const S = (s: string) => new A.ImmutableString(s);
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const TASK = id(2);
const PARA = id(3);
const P_TASK = id(4);
const P_PARA = id(5);

// Fixtures write arbitrary, deliberately invalid shapes into the document.
// biome-ignore lint/suspicious/noExplicitAny: test fixtures build invalid documents
type Doc = Record<string, any>;
const actor = toHex(deriveSectionActorId(resource, alice));

/** A ready section: one Task with a child paragraph, as SS01 shapes it. */
function section(edit?: (d: Doc) => void, ready = true): A.Doc<Doc> {
  return A.change(A.init<Doc>({ actor }), { time: 0, message: "initial" }, (d) => {
    d.profile = S(SECTIONS_PROFILE_ID);
    d.section = {
      id: S(SECTION),
      title: S("Launch"),
      created_by: S(ALICE),
      children: [S(P_TASK)],
      extensions: {},
    };
    if (ready) d.section.ready = true;
    d.objects = {
      [TASK]: {
        id: S(TASK),
        type: S("task"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        title: S("Prepare contract"),
        status: S("todo"),
        priority: S("normal"),
        tags: {},
        assignees: {},
        extensions: {},
      },
    };
    d.nodes = {
      [TASK]: {
        id: S(TASK),
        kind: S("task"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        placement: S(P_TASK),
        children: [S(P_PARA)],
        extensions: {},
        task_id: S(TASK),
        list_style: S("bullet"),
      },
      [PARA]: {
        id: S(PARA),
        kind: S("paragraph"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        placement: S(P_PARA),
        children: [],
        extensions: {},
        text: "Draft contract",
      },
    };
    d.placements = {
      [P_TASK]: { id: S(P_TASK), node_id: S(TASK), parent_id: S(SECTION), created_by: S(ALICE) },
      [P_PARA]: { id: S(P_PARA), node_id: S(PARA), parent_id: S(TASK), created_by: S(ALICE) },
    };
    d.extensions = {};
    edit?.(d);
  });
}

const nodeDiagnostics = (doc: A.Doc<unknown>) =>
  Object.fromEntries([...validateSection(doc).nodes].map(([k, p]) => [k, p.diagnostic]));

describe("profile dispatch (§1, §17)", () => {
  it("selects the model from the Genesis profile, exactly", () => {
    expect(profileModel(PROFILE_ID).kind).toBe("shared-objects");
    expect(profileModel(SECTIONS_PROFILE_ID).kind).toBe("shared-sections");
    expect(SUPPORTED_DATA_PROFILES).toEqual([PROFILE_ID, SECTIONS_PROFILE_ID]);
    for (const other of [
      "org.openlfcp.shared-sections.v2",
      "ORG.OPENLFCP.SHARED-SECTIONS.V1",
      `${SECTIONS_PROFILE_ID} `,
      "",
    ])
      expect(profileModel(other)).toEqual({
        kind: "profile-unsupported",
        code: "PROFILE_UNSUPPORTED",
        dataProfile: other,
      });
  });

  it("reads a Task reference with the model of its Resource's profile", () => {
    expect(taskRefModel(PROFILE_ID).kind).toBe("shared-objects");
    expect(taskRefModel(SECTIONS_PROFILE_ID).kind).toBe("shared-sections");
    expect(taskRefModel("com.example.other").kind).toBe("profile-unsupported");
  });
});

describe("section actor binding (§2)", () => {
  it("differs from the Shared Objects actor of the same pair", () => {
    expect(toHex(deriveSectionActorId(resource, alice))).not.toBe(
      toHex(deriveActorId(resource, alice)),
    );
  });

  it("refuses a change of the Shared Objects actor as CHANGE_ACTOR_MISMATCH", () => {
    const legacy = A.change(
      A.init<Doc>({ actor: toHex(deriveActorId(resource, alice)) }),
      { time: 0 },
      (d) => {
        d.x = 1;
      },
    );
    const change = checkChange(A.getLastLocalChange(legacy) as Uint8Array);
    expect(() => checkChangeActor(change, actor)).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHANGE_ACTOR_MISMATCH" }),
    );
    const own = checkChange(A.getLastLocalChange(section()) as Uint8Array);
    expect(checkChangeActor(own, actor).actor).toBe(actor);
  });
});

describe("section schema (§3, §4, §14.2)", () => {
  it("accepts a well-formed section, ready or importing", () => {
    const v = validateSection(section());
    expect(v.state).toBe("ready");
    expect(v.sectionId).toBe(SECTION);
    expect([v.problems, v.collisions, v.nodes.size, v.placements.size, v.objects.size]).toEqual([
      [],
      [],
      0,
      0,
      0,
    ]);
    expect(validateSection(section(undefined, false)).state).toBe("importing");
  });

  it("never changes the document", () => {
    const doc = section((d) => {
      d.nodes[PARA].kind = S("heading");
    });
    const before = A.save(doc);
    validateSection(doc);
    expect(A.save(doc)).toEqual(before);
  });

  it("a Task title written as Text isolates the Task and its node (§2, SOP §30)", () => {
    const doc = section((d) => {
      d.objects[TASK].title = "as Text";
    });
    const v = validateSection(doc);
    expect(v.state).toBe("ready");
    expect(v.objects.get(TASK)?.map((p) => [p.diagnostic, p.pointer])).toEqual([
      ["INVALID_FIELD_TYPE", `/objects/${TASK}/title`],
    ]);
    expect(nodeDiagnostics(doc)).toEqual({ [TASK]: "INVALID_FIELD_TYPE" });
  });

  it("a paragraph body written as a scalar is INVALID_FIELD_TYPE (§4.2)", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].text = S("scalar");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_FIELD_TYPE" });
  });

  it("a task node with text, or any other field as Text, is INVALID_FIELD_TYPE", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[TASK].text = "body";
        }),
      ),
    ).toEqual({ [TASK]: "INVALID_FIELD_TYPE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].lifecycle = "active";
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_FIELD_TYPE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].children.push("not scalar");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_FIELD_TYPE" });
  });

  it("enforces canonical IDs and enumerations", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].kind = S("heading");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_ENUM_VALUE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[TASK].lifecycle = S("deleted");
        }),
      ),
    ).toEqual({ [TASK]: "INVALID_ENUM_VALUE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].id = S(PARA.toUpperCase());
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_OBJECT_ID" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].list_style = S("bullet");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_FIELD_TYPE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[TASK].list_style = S("numbered");
        }),
      ),
    ).toEqual({ [TASK]: "INVALID_ENUM_VALUE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].created_by = S("p:short");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_PRINCIPAL_REF" });
  });

  it("checks references: a missing Task, a paragraph parent, another node's placement", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          delete d.objects[TASK];
        }),
      ),
    ).toEqual({ [TASK]: "INVALID_REFERENCE" });
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].placement = S(P_TASK);
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_REFERENCE" });
    const under = id(9);
    const doc = section((d) => {
      d.nodes[under] = {
        id: S(under),
        kind: S("item"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        placement: S(id(10)),
        children: [],
        extensions: {},
        text: "child of a paragraph",
      };
      d.placements[id(10)] = {
        id: S(id(10)),
        node_id: S(under),
        parent_id: S(PARA),
        created_by: S(ALICE),
      };
    });
    expect(nodeDiagnostics(doc)).toEqual({ [under]: "INVALID_REFERENCE" });
  });

  it("a node's diagnostic is the first that applies in §14.2 order", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].created_by = S("p:short");
          d.nodes[PARA].text = S("scalar");
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_FIELD_TYPE" });
  });

  it("concurrent values of an immutable field are IMMUTABLE_FIELD_MUTATED", () => {
    const base = section();
    const bob = toHex(deriveSectionActorId(resource, principalId(new Uint8Array(32).fill(2))));
    const a = A.change(A.clone(base), (d) => {
      d.nodes[PARA].kind = S("item");
    });
    const b = A.change(A.clone(base, { actor: bob }), (d) => {
      d.nodes[PARA].kind = S("raw");
    });
    expect(nodeDiagnostics(A.merge(a, b))).toEqual({ [PARA]: "IMMUTABLE_FIELD_MUTATED" });
  });

  it("does not isolate an ID reused across categories (§3 is the writer's rule)", () => {
    const doc = section((d) => {
      d.placements[PARA] = {
        id: S(PARA),
        node_id: S(PARA),
        parent_id: S(SECTION),
        created_by: S(ALICE),
      };
    });
    const v = validateSection(doc);
    expect([v.collisions, v.collided]).toEqual([[], []]);
    expect(v.nodes.has(PARA)).toBe(false);
  });

  it("a node whose own, Task or selected placement ID collides is not validated (§14.2)", () => {
    const base = section();
    const bob = toHex(deriveSectionActorId(resource, principalId(new Uint8Array(32).fill(2))));
    const item = id(30);
    const shared = id(31);
    const write = (doc: A.Doc<Doc>, who: string | undefined, text: string) =>
      A.change(who === undefined ? A.clone(doc) : A.clone(doc, { actor: who }), (d) => {
        d.nodes[item] = {
          id: S(item),
          kind: S("item"),
          created_by: S(ALICE),
          lifecycle: S("active"),
          placement: S(shared),
          children: [],
          extensions: {},
          text,
        };
        d.placements[shared] = {
          id: S(shared),
          node_id: S(item),
          parent_id: S(SECTION),
          created_by: S(ALICE),
        };
        d.section.children.push(S(shared));
      });
    const v = validateSection(A.merge(write(base, undefined, "a"), write(base, bob, "b")));
    expect(v.collisions).toEqual([item, shared].sort());
    expect(v.collided).toEqual([item]);
    expect([v.state, v.nodes.size, v.placements.size]).toEqual(["ready", 0, 0]);

    // Both writers create the Task map anew: two concurrent maps under one ID.
    const recreate = (title: string) => (d: Doc) => {
      d.objects[TASK] = {
        id: S(TASK),
        type: S("task"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        title: S(title),
        status: S("todo"),
        priority: S("normal"),
        tags: {},
        assignees: {},
        extensions: {},
      };
    };
    const task = A.merge(
      A.change(A.clone(base), recreate("A")),
      A.change(A.clone(base, { actor: bob }), recreate("B")),
    );
    const t = validateSection(task);
    expect(t.collisions).toEqual([TASK]);
    expect(t.collided).toEqual([TASK]);
    expect(t.nodes.has(TASK)).toBe(false);
  });

  it("section-level problems leave nothing usable", () => {
    for (const [edit, pointer] of [
      [(d: Doc) => (d.profile = S(PROFILE_ID)), "/profile"],
      [(d: Doc) => (d.profile = SECTIONS_PROFILE_ID), "/profile"],
      [(d: Doc) => delete d.placements, "/placements"],
      [(d: Doc) => (d.section.children = S("x")), "/section/children"],
    ] as const) {
      const v = validateSection(section(edit));
      expect(v.state).toBe("invalid");
      expect(v.problems.map((p) => [p.diagnostic, p.pointer])).toEqual([["INVALID_ROOT", pointer]]);
    }
    const v = validateSection(
      section((d) => {
        d.section.title = "as Text";
        d.section.ready = S("yes");
      }),
    );
    expect(v.state).toBe("invalid");
    expect(v.problems.map((p) => p.pointer)).toEqual(["/section/title", "/section/ready"]);
  });

  it("preserves unknown root keys, extensions and object types", () => {
    const other = id(20);
    const doc = section((d) => {
      d["com.example.root"] = S("kept");
      d.extensions["com.example.future"] = { value: S("kept") };
      d.nodes[PARA].extensions["com.example.future"] = { value: S("kept") };
      d.objects[other] = {
        id: S(other),
        type: S("com.example.note"),
        created_by: S(ALICE),
        lifecycle: S("active"),
        extensions: {},
      };
    });
    const v = validateSection(doc);
    expect([v.state, v.problems, v.nodes.size, v.objects.size]).toEqual(["ready", [], 0, 0]);
    const loaded = SectionDocument.fromSave(A.save(doc), "local-state");
    expect(loaded.valueTypes(["nodes", PARA, "extensions", "com.example.future", "value"])).toEqual(
      ["str"],
    );
    expect(loaded.valueTypes(["com.example.root"])).toEqual(["str"]);
  });

  it("an extension namespace must be reverse-domain", () => {
    expect(
      nodeDiagnostics(
        section((d) => {
          d.nodes[PARA].extensions.Bad = {};
        }),
      ),
    ).toEqual({ [PARA]: "INVALID_EXTENSION_NAMESPACE" });
  });
});

describe("legacy dispatch regression", () => {
  it("a Shared Objects root is not a section, and a section root is not Shared Objects", () => {
    const legacy = A.change(A.init<Doc>(), (d) => {
      d.profile = S(PROFILE_ID);
      d.objects = {};
      d.extensions = {};
    });
    expect(validateSection(legacy).state).toBe("invalid");
    expect(validateRoot(A.toJS(section()) as never).problems.map((p) => p.diagnostic)).toContain(
      "INVALID_ROOT",
    );
  });
});

describe("SectionDocument", () => {
  it("loads changes in any order and names the ones whose dependencies are missing", () => {
    const doc = A.change(section(), { time: 0 }, (d) => {
      A.splice(d, ["nodes", PARA, "text"], 0, 0, "Final ");
    });
    const changes = A.getAllChanges(doc);
    const all = SectionDocument.fromChanges([...changes].reverse());
    expect(all.unapplied).toEqual([]);
    expect(all.document.heads()).toEqual([...A.getHeads(doc)].sort());
    const partial = SectionDocument.fromChanges(changes.slice(1));
    expect(partial.unapplied).toHaveLength(1);
  });

  it("refuses bytes that are not an Automerge save", () => {
    expect(() => SectionDocument.fromSave(new Uint8Array([1, 2, 3]))).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" }),
    );
  });
});
