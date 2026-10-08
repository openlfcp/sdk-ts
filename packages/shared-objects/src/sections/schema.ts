import * as A from "@automerge/automerge";
import { isObjectId } from "@openlfcp/core";
import { storedObjectProblems } from "../replica.js";
import { type ProfileProblem, pointerToken } from "../validate.js";
import { isPrincipalRef, isReverseDomain, isUtcTimestamp } from "../values.js";
import {
  LIST_STYLES,
  NODE_KINDS,
  type NodeKind,
  PARENT_KINDS,
  ROOT_MAPS,
  SECTIONS_PROFILE_ID,
  TEXT_KINDS,
} from "./values.js";

/**
 * Schema validation of a SHARED-SECTIONS-PROFILE-01 document (§3, §4,
 * §14.2) as Automerge stores it, read through the backend so that a scalar
 * string and collaborative Text are told apart, conflicted or not (§2: never
 * from a plain JSON dump). Every concurrent value of a field is inspected.
 *
 * - Section-level problems (the root, the section map) leave nothing to
 *   project: the document is "invalid".
 * - Otherwise each invalid node, placement and object is isolated with one
 *   diagnostic, the first that applies in the §14.2 order; the rest of the
 *   section stays usable.
 * - A section without `ready` is "importing" (§12.1).
 *
 * Structural facts (placement conflicts, cycles, blocked parents, lifecycle
 * conflicts, §14.3) and the effective tree are not decided here. Admission
 * (§14.1) runs before a change is merged; this reads merged state only and
 * never changes the document.
 */

/** §14.2: the diagnostics of a section value, in their order. */
export type SectionDiagnostic =
  | "INVALID_ROOT"
  | "INVALID_OBJECT_ID"
  | "OBJECT_ID_MISMATCH"
  | "MISSING_REQUIRED_FIELD"
  | "INVALID_FIELD_TYPE"
  | "INVALID_ENUM_VALUE"
  | "INVALID_EXTENSION_NAMESPACE"
  | "INVALID_PRINCIPAL_REF"
  | "INVALID_TIMESTAMP"
  | "INVALID_LOCAL_DATE"
  | "INVALID_COLLECTION_REPRESENTATION"
  | "INVALID_TAG"
  | "INVALID_REFERENCE"
  | "IMMUTABLE_FIELD_MUTATED";

/** §14.2: SOP §74.1's registry with the section rows, in table order. */
export const SECTION_DIAGNOSTIC_ORDER: readonly SectionDiagnostic[] = Object.freeze([
  "INVALID_ROOT",
  "INVALID_OBJECT_ID",
  "OBJECT_ID_MISMATCH",
  "MISSING_REQUIRED_FIELD",
  "INVALID_FIELD_TYPE",
  "INVALID_ENUM_VALUE",
  "INVALID_EXTENSION_NAMESPACE",
  "INVALID_PRINCIPAL_REF",
  "INVALID_TIMESTAMP",
  "INVALID_LOCAL_DATE",
  "INVALID_COLLECTION_REPRESENTATION",
  "INVALID_TAG",
  "INVALID_REFERENCE",
  "IMMUTABLE_FIELD_MUTATED",
]);

/** One section validation failure: PROFILE_INVALID with its §14.2 diagnostic. */
export interface SectionProblem {
  readonly code: "PROFILE_INVALID";
  readonly diagnostic: SectionDiagnostic;
  /** JSON Pointer of the offending value (of its container, for a missing field). */
  readonly pointer: string;
  readonly message: string;
}

export interface SectionValidation {
  /**
   * "invalid": a section-level problem, nothing is projected (§14.2);
   * "importing": valid, `ready` not yet written (§12.1);
   * "ready": valid and ready.
   */
  readonly state: "invalid" | "importing" | "ready";
  /** The section-level problems: the root and the section map. */
  readonly problems: readonly SectionProblem[];
  /** The section ID, when it is one. */
  readonly sectionId: string | undefined;
  /** Each invalid node with its one diagnostic (§14.2); its descendants are blocked (§7). */
  readonly nodes: ReadonlyMap<string, SectionProblem>;
  /** Each invalid placement with its one diagnostic. */
  readonly placements: ReadonlyMap<string, SectionProblem>;
  /** Each invalid object (a Task or a preserved unknown Shared Object), per field (SOP §74.1). */
  readonly objects: ReadonlyMap<string, readonly ProfileProblem[]>;
  /**
   * §14.2, SOP §21 OBJECT_ID_COLLISION: IDs under which `nodes`,
   * `objects` or `placements` holds concurrent maps, sorted. A separate
   * named error, not a diagnostic. Reusing one ID across categories (a
   * node ID equal to a PlacementId, say) is a writer error (§3) that a
   * reader does not check: isolating it would let any writer take out
   * another's node with an ordinary change.
   */
  readonly collisions: readonly string[];
  /**
   * §14.2: the nodes whose own ID, Task ID or selected PlacementId
   * collides, sorted. They are not validated and not projected, and no
   * value is chosen; their descendants are blocked (§7).
   */
  readonly collided: readonly string[];
}

/** A backend value: [datatype, value, opId] for a scalar, [datatype, objId] for an object. */
type Value = readonly [string, ...unknown[]];

const problem = (diagnostic: SectionDiagnostic, pointer: string, message: string): SectionProblem =>
  Object.freeze({ code: "PROFILE_INVALID", diagnostic, pointer, message });

const rank = (p: SectionProblem) => SECTION_DIAGNOSTIC_ORDER.indexOf(p.diagnostic);

/** The first problem in §14.2 order; ties keep their discovery order. */
const first = (problems: readonly SectionProblem[]): SectionProblem | undefined =>
  problems.reduce<SectionProblem | undefined>(
    (best, p) => (best === undefined || rank(p) < rank(best) ? p : best),
    undefined,
  );

const ref = (base: string, key: string) => `${base}/${pointerToken(key)}`;

/** Reads a document through the backend, at its current state (no heads: a historical read is far slower). */
class Reader {
  readonly #backend: ReturnType<typeof A.getBackend>;

  constructor(doc: A.Doc<unknown>) {
    this.#backend = A.getBackend(doc);
  }

  all(obj: string, prop: string | number): Value[] {
    return this.#backend.getAll(obj, prop) as Value[];
  }

  keys(obj: string): string[] {
    return this.#backend.keys(obj);
  }

  length(obj: string): number {
    return this.#backend.length(obj);
  }

  /** The value of `prop` when it has exactly one, and that one is a map. */
  map(obj: string, prop: string): string | undefined {
    const values = this.all(obj, prop);
    return values.length === 1 && values[0]?.[0] === "map" ? (values[0][1] as string) : undefined;
  }

  /** The value of `prop` when it has exactly one, and that one is a scalar string. */
  str(obj: string, prop: string): string | undefined {
    const values = this.all(obj, prop);
    return values.length === 1 && values[0]?.[0] === "str" ? (values[0][1] as string) : undefined;
  }
}

/** The checks of one map's fields, collected with their pointers. */
class Fields {
  readonly out: SectionProblem[] = [];

  constructor(
    readonly r: Reader,
    readonly obj: string,
    readonly at: string,
    readonly what: string,
  ) {}

  has(field: string): boolean {
    return this.r.all(this.obj, field).length > 0;
  }

  required(fields: readonly string[]): void {
    for (const f of fields)
      if (!this.has(f))
        this.out.push(
          problem("MISSING_REQUIRED_FIELD", this.at, `${this.what} has no required field ${f}`),
        );
  }

  /**
   * Every value of `field` is a scalar string that `check` accepts (or
   * `onBad` with `reason`); an immutable field must have one value.
   */
  scalar(
    field: string,
    check: ((s: string) => boolean) | undefined,
    onBad: SectionDiagnostic,
    reason: string,
    immutable: boolean,
  ): void {
    const values = this.r.all(this.obj, field);
    const at = ref(this.at, field);
    for (const v of values) {
      if (v[0] !== "str")
        this.out.push(
          problem(
            "INVALID_FIELD_TYPE",
            at,
            v[0] === "text"
              ? `${field} is collaborative Text, not a scalar string (§3)`
              : `${field} must be a scalar string (§3, §4)`,
          ),
        );
      else if (check !== undefined && !check(v[1] as string))
        this.out.push(problem(onBad, at, `${field} ${reason}`));
    }
    if (immutable && values.length > 1)
      this.out.push(
        problem("IMMUTABLE_FIELD_MUTATED", at, `the immutable ${field} has concurrent values`),
      );
  }

  /** The field is one list (insert-only, §4.1) of scalar strings. */
  list(field: string): void {
    const values = this.r.all(this.obj, field);
    const at = ref(this.at, field);
    if (values.length !== 1 || values[0]?.[0] !== "list") {
      this.out.push(problem("INVALID_FIELD_TYPE", at, `${field} must be one Automerge list (§4)`));
      return;
    }
    const list = values[0][1] as string;
    for (let i = 0; i < this.r.length(list); i++)
      if (this.r.all(list, i).some((v) => v[0] !== "str"))
        this.out.push(
          problem(
            "INVALID_FIELD_TYPE",
            `${at}/${i}`,
            `a ${field} entry must be a scalar string PlacementId (§4.3)`,
          ),
        );
  }

  /** The field is one map whose keys are reverse-domain namespaces (§3, SOP §18). */
  extensions(field = "extensions"): void {
    const values = this.r.all(this.obj, field);
    const at = ref(this.at, field);
    if (values.length !== 1 || values[0]?.[0] !== "map") {
      this.out.push(problem("INVALID_FIELD_TYPE", at, `${field} must be one map (§3)`));
      return;
    }
    for (const ns of this.r.keys(values[0][1] as string))
      if (!isReverseDomain(ns))
        this.out.push(
          problem(
            "INVALID_EXTENSION_NAMESPACE",
            ref(at, ns),
            `"${ns}" is not a reverse-domain namespace (§3)`,
          ),
        );
  }

  createdBy(): void {
    this.scalar(
      "created_by",
      isPrincipalRef,
      "INVALID_PRINCIPAL_REF",
      "is not p: + base64url of 32 bytes",
      true,
    );
  }

  createdAt(): void {
    if (this.has("created_at"))
      this.scalar(
        "created_at",
        isUtcTimestamp,
        "INVALID_TIMESTAMP",
        "is not an RFC 3339 UTC timestamp",
        true,
      );
  }

  /** `id` is a canonical UUIDv7 equal to the map key `key`. */
  id(key: string): void {
    this.scalar("id", isObjectId, "INVALID_OBJECT_ID", "is not a canonical UUIDv7 (§3)", true);
    const id = this.r.str(this.obj, "id");
    if (id !== undefined && id !== key && isObjectId(id))
      this.out.push(
        problem("OBJECT_ID_MISMATCH", ref(this.at, "id"), "id differs from its map key"),
      );
  }
}

const isNodeKind = (s: string): s is NodeKind => (NODE_KINDS as readonly string[]).includes(s);
const LIFECYCLES = new Set(["active", "deleted"]);

/** Validates a section document (§3, §4, §14.2). Reads only; the document is unchanged. */
export function validateSection(doc: A.Doc<unknown>): SectionValidation {
  const r = new Reader(doc);
  const root = new Fields(r, "_root", "", "the root");
  const rootProblems: SectionProblem[] = [];

  // §3: the profile, and one map per root container.
  const profiles = r.all("_root", "profile");
  if (profiles.length !== 1 || profiles[0]?.[0] !== "str" || profiles[0][1] !== SECTIONS_PROFILE_ID)
    rootProblems.push(
      problem(
        "INVALID_ROOT",
        "/profile",
        `profile must be the scalar string ${SECTIONS_PROFILE_ID}`,
      ),
    );
  const containers = new Map<string, string>();
  for (const key of ROOT_MAPS) {
    const obj = r.map("_root", key);
    if (obj === undefined)
      rootProblems.push(problem("INVALID_ROOT", `/${key}`, `${key} must be exactly one map (§3)`));
    else containers.set(key, obj);
  }
  const extensions = containers.get("extensions");
  if (extensions !== undefined) {
    root.extensions();
    rootProblems.push(...root.out);
  }

  // §4.1: the section map.
  const sectionObj = containers.get("section");
  let sectionId: string | undefined;
  let ready = false;
  if (sectionObj !== undefined) {
    const section = new Fields(r, sectionObj, "/section", "the section");
    section.required(["id", "title", "created_by", "children", "extensions"]);
    if (section.has("id"))
      section.scalar("id", isObjectId, "INVALID_OBJECT_ID", "is not a canonical UUIDv7 (§3)", true);
    if (section.has("title")) section.scalar("title", undefined, "INVALID_FIELD_TYPE", "", false);
    if (section.has("created_by")) section.createdBy();
    section.createdAt();
    if (section.has("children")) {
      const children = r.all(sectionObj, "children");
      if (children.length !== 1 || children[0]?.[0] !== "list")
        rootProblems.push(
          problem("INVALID_ROOT", "/section/children", "section.children must be one list (§3)"),
        );
      else section.list("children");
    }
    if (section.has("extensions")) section.extensions();
    // §12.1: ready is the scalar boolean true, or absent.
    const readyValues = r.all(sectionObj, "ready");
    if (readyValues.some((v) => v[0] !== "boolean" || v[1] !== true))
      section.out.push(
        problem("INVALID_FIELD_TYPE", "/section/ready", "ready must be the scalar boolean true"),
      );
    ready = readyValues.length > 0;
    rootProblems.push(...section.out);
    sectionId = r.str(sectionObj, "id");
  }

  const nodesObj = containers.get("nodes");
  const placementsObj = containers.get("placements");
  const objectsObj = containers.get("objects");
  const nodeKeys = nodesObj === undefined ? [] : r.keys(nodesObj);
  const placementKeys = placementsObj === undefined ? [] : r.keys(placementsObj);
  const objectKeys = objectsObj === undefined ? [] : r.keys(objectsObj);
  const nodeSet = new Set(nodeKeys);

  // §14.2, SOP §21: collisions. A key created concurrently twice holds two maps.
  const collisions = new Set<string>();
  for (const [obj, keys] of [
    [nodesObj, nodeKeys],
    [placementsObj, placementKeys],
    [objectsObj, objectKeys],
  ] as const)
    for (const k of keys) if (obj !== undefined && r.all(obj, k).length > 1) collisions.add(k);

  const kinds = new Map<string, NodeKind>();
  for (const k of nodeKeys) {
    const node = nodesObj === undefined ? undefined : r.map(nodesObj, k);
    const kind = node === undefined ? undefined : r.str(node, "kind");
    if (kind !== undefined && isNodeKind(kind)) kinds.set(k, kind);
  }

  // Objects: SOP Tasks and preserved unknown Shared Objects (§2, §3).
  const objects = new Map<string, readonly ProfileProblem[]>();
  for (const k of objectKeys) {
    if (objectsObj === undefined || collisions.has(k)) continue;
    const values = r.all(objectsObj, k);
    if (values[0]?.[0] !== "map") {
      objects.set(k, [
        Object.freeze({
          code: "PROFILE_INVALID",
          diagnostic: "INVALID_FIELD_TYPE",
          pointer: ref("/objects", k),
          message: "a Shared Object must be a map",
        }),
      ]);
      continue;
    }
    const stored = (doc as Record<string, Record<string, Record<string, unknown>>>).objects?.[k];
    const problems = stored === undefined ? [] : storedObjectProblems(doc, stored, k);
    if (problems.length > 0) objects.set(k, Object.freeze(problems));
  }

  // §4.3: placements.
  const placements = new Map<string, SectionProblem>();
  for (const k of placementKeys) {
    if (placementsObj === undefined || collisions.has(k)) continue;
    const at = ref("/placements", k);
    const obj = r.map(placementsObj, k);
    const out: SectionProblem[] = [];
    if (!isObjectId(k))
      out.push(problem("INVALID_OBJECT_ID", at, "a PlacementId key is not a canonical UUIDv7"));
    if (obj === undefined) {
      out.push(problem("INVALID_FIELD_TYPE", at, "a placement must be a map (§4.3)"));
    } else {
      const f = new Fields(r, obj, at, "a placement");
      f.required(["id", "node_id", "parent_id", "created_by"]);
      if (f.has("id")) f.id(k);
      for (const field of ["node_id", "parent_id"])
        if (f.has(field))
          f.scalar(field, isObjectId, "INVALID_OBJECT_ID", "is not a canonical UUIDv7", true);
      if (f.has("created_by")) f.createdBy();
      out.push(...f.out);
      const node = r.str(obj, "node_id");
      const parent = r.str(obj, "parent_id");
      if (out.length === 0) {
        if (node === undefined || !nodeSet.has(node))
          out.push(problem("INVALID_REFERENCE", ref(at, "node_id"), "node_id names no node"));
        if (parent === undefined || (parent !== sectionId && !nodeSet.has(parent)))
          out.push(
            problem(
              "INVALID_REFERENCE",
              ref(at, "parent_id"),
              "parent_id names no node or section",
            ),
          );
      }
    }
    const p = first(out);
    if (p !== undefined) placements.set(k, p);
  }

  // §14.2: a node whose own ID (a Task node's is its Task ID) or selected
  // PlacementId collides is not validated.
  const collided = new Set(
    nodeKeys.filter((k) => {
      if (collisions.has(k)) return true;
      const node = nodesObj === undefined ? undefined : r.map(nodesObj, k);
      const selected = node === undefined ? [] : r.all(node, "placement");
      return selected.length === 1 && collisions.has(selected[0]?.[1] as string);
    }),
  );

  // §4.2: nodes, then their references.
  const nodes = new Map<string, SectionProblem>();
  const placementOf = (id: string) =>
    placementsObj === undefined ? undefined : r.map(placementsObj, id);
  for (const k of nodeKeys) {
    if (nodesObj === undefined || collided.has(k)) continue;
    const at = ref("/nodes", k);
    const obj = r.map(nodesObj, k);
    const out: SectionProblem[] = [];
    if (!isObjectId(k))
      out.push(problem("INVALID_OBJECT_ID", at, "a NodeId key is not a canonical UUIDv7"));
    if (obj === undefined) {
      out.push(problem("INVALID_FIELD_TYPE", at, "a node must be a map (§4.2)"));
      nodes.set(k, first(out) as SectionProblem);
      continue;
    }
    const f = new Fields(r, obj, at, "a node");
    const kind = kinds.get(k);
    f.required(["id", "kind", "created_by", "lifecycle", "placement", "children", "extensions"]);
    if (kind === "task") f.required(["task_id"]);
    if (kind !== undefined && TEXT_KINDS.has(kind)) f.required(["text"]);
    if (f.has("id")) f.id(k);
    if (f.has("kind"))
      f.scalar(
        "kind",
        isNodeKind,
        "INVALID_ENUM_VALUE",
        "is not task, paragraph, item or raw (§4.2)",
        true,
      );
    if (f.has("created_by")) f.createdBy();
    f.createdAt();
    if (f.has("lifecycle"))
      f.scalar(
        "lifecycle",
        (s) => (kind === "task" ? s === "active" : LIFECYCLES.has(s)),
        "INVALID_ENUM_VALUE",
        kind === "task"
          ? "of a task node is always active; its Task holds the lifecycle (§4.2)"
          : "is not active or deleted (§9)",
        false,
      );
    if (f.has("placement"))
      f.scalar(
        "placement",
        isObjectId,
        "INVALID_OBJECT_ID",
        "is not a canonical UUIDv7 PlacementId",
        false,
      );
    if (f.has("children")) f.list("children");
    if (f.has("extensions")) f.extensions();
    // task_id on task nodes only, equal to the node's ID.
    if (f.has("task_id")) {
      if (kind !== undefined && kind !== "task")
        f.out.push(
          problem("INVALID_FIELD_TYPE", ref(at, "task_id"), "only a task node has task_id (§4.2)"),
        );
      else {
        f.scalar("task_id", isObjectId, "INVALID_OBJECT_ID", "is not a canonical UUIDv7", true);
        const taskId = r.str(obj, "task_id");
        if (taskId !== undefined && isObjectId(taskId) && taskId !== k)
          f.out.push(
            problem(
              "OBJECT_ID_MISMATCH",
              ref(at, "task_id"),
              "a task node's ID differs from its task_id (§4.2)",
            ),
          );
      }
    }
    // text: collaborative Text on paragraph, item and raw nodes; absent on task nodes.
    const texts = r.all(obj, "text");
    if (kind === "task" && texts.length > 0)
      f.out.push(problem("INVALID_FIELD_TYPE", ref(at, "text"), "a task node has no text (§4.2)"));
    else if (texts.some((v) => v[0] !== "text"))
      f.out.push(
        problem("INVALID_FIELD_TYPE", ref(at, "text"), "text must be collaborative Text (§4.2)"),
      );
    // list_style on task and item nodes only.
    if (f.has("list_style")) {
      if (kind === "paragraph" || kind === "raw")
        f.out.push(
          problem(
            "INVALID_FIELD_TYPE",
            ref(at, "list_style"),
            "only task and item nodes have list_style (§4.2)",
          ),
        );
      else
        f.scalar(
          "list_style",
          (s) => (LIST_STYLES as readonly string[]).includes(s),
          "INVALID_ENUM_VALUE",
          "is not bullet or ordered (§4.2)",
          false,
        );
    }
    out.push(...f.out);

    // §14.2 references, for an otherwise valid node.
    if (out.length === 0) {
      if (kind === "task") {
        const task = objectsObj === undefined ? undefined : r.map(objectsObj, k);
        const taskProblems = objects.get(k);
        if (task === undefined || r.str(task, "type") !== "task")
          out.push(
            problem("INVALID_REFERENCE", ref(at, "task_id"), "task_id names no Task (§4.2)"),
          );
        else if (taskProblems !== undefined && taskProblems.length > 0) {
          // §14.2: a Task whose object is invalid isolates its Task node the same way.
          const worst = [...taskProblems].sort(
            (a, b) =>
              SECTION_DIAGNOSTIC_ORDER.indexOf(a.diagnostic as SectionDiagnostic) -
              SECTION_DIAGNOSTIC_ORDER.indexOf(b.diagnostic as SectionDiagnostic),
          )[0] as ProfileProblem;
          out.push(
            problem(
              worst.diagnostic as SectionDiagnostic,
              worst.pointer,
              `its Task is invalid: ${worst.message}`,
            ),
          );
        }
      }
      // Only an unconflicted placement selects a parent (§7); a conflict is a fact, not a problem.
      const selected = r.all(obj, "placement");
      if (selected.length === 1) {
        const pid = selected[0]?.[1] as string;
        const placement = placementOf(pid);
        if (placement === undefined || placements.has(pid))
          out.push(
            problem(
              "INVALID_REFERENCE",
              ref(at, "placement"),
              "placement names no valid placement",
            ),
          );
        else if (r.str(placement, "node_id") !== k)
          out.push(
            problem("INVALID_REFERENCE", ref(at, "placement"), "placement belongs to another node"),
          );
        else {
          const parent = r.str(placement, "parent_id") as string;
          // Under a collided parent the node is blocked (§7), not invalid.
          if (parent !== sectionId && !collided.has(parent)) {
            const parentKind = kinds.get(parent);
            if (parentKind === undefined || !PARENT_KINDS.has(parentKind))
              out.push(
                problem(
                  "INVALID_REFERENCE",
                  ref(at, "placement"),
                  "its parent cannot hold content (§4.2)",
                ),
              );
          }
        }
      }
    }
    const p = first(out);
    if (p !== undefined) nodes.set(k, p);
  }

  const state = rootProblems.length > 0 ? "invalid" : ready ? "ready" : "importing";
  return Object.freeze({
    state,
    problems: Object.freeze(rootProblems),
    sectionId,
    nodes,
    placements,
    objects,
    collisions: Object.freeze([...collisions].sort()),
    collided: Object.freeze([...collided].sort()),
  });
}
