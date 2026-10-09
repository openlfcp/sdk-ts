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

/**
 * Reads a document through the backend, at its current state (no heads: a
 * historical read is far slower). One validation asks for most fields more
 * than once (present? then its values, then the one string); each answer is
 * kept for the pass, which runs on one unchanging document.
 */
class Reader {
  readonly #backend: ReturnType<typeof A.getBackend>;
  readonly #values = new Map<string, Value[]>();

  constructor(doc: A.Doc<unknown>) {
    this.#backend = A.getBackend(doc);
  }

  all(obj: string, prop: string | number): Value[] {
    const key = `${obj}\u0000${prop}`;
    let values = this.#values.get(key);
    if (values === undefined) {
      values = this.#backend.getAll(obj, prop) as Value[];
      this.#values.set(key, values);
    }
    return values;
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

/**
 * What one validation reads, per entity: everything a node, a placement or
 * an object contributes that depends on its own subtree only, and the root
 * and section part. The checks across entities (references, collided
 * parents) are derived from these facts without reading the document.
 */
interface NodeFacts {
  readonly collides: boolean;
  /** The node's map when it has exactly one value, a map. */
  readonly map: string | undefined;
  readonly kind: NodeKind | undefined;
  /** The values of `placement` (one when not in conflict). */
  readonly selected: readonly Value[];
  /** The node's own problems, before its references are checked. */
  readonly local: readonly SectionProblem[];
}

interface PlacementFacts {
  readonly collides: boolean;
  readonly map: string | undefined;
  readonly local: readonly SectionProblem[];
  readonly nodeId: string | undefined;
  readonly parentId: string | undefined;
}

interface ObjectFacts {
  readonly collides: boolean;
  /** The object's map when it has exactly one value, a map. */
  readonly map: string | undefined;
  /** Its `type`, a scalar string, when it is one map. */
  readonly type: string | undefined;
  /** The object's problems (§2, SOP §74.1); undefined when it has none. */
  readonly problems: readonly ProfileProblem[] | undefined;
}

interface RootFacts {
  readonly problems: readonly SectionProblem[];
  readonly sectionId: string | undefined;
  readonly ready: boolean;
  readonly nodesObj: string | undefined;
  readonly placementsObj: string | undefined;
  readonly objectsObj: string | undefined;
}

interface Facts {
  readonly root: RootFacts;
  readonly nodeKeys: readonly string[];
  readonly placementKeys: readonly string[];
  readonly objectKeys: readonly string[];
  readonly nodes: ReadonlyMap<string, NodeFacts>;
  readonly placements: ReadonlyMap<string, PlacementFacts>;
  readonly objects: ReadonlyMap<string, ObjectFacts>;
}

function rootFacts(r: Reader): RootFacts {
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
  return {
    problems: rootProblems,
    sectionId,
    ready,
    nodesObj: containers.get("nodes"),
    placementsObj: containers.get("placements"),
    objectsObj: containers.get("objects"),
  };
}

function nodeFacts(r: Reader, nodesObj: string, k: string): NodeFacts {
  const collides = r.all(nodesObj, k).length > 1;
  const obj = r.map(nodesObj, k);
  const own = obj === undefined ? undefined : r.str(obj, "kind");
  const kind = own !== undefined && isNodeKind(own) ? own : undefined;
  const selected = obj === undefined ? [] : r.all(obj, "placement");
  const at = ref("/nodes", k);
  const out: SectionProblem[] = [];
  if (!isObjectId(k))
    out.push(problem("INVALID_OBJECT_ID", at, "a NodeId key is not a canonical UUIDv7"));
  if (obj === undefined) {
    out.push(problem("INVALID_FIELD_TYPE", at, "a node must be a map (§4.2)"));
    return { collides, map: obj, kind, selected, local: out };
  }
  const f = new Fields(r, obj, at, "a node");
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
  return { collides, map: obj, kind, selected, local: out };
}

function placementFacts(r: Reader, placementsObj: string, k: string): PlacementFacts {
  const collides = r.all(placementsObj, k).length > 1;
  const at = ref("/placements", k);
  const obj = r.map(placementsObj, k);
  const out: SectionProblem[] = [];
  if (!isObjectId(k))
    out.push(problem("INVALID_OBJECT_ID", at, "a PlacementId key is not a canonical UUIDv7"));
  if (obj === undefined) {
    out.push(problem("INVALID_FIELD_TYPE", at, "a placement must be a map (§4.3)"));
    return { collides, map: obj, local: out, nodeId: undefined, parentId: undefined };
  }
  const f = new Fields(r, obj, at, "a placement");
  f.required(["id", "node_id", "parent_id", "created_by"]);
  if (f.has("id")) f.id(k);
  for (const field of ["node_id", "parent_id"])
    if (f.has(field))
      f.scalar(field, isObjectId, "INVALID_OBJECT_ID", "is not a canonical UUIDv7", true);
  if (f.has("created_by")) f.createdBy();
  out.push(...f.out);
  return {
    collides,
    map: obj,
    local: out,
    nodeId: r.str(obj, "node_id"),
    parentId: r.str(obj, "parent_id"),
  };
}

function objectFacts(doc: A.Doc<unknown>, r: Reader, objectsObj: string, k: string): ObjectFacts {
  const values = r.all(objectsObj, k);
  const collides = values.length > 1;
  const map = r.map(objectsObj, k);
  const type = map === undefined ? undefined : r.str(map, "type");
  if (collides) return { collides, map, type, problems: undefined };
  // Objects: SOP Tasks and preserved unknown Shared Objects (§2, §3).
  if (values[0]?.[0] !== "map")
    return {
      collides,
      map,
      type,
      problems: [
        Object.freeze({
          code: "PROFILE_INVALID",
          diagnostic: "INVALID_FIELD_TYPE",
          pointer: ref("/objects", k),
          message: "a Shared Object must be a map",
        }),
      ],
    };
  const stored = (doc as Record<string, Record<string, Record<string, unknown>>>).objects?.[k];
  const problems = stored === undefined ? [] : storedObjectProblems(doc, stored, k);
  return {
    collides,
    map,
    type,
    problems: problems.length > 0 ? Object.freeze(problems) : undefined,
  };
}

/** Facts of every entity, or of the `dirty` ones over `base`, whose other entities are unchanged. */
function readFacts(
  doc: A.Doc<unknown>,
  base?: { readonly facts: Facts; readonly dirty: Dirty },
): Facts {
  const r = new Reader(doc);
  const root = rootFacts(r);
  const reuse =
    base !== undefined &&
    base.facts.root.nodesObj === root.nodesObj &&
    base.facts.root.placementsObj === root.placementsObj &&
    base.facts.root.objectsObj === root.objectsObj
      ? base
      : undefined;
  const nodeKeys = root.nodesObj === undefined ? [] : r.keys(root.nodesObj);
  const placementKeys = root.placementsObj === undefined ? [] : r.keys(root.placementsObj);
  const objectKeys = root.objectsObj === undefined ? [] : r.keys(root.objectsObj);
  const collect = <F>(
    keys: readonly string[],
    obj: string | undefined,
    old: ReadonlyMap<string, F> | undefined,
    dirty: ReadonlySet<string> | undefined,
    read: (obj: string, k: string) => F,
  ): Map<string, F> => {
    const out = new Map<string, F>();
    if (obj === undefined) return out;
    for (const k of keys) {
      const kept = dirty?.has(k) ? undefined : old?.get(k);
      out.set(k, kept ?? read(obj, k));
    }
    return out;
  };
  return {
    root,
    nodeKeys,
    placementKeys,
    objectKeys,
    nodes: collect(nodeKeys, root.nodesObj, reuse?.facts.nodes, reuse?.dirty.nodes, (o, k) =>
      nodeFacts(r, o, k),
    ),
    placements: collect(
      placementKeys,
      root.placementsObj,
      reuse?.facts.placements,
      reuse?.dirty.placements,
      (o, k) => placementFacts(r, o, k),
    ),
    objects: collect(
      objectKeys,
      root.objectsObj,
      reuse?.facts.objects,
      reuse?.dirty.objects,
      (o, k) => objectFacts(doc, r, o, k),
    ),
  };
}

/** The validation of a document from its facts: the checks across entities, in document order. */
function assemble(facts: Facts): SectionValidation {
  const { root, nodeKeys, placementKeys, objectKeys } = facts;
  const { sectionId } = root;
  const nodeSet = new Set(nodeKeys);

  // §14.2, SOP §21: collisions. A key created concurrently twice holds two maps.
  const collisions = new Set<string>();
  for (const [keys, of] of [
    [nodeKeys, facts.nodes],
    [placementKeys, facts.placements],
    [objectKeys, facts.objects],
  ] as const)
    for (const k of keys)
      if ((of as ReadonlyMap<string, { collides: boolean }>).get(k)?.collides) collisions.add(k);

  const kinds = new Map<string, NodeKind>();
  for (const k of nodeKeys) {
    const kind = facts.nodes.get(k)?.kind;
    if (kind !== undefined) kinds.set(k, kind);
  }

  const objects = new Map<string, readonly ProfileProblem[]>();
  for (const k of objectKeys) {
    const o = facts.objects.get(k);
    if (o === undefined || collisions.has(k)) continue;
    if (o.problems !== undefined) objects.set(k, o.problems);
  }

  // §4.3: placements.
  const placements = new Map<string, SectionProblem>();
  for (const k of placementKeys) {
    const p = facts.placements.get(k);
    if (p === undefined || collisions.has(k)) continue;
    const at = ref("/placements", k);
    const out = [...p.local];
    if (out.length === 0 && p.map !== undefined) {
      if (p.nodeId === undefined || !nodeSet.has(p.nodeId))
        out.push(problem("INVALID_REFERENCE", ref(at, "node_id"), "node_id names no node"));
      if (p.parentId === undefined || (p.parentId !== sectionId && !nodeSet.has(p.parentId)))
        out.push(
          problem("INVALID_REFERENCE", ref(at, "parent_id"), "parent_id names no node or section"),
        );
    }
    const worst = first(out);
    if (worst !== undefined) placements.set(k, worst);
  }

  // §14.2: a node whose own ID (a Task node's is its Task ID) or selected
  // PlacementId collides is not validated.
  const collided = new Set(
    nodeKeys.filter((k) => {
      if (collisions.has(k)) return true;
      const selected = facts.nodes.get(k)?.selected ?? [];
      return selected.length === 1 && collisions.has(selected[0]?.[1] as string);
    }),
  );

  // §4.2: nodes, then their references.
  const nodes = new Map<string, SectionProblem>();
  for (const k of nodeKeys) {
    const n = facts.nodes.get(k);
    if (n === undefined || collided.has(k)) continue;
    const at = ref("/nodes", k);
    const out = [...n.local];
    if (n.map === undefined) {
      nodes.set(k, first(out) as SectionProblem);
      continue;
    }

    // §14.2 references, for an otherwise valid node.
    if (out.length === 0) {
      if (n.kind === "task") {
        const task = facts.objects.get(k);
        const taskProblems = objects.get(k);
        if (task?.map === undefined || task.type !== "task")
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
      if (n.selected.length === 1) {
        const pid = n.selected[0]?.[1] as string;
        const placement = facts.placements.get(pid);
        if (placement?.map === undefined || placements.has(pid))
          out.push(
            problem(
              "INVALID_REFERENCE",
              ref(at, "placement"),
              "placement names no valid placement",
            ),
          );
        else if (placement.nodeId !== k)
          out.push(
            problem("INVALID_REFERENCE", ref(at, "placement"), "placement belongs to another node"),
          );
        else {
          const parent = placement.parentId as string;
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
    const worst = first(out);
    if (worst !== undefined) nodes.set(k, worst);
  }

  const state = root.problems.length > 0 ? "invalid" : root.ready ? "ready" : "importing";
  return Object.freeze({
    state,
    problems: Object.freeze([...root.problems]),
    sectionId,
    nodes,
    placements,
    objects,
    collisions: Object.freeze([...collisions].sort()),
    collided: Object.freeze([...collided].sort()),
  });
}

/** The entities a range of changes touched, by the patches of A.diff. */
interface Dirty {
  readonly nodes: ReadonlySet<string>;
  readonly placements: ReadonlySet<string>;
  readonly objects: ReadonlySet<string>;
}

/** Null when a patch is above an entity (a container replaced): read everything again. */
function dirtyOf(patches: readonly A.Patch[]): Dirty | null {
  const dirty = {
    nodes: new Set<string>(),
    placements: new Set<string>(),
    objects: new Set<string>(),
  };
  for (const p of patches) {
    const [container, key] = p.path;
    if (container === "nodes" || container === "placements" || container === "objects") {
      if (typeof key !== "string") return null;
      dirty[container].add(key);
    }
    // Any other path is the root or the section, read again on every validation.
  }
  return dirty;
}

/** Validations by document object, and the latest few by heads (a clone has the heads of its source). */
const byDoc = new WeakMap<object, SectionValidation>();
const byHeads = new Map<string, SectionValidation>();
/** The facts of the latest validations, to validate a later revision of one of them incrementally. */
const bases: { heads: A.Heads; facts: Facts }[] = [];
const KEPT = 8;

/**
 * Validates a section document (§3, §4, §14.2). Reads only; the document is
 * unchanged. A document's heads determine its content, so a validation is
 * computed once per heads: committing and then reading one revision (or a
 * clone of it) validates it once. A later revision of a document validated
 * before reads again only the nodes, placements and objects its changes
 * touched (A.diff); the checks across entities run in full each time.
 */
export function validateSection(doc: A.Doc<unknown>): SectionValidation {
  const known = byDoc.get(doc);
  if (known !== undefined) return known;
  const heads = A.getHeads(doc);
  const key = heads.slice().sort().join(",");
  let v = byHeads.get(key);
  if (v === undefined) {
    const facts = factsOf(doc, heads);
    v = assemble(facts);
    byHeads.set(key, v);
    if (byHeads.size > KEPT) byHeads.delete(byHeads.keys().next().value as string);
    bases.unshift({ heads, facts });
    if (bases.length > KEPT) bases.pop();
  }
  byDoc.set(doc, v);
  return v;
}

function factsOf(doc: A.Doc<unknown>, heads: A.Heads): Facts {
  for (const base of bases) {
    if (!A.hasHeads(doc, base.heads)) continue;
    const dirty = dirtyOf(A.diff(doc, base.heads, heads));
    if (dirty === null) break;
    return readFacts(doc, { facts: base.facts, dirty });
  }
  return readFacts(doc);
}

/** Validates without the per-revision cache and the incremental path: for tests. */
export function validateSectionInFull(doc: A.Doc<unknown>): SectionValidation {
  return assemble(readFacts(doc));
}
