import * as A from "@automerge/automerge";
import {
  fromHex,
  LfcpError,
  type ObjectId,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type CheckedChange,
  checkChange,
  checkSaveHeader,
  unframeChange,
  unframeSnapshot,
} from "./admission/framing.js";
import {
  checkSnapshotExpansion,
  MAX_DOCUMENT_DEPTH,
  SNAPSHOT_LIMITS_FLOOR,
  type SnapshotLimits,
} from "./admission/limits.js";
import { admitBatch, admitChange, type DocumentSequences } from "./admission/sequence.js";

/** The decoded actions that create an object (§11.2). */
const MAKE_ACTIONS: ReadonlySet<string> = new Set(["makeMap", "makeList", "makeText", "makeTable"]);

import { ProfileInvalidError } from "./profile-invalid.js";
import { ProfileError, parseTask, type Task, type TaskIntent } from "./task.js";
import {
  firstPerField,
  isMap,
  type Json,
  objectProblems,
  type ProfileProblem,
  pointerToken,
  type RootValidation,
  validateRoot,
} from "./validate.js";
import { deriveActorId, frameProfilePayload, PROFILE_ID } from "./values.js";

/**
 * The Automerge binding of SHARED-OBJECTS-PROFILE-01 (LFCP-031): one
 * Resource's replica of the org.openlfcp.shared-objects.v1 document.
 *
 * - The actor is always the §8 actor of (Resource, Principal), set
 *   explicitly; §9 actor state safety is enforced with `minSeq`.
 * - One semantic intent is exactly one Automerge change (§10, §12), with
 *   time 0 (informational, and a wall clock would leak edit times) and the
 *   intent name as message. An intent that changes nothing makes no change.
 * - Writes touch single properties only, so unknown fields, extension
 *   namespaces and object types survive (§70-§72). Objects are never
 *   removed: deletion is the lifecycle tombstone (§54-§56).
 * - Scalar conflicts stay visible (§44-§47) and are resolved by a new
 *   causal write (§69); tags and assignees are add-wins maps (§39-§43).
 *
 * Receiving is pure profile work: LFCP verification, decryption and
 * authorization come first (§95, LFCP-033).
 */

// §30 (G-SC3): every profile string is an Automerge scalar string
// (ImmutableString), never collaborative Text. Automerge 3 JS stores a plain
// JS string as Text, so writes wrap every string, and a known field found as
// Text is PROFILE_INVALID / INVALID_FIELD_TYPE.

// §58 (G-SC4): Automerge drops an assignment of the value already
// present, so an intent that writes deletes the property first when the value
// is unchanged: the intent is then a real concurrent write (add-wins, conflicts)
// exactly as in the reference corpus generator.

/** The conflict-preserving scalar registers of a Task (§44). */
export const SCALAR_FIELDS = [
  "lifecycle",
  "title",
  "status",
  "due",
  "scheduled",
  "completion_date",
  "priority",
] as const;
export type ScalarField = (typeof SCALAR_FIELDS)[number];
const DATE_FIELDS = new Set<string>(["due", "scheduled", "completion_date"]);

/** RFC 6901: a reference token back to its key. */
const unescapeToken = (token: string): string => token.replace(/~1/g, "/").replace(/~0/g, "~");

/** §69 task.resolve_field_conflict: write `value` (null clears a date) after the merged conflicts. */
export interface ResolveFieldConflict {
  readonly intent: "task.resolve_field_conflict";
  readonly id: ObjectId;
  readonly field: ScalarField;
  readonly value: string | null;
}

export type ReplicaIntent = TaskIntent | ResolveFieldConflict;

/** task.resolve_field_conflict (§69). */
export function resolveFieldConflict(
  id: ObjectId,
  field: ScalarField,
  value: string | null,
): ResolveFieldConflict {
  if (!(SCALAR_FIELDS as readonly string[]).includes(field))
    throw new LfcpError("UNSUPPORTED_VALUE", `${field} is not a scalar register (§44)`);
  if (value === null && !DATE_FIELDS.has(field))
    throw new LfcpError("UNSUPPORTED_VALUE", `only a date field can be cleared (§36)`);
  return Object.freeze({ intent: "task.resolve_field_conflict", id, field, value });
}

/** §21: two concurrent objects under one Object ID: OBJECT_ID_COLLISION, a profile error of its own, not PROFILE_INVALID. */
export class ObjectIdCollisionError extends LfcpError {
  readonly objectId: string;
  constructor(objectId: string) {
    super("OBJECT_ID_COLLISION", `${objectId}: concurrent objects share this Object ID (§21)`);
    this.name = "ObjectIdCollisionError";
    this.objectId = objectId;
  }
}

/** §99: a scalar register's provisional value and every concurrent value. */
export interface ScalarView {
  /** Automerge's deterministic visible value; provisional while conflicted. Undefined when absent. */
  readonly value: Json | undefined;
  /** Every concurrent value, sorted by JSON: none when absent, one when resolved. */
  readonly values: readonly Json[];
  readonly conflicted: boolean;
}

export type ObjectStatus = "ready" | "profile_invalid" | "object_id_collision";

/** §99: a Task with its conflict metadata. */
export interface TaskView {
  readonly id: string;
  readonly status: ObjectStatus;
  readonly problems: readonly ProfileProblem[];
  /** The provisional Task, when every visible value is valid. */
  readonly task: Task | undefined;
  readonly fields: { readonly [F in ScalarField]: ScalarView };
  readonly tags: readonly string[];
  readonly assignees: readonly string[];
}

/** §100: what one change did to one object. */
export interface ObjectChange {
  readonly resource: ResourceId;
  readonly objectId: string;
  readonly objectType: string | undefined;
  /** Top-level fields written, sorted. */
  readonly fields: readonly string[];
  readonly conflictsAppeared: readonly string[];
  readonly conflictsDisappeared: readonly string[];
  /** "rebuild": the state was rebuilt without some changes (§14.1, G-EP7). */
  readonly origin: "local" | "remote" | "rebuild";
}

/** A local intent's Automerge change, ready to become a Data Unit. */
export interface LocalChange {
  readonly intent: string;
  /** The exact Automerge change bytes. */
  readonly change: Uint8Array;
  /** §11: the Data Unit plaintext [1, change]. */
  readonly plaintext: Uint8Array;
  readonly hash: string;
  readonly seq: number;
  readonly objects: readonly ObjectChange[];
}

/**
 * The outcome of receiving one change. A change whose dependencies are not
 * all here is not applied and not invalid: the caller buffers it and offers
 * it again later (LFCP-033).
 */
export type ReceiveResult =
  | {
      readonly status: "applied";
      readonly change: CheckedChange;
      readonly objects: readonly ObjectChange[];
    }
  | { readonly status: "duplicate"; readonly change: CheckedChange }
  | {
      readonly status: "missing_dependencies";
      readonly change: CheckedChange;
      readonly missing: readonly string[];
    };

/**
 * The outcome of receiving many changes at once (receiveChanges): the
 * changes merged, those already held, those still missing a dependency
 * (not handed to Automerge, §14.1), and those refused with their error.
 */
export interface BatchReceiveResult {
  readonly applied: readonly CheckedChange[];
  readonly duplicates: readonly CheckedChange[];
  readonly waiting: readonly CheckedChange[];
  readonly refused: readonly { readonly change: CheckedChange; readonly error: LfcpError }[];
  /** §100 notifications for everything the batch changed. */
  readonly objects: readonly ObjectChange[];
}

/** Root validation plus §21 collisions and the G-SC3 scalar-string rule. */
export interface ReplicaValidation extends RootValidation {
  /** Object IDs with concurrent objects (OBJECT_ID_COLLISION, §21). */
  readonly collisions: readonly string[];
}

export interface ReplicaOptions {
  readonly resource: ResourceId;
  /** The writing Principal; with the Resource it fixes the §8 actor. */
  readonly principal: PrincipalId;
  /**
   * §9: the highest change sequence this actor is known to have used
   * (persisted by the caller, LFCP-035). If the loaded state is behind it,
   * local writes are refused: they would start an unrelated history under
   * sequences already used.
   */
  readonly minSeq?: number;
}

/** A replica built from a change set; `unapplied` lacks dependencies in that set. */
export interface BuiltReplica {
  readonly replica: SharedObjectsReplica;
  readonly unapplied: readonly CheckedChange[];
}

type Doc = A.Doc<Record<string, unknown>>;
type AMap = Record<string, unknown>;

const scalarString = (s: string): A.ImmutableString => new A.ImmutableString(s);

/**
 * A logical value as Automerge input: every string becomes a scalar string
 * (G-SC3). `depth` is the depth of `value` if it is a map or list (an
 * object's field value is depth 1, §30); a writer never nests deeper than
 * MAX_VALUE_DEPTH, and checking here keeps Automerge from ever building a
 * deep value (§11.2: deep nesting can trap its wasm module).
 */
function scalarize(value: Json, depth = 1): unknown {
  if (typeof value === "string") return scalarString(value);
  const nested = Array.isArray(value) || isMap(value);
  if (nested && depth > MAX_VALUE_DEPTH)
    throw new ProfileError([
      problem(
        "INVALID_FIELD_TYPE",
        "",
        `a value nests maps or lists deeper than ${MAX_VALUE_DEPTH} levels (§30)`,
      ),
    ]);
  if (Array.isArray(value)) return value.map((v) => scalarize(v, depth + 1));
  if (isMap(value))
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scalarize(v, depth + 1)]));
  return value;
}

/** §30: an object's maps and lists nest at most this many levels (the field's own map is 1). */
export const MAX_VALUE_DEPTH = 64;
/** Maps and lists plain() reads, the first included: the root, `objects` and an object map plus MAX_VALUE_DEPTH. */
const MAX_READ_DEPTH = MAX_VALUE_DEPTH + 3;

/**
 * An Automerge value as logical JSON: scalar strings and Text read as
 * strings. Reads at most `budget` nested maps and lists; a deeper one reads
 * as null, so a crafted document cannot exhaust the stack (§30: it is
 * INVALID_FIELD_TYPE, reported by textProblems).
 */
function plain(value: unknown, budget = MAX_READ_DEPTH): Json {
  if (A.isImmutableString(value)) return value.toString();
  if (value instanceof A.Counter) return value.value;
  const nested =
    value !== null &&
    typeof value === "object" &&
    !(value instanceof Uint8Array) &&
    !(value instanceof Date);
  if (nested && budget <= 0) return null;
  if (Array.isArray(value)) return value.map((v) => plain(v, budget - 1));
  if (nested)
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v, budget - 1)]));
  return value as Json;
}

/**
 * Whether any concurrent value of `map[key]` is collaborative Text (G-SC3).
 *
 * Not from the JS values: Automerge 3.5.0 reads a Text property as a plain
 * JS string, and getConflicts returns a concurrent scalar ImmutableString as
 * a plain JS string too (verified empirically), so `typeof` cannot tell them
 * apart once a field is conflicted. The backend's getAll lists every
 * concurrent value with its datatype: ["str", value, opId] for a scalar
 * string and ["text", objId] for a Text object, conflicted or not.
 */
function hasTextValue(doc: Doc, map: AMap, key: string): boolean {
  const obj = A.getObjectId(map);
  if (obj === null) return false;
  return A.getBackend(doc)
    .getAll(obj, key, A.getHeads(doc))
    .some((v) => v[0] === "text");
}

const byJson = (a: Json, b: Json): number => {
  const [x, y] = [JSON.stringify(a), JSON.stringify(b)];
  return x < y ? -1 : x > y ? 1 : 0;
};

/**
 * The same JSON with object keys in a canonical order (UTF-16 code unit
 * order, at every level; arrays keep their order). Automerge's property
 * order depends on history: after a G-SC4 delete+put the writer and a
 * receiver list the same keys in different orders, so only a canonical form
 * makes JSON of the logical state comparable across replicas.
 */
function canonical(value: Json): Json {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((k) => [k, canonical((value as Record<string, Json>)[k] as Json)]),
    );
  return value;
}

/** Every concurrent value of `map[key]`: none if absent, one if not conflicted. */
function valuesOf(map: AMap, key: string): unknown[] {
  if (!(key in map)) return [];
  const conflicts = A.getConflicts(map, key);
  return conflicts === undefined ? [map[key]] : Object.values(conflicts);
}

/** Top-level fields of `object` with more than one concurrent value. */
function conflictedFields(object: AMap): string[] {
  return Object.keys(object)
    .filter((f) => A.getConflicts(object, f) !== undefined)
    .sort();
}

const problem = (
  diagnostic: ProfileProblem["diagnostic"],
  pointer: string,
  message: string,
): ProfileProblem => Object.freeze({ code: "PROFILE_INVALID", diagnostic, pointer, message });

/**
 * §30, §74.1 (SO-STRINGS): every collaborative Text value anywhere in one
 * stored object (known and unknown fields, `extensions`, nested maps,
 * lists by index, every concurrent value) is INVALID_FIELD_TYPE at its own
 * JSON Pointer. Read from the backend's getAll datatypes (see hasTextValue):
 * "text" is Text, "str" a scalar string.
 */
function textProblems(doc: Doc, object: AMap, key: string): ProfileProblem[] {
  const obj = A.getObjectId(object);
  if (obj === null) return [];
  const backend = A.getBackend(doc);
  const heads = A.getHeads(doc);
  const out: ProfileProblem[] = [];
  // `depth` is the depth of the maps and lists found under this one: the
  // object's field values are at depth 1 (§30).
  const scan = (id: string, kind: "map" | "list", at: string, depth: number): void => {
    const props: (string | number)[] =
      kind === "list"
        ? Array.from({ length: backend.length(id, heads) }, (_, i) => i)
        : backend.keys(id, heads);
    for (const prop of props) {
      const here = `${at}/${pointerToken(String(prop))}`;
      const values = backend.getAll(id, prop, heads);
      const nested = values.filter((v) => v[0] === "map" || v[0] === "list");
      if (values.some((v) => v[0] === "text"))
        out.push(
          problem("INVALID_FIELD_TYPE", here, "collaborative Text, not a scalar string (§30)"),
        );
      else if (nested.length > 0 && depth > MAX_VALUE_DEPTH)
        out.push(
          problem("INVALID_FIELD_TYPE", here, `nested deeper than ${MAX_VALUE_DEPTH} levels (§30)`),
        );
      if (depth > MAX_VALUE_DEPTH) continue; // nothing below it is examined
      for (const v of nested) scan(v[1] as string, v[0] as "map" | "list", here, depth + 1);
    }
  };
  scan(obj, "map", `/objects/${pointerToken(key)}`, 1);
  return out;
}

/** Problems of the non-visible concurrent values of a Task's scalar registers (§45). */
function conflictValueProblems(object: AMap, key: string): ProfileProblem[] {
  const visible = plain(object) as Record<string, Json>;
  const out: ProfileProblem[] = [];
  for (const field of SCALAR_FIELDS) {
    const conflicts = A.getConflicts(object, field);
    if (conflicts === undefined) continue;
    for (const v of Object.values(conflicts)) {
      const at = `/objects/${pointerToken(key)}/${field}`;
      out.push(
        ...objectProblems({ ...visible, [field]: plain(v) }, key).filter(
          (p) =>
            p.pointer === at &&
            !out.some((q) => q.pointer === p.pointer && q.diagnostic === p.diagnostic),
        ),
      );
    }
  }
  return out;
}

/**
 * §99: the Task under `id` of `objects` (the document's `objects` map) with
 * conflict metadata, or undefined if there is no object or it is not a Task.
 * Shared by the Shared Objects and the Shared Sections replicas.
 */
export function taskView(
  doc: A.Doc<unknown>,
  objects: AMap | undefined,
  id: string,
): TaskView | undefined {
  const stored = objects?.[id];
  if (objects === undefined || !isMap(stored as Json)) return undefined;
  const object = stored as AMap;
  if (plain(object.type) !== "task") return undefined;
  const collided = A.getConflicts(objects, id) !== undefined;
  const problems = storedObjectProblems(doc, object, id);
  const parsed = parseTask(plain(object), id);
  const field = (f: string): ScalarView => {
    const values = valuesOf(object, f).map(plain).sort(byJson);
    return Object.freeze({
      value: f in object ? plain(object[f]) : undefined,
      values: Object.freeze(values),
      conflicted: values.length > 1,
    });
  };
  const keys = (f: string): string[] =>
    isMap(plain(object[f])) ? Object.keys(plain(object[f]) as object).sort() : [];
  return Object.freeze({
    id,
    status: collided ? "object_id_collision" : problems.length > 0 ? "profile_invalid" : "ready",
    problems: Object.freeze(problems),
    task: parsed.valid ? parsed.task : undefined,
    fields: Object.freeze(
      Object.fromEntries(SCALAR_FIELDS.map((f) => [f, field(f)])),
    ) as TaskView["fields"],
    tags: Object.freeze(keys("tags")),
    assignees: Object.freeze(keys("assignees")),
  });
}

/**
 * §74.1 problems of one object as stored at `/objects/<id>` of `doc`: its
 * logical values, every collaborative Text in it (§30) and every concurrent
 * value of its scalar registers (§45), one diagnostic per field. Shared by
 * every profile whose Tasks are SOP Tasks (SHARED-SECTIONS-PROFILE-01 §2).
 */
export function storedObjectProblems(
  doc: A.Doc<unknown>,
  stored: AMap,
  id: string,
): ProfileProblem[] {
  const at = `/objects/${pointerToken(id)}`;
  const all = [
    ...objectProblems(plain(stored), id).filter((p) => p.pointer.startsWith(at)),
    ...textProblems(doc as Doc, stored, id),
    ...conflictValueProblems(stored, id),
  ];
  // §74.1: one diagnostic per field, the first in table order over every value.
  return firstPerField(
    all.filter(
      (p, i) =>
        all.findIndex((q) => q.pointer === p.pointer && q.diagnostic === p.diagnostic) === i,
    ),
    at,
  );
}

/** A Task intent checked against the stored objects, ready to write inside a change. */
export interface PreparedTaskIntent {
  /** The Task it writes. */
  readonly id: string;
  /** Writes the intent into the `objects` map of a change's document. */
  readonly perform: (objects: Record<string, unknown>) => void;
}

/**
 * Checks one Task intent against `objects`, the stored objects map of
 * `doc`, before anything is written: §21 no reuse of an Object ID on
 * create, §74 the Task after the intent is valid, and no Text left in a
 * field it writes. Throws ProfileError or ObjectIdCollisionError. Shared by
 * every profile whose Tasks are SOP Tasks (SHARED-SECTIONS-PROFILE-01 §2).
 */
export function prepareTaskIntent(
  doc: A.Doc<unknown>,
  objects: Record<string, unknown>,
  intent: ReplicaIntent,
): PreparedTaskIntent {
  if (intent.intent === "task.create") {
    const task = intent.task as unknown as Record<string, Json>;
    const id = String(task.id);
    // §21: a local create never reuses an Object ID this replica already holds.
    if (id in objects) throw new ObjectIdCollisionError(id);
    const problems = objectProblems(task, id);
    if (problems.length > 0) throw new ProfileError(problems);
    return Object.freeze({
      id,
      perform: (o: Record<string, unknown>) => {
        o[id] = scalarize(task, 0); // §53: the whole Task in one change (the object map is depth 0)
      },
    });
  }

  const id = intent.id;
  const stored = objects[id];
  if (!isMap(stored as Json)) throw new ProfileError(objectProblems(undefined, id));
  if (A.getConflicts(objects, id) !== undefined) throw new ObjectIdCollisionError(id);
  const object = stored as AMap;
  const writes = writesOf(intent);
  const touched = new Set(
    writes.map((w) => (w.op === "put" || w.op === "delete" ? w.field : w.set)),
  );
  const next = candidate(plain(object) as Record<string, Json>, writes);
  const problems = [
    ...(next.type === "task"
      ? objectProblems(next, id)
      : [problem("INVALID_FIELD_TYPE", `/objects/${pointerToken(id)}/type`, "not a Task (§25)")]),
    // Text in a field this intent writes is replaced by the write.
    ...textProblems(doc as Doc, object, id).filter(
      (p) => !touched.has(unescapeToken(p.pointer.split("/")[3] ?? "")),
    ),
  ];
  if (problems.length > 0) throw new ProfileError(problems);
  return Object.freeze({
    id,
    perform: (o: Record<string, unknown>) => perform(o[id] as AMap, writes),
  });
}

/** One intent's writes on one object, in order. */
type Write =
  | { readonly op: "put"; readonly field: string; readonly value: Json }
  | { readonly op: "delete"; readonly field: string }
  | { readonly op: "add"; readonly set: "tags" | "assignees"; readonly key: string }
  | { readonly op: "remove"; readonly set: "tags" | "assignees"; readonly key: string };

function writesOf(intent: Exclude<ReplicaIntent, { intent: "task.create" }>): Write[] {
  const put = (field: string, value: Json): Write => ({ op: "put", field, value });
  const del = (field: string): Write => ({ op: "delete", field });
  switch (intent.intent) {
    case "task.set_title":
      return [put("title", intent.title)];
    case "task.set_status":
      return [put("status", intent.status)];
    case "task.complete": // §63
      return intent.completionDate === undefined
        ? [put("status", "done")]
        : [put("status", "done"), put("completion_date", intent.completionDate)];
    case "task.reopen": // §64
      return [put("status", "todo"), del("completion_date")];
    case "task.cancel": // §65
      return [put("status", "cancelled"), del("completion_date")];
    case "task.set_due":
      return [put("due", intent.date)];
    case "task.set_scheduled":
      return [put("scheduled", intent.date)];
    case "task.clear_due": // §36, §66: delete the property
      return [del("due")];
    case "task.clear_scheduled":
      return [del("scheduled")];
    case "task.set_priority":
      return [put("priority", intent.priority)];
    case "task.add_tag": // §67
      return [{ op: "add", set: "tags", key: intent.tag }];
    case "task.remove_tag":
      return [{ op: "remove", set: "tags", key: intent.tag }];
    case "task.add_assignee": // §68
      return [{ op: "add", set: "assignees", key: intent.assignee }];
    case "task.remove_assignee":
      return [{ op: "remove", set: "assignees", key: intent.assignee }];
    case "task.delete": // §54
      return [put("lifecycle", "deleted")];
    case "task.restore": // §55
      return [put("lifecycle", "active")];
    case "task.resolve_field_conflict": // §69
      return [intent.value === null ? del(intent.field) : put(intent.field, intent.value)];
  }
}

/** The logical object after `writes`, for validation before any change is made. */
function candidate(object: Record<string, Json>, writes: readonly Write[]): Record<string, Json> {
  const next: Record<string, Json> = { ...object };
  for (const w of writes) {
    if (w.op === "put") next[w.field] = w.value;
    else if (w.op === "delete") delete next[w.field];
    else {
      const set = { ...((isMap(next[w.set]) ? next[w.set] : {}) as Record<string, Json>) };
      if (w.op === "add") set[w.key] = true;
      else delete set[w.key];
      next[w.set] = set;
    }
  }
  return next;
}

/** Applies `writes` to the Automerge object map, inside a change. */
function perform(object: AMap, writes: readonly Write[]): void {
  for (const w of writes) {
    if (w.op === "delete") {
      if (w.field in object) delete object[w.field];
    } else if (w.op === "put") {
      // §58 (G-SC4): an unchanged value is deleted first so the intent writes.
      if (w.field in object && JSON.stringify(plain(object[w.field])) === JSON.stringify(w.value))
        delete object[w.field];
      object[w.field] = scalarize(w.value);
    } else {
      const set = object[w.set] as AMap;
      if (w.op === "add") {
        // §58 (G-SC4): a re-add is a fresh write, so it wins over a concurrent remove (§41, §43).
        if (w.key in set) delete set[w.key];
        set[w.key] = true;
      } else if (w.key in set) delete set[w.key];
    }
  }
}

const actorHex = (opts: ReplicaOptions): string =>
  toHex(deriveActorId(opts.resource, opts.principal));

/**
 * Whether a thrown value is a wasm trap (the engine's module is dead, not
 * the change refused): it is rethrown as it is, never turned into
 * INVALID_AUTOMERGE_BYTES, so a crash-loop breaker sees it.
 */
function isWasmTrap(e: unknown): boolean {
  const trap = (globalThis as { WebAssembly?: { RuntimeError?: abstract new () => unknown } })
    .WebAssembly?.RuntimeError;
  if (trap !== undefined && e instanceof trap) return true;
  return e instanceof Error && /\b(module|instance)\b.*\bterminated\b/i.test(e.message);
}

/**
 * Applies one change that passed the receive checks. Automerge can throw
 * after changing the document in place (a change that skips a sequence
 * number stays in its graph without its operations), so on any engine error
 * the handle is dropped: the document is rebuilt from the changes it held,
 * which must give back the heads it had. A wasm trap is rethrown as it
 * is: the module is dead, and only a restart recovers. Exported for tests.
 */
export function applyChecked(
  doc: Doc,
  bytes: Uint8Array,
): { readonly next: Doc } | { readonly restored: Doc; readonly error: Error } {
  const before = [...A.getHeads(doc)].sort().join();
  try {
    return { next: A.applyChanges(doc, [bytes])[0] };
  } catch (e) {
    if (isWasmTrap(e)) throw e;
    const error = e instanceof Error ? e : new Error(String(e));
    let restored: Doc;
    try {
      [restored] = A.applyChanges(A.init({ actor: A.getActorId(doc) }), A.getAllChanges(doc));
    } catch (r) {
      throw new Error(`the replica could not be restored after an Automerge error: ${String(r)}`);
    }
    if ([...A.getHeads(restored)].sort().join() !== before)
      throw new Error("the replica could not be restored after an Automerge error: heads differ");
    return { restored, error };
  }
}

/**
 * applyChecked for a batch of admitted changes, in one engine call. On any
 * engine error the handle is dropped and the document as it was before is
 * rebuilt from the changes it held minus the batch, checked against the
 * heads it had. Exported for tests.
 */
export function applyBatchChecked(
  doc: Doc,
  batch: readonly CheckedChange[],
): { readonly next: Doc } | { readonly restored: Doc; readonly error: Error } {
  const heads = A.getHeads(doc);
  try {
    return {
      next: A.applyChanges(
        doc,
        batch.map((c) => c.bytes),
      )[0],
    };
  } catch (e) {
    if (isWasmTrap(e)) throw e;
    const error = e instanceof Error ? e : new Error(String(e));
    return { restored: restoreWithout(doc, batch, heads), error };
  }
}

function restoreWithout(doc: Doc, batch: readonly CheckedChange[], heads: A.Heads): Doc {
  const out = new Set(batch.map((c) => c.hash));
  const kept = A.getAllChanges(doc).filter((c) => !out.has(A.decodeChange(c).hash));
  let restored: Doc;
  try {
    [restored] = A.applyChanges(A.init({ actor: A.getActorId(doc) }), kept);
  } catch (r) {
    throw new Error(`the replica could not be restored after an Automerge error: ${String(r)}`);
  }
  if ([...A.getHeads(restored)].sort().join() !== [...heads].sort().join())
    throw new Error("the replica could not be restored after an Automerge error: heads differ");
  return restored;
}

function loadFailure(e: unknown, what: string): never {
  if (e instanceof LfcpError) throw e;
  throw new ProfileInvalidError("INVALID_AUTOMERGE_BYTES", `${what}: ${(e as Error).message}`);
}

export class SharedObjectsReplica {
  readonly resource: ResourceId;
  /** The §8 Automerge actor ID. */
  readonly actorId: Uint8Array;
  readonly #principal: PrincipalId;
  readonly #actor: string;
  readonly #minSeq: number;
  #doc: Doc;
  /** Highest sequence seen per actor (hex). */
  readonly #seqs = new Map<string, number>();
  /** §11.2: known object depths (object ID → depth below the root), filled as objects appear. */
  readonly #depths = new Map<string, number>();
  /**
   * Conflicted fields per object, kept current on every change. Automerge
   * 3.5.0 getConflicts on an A.view reports the current conflicts, not those
   * at the view's heads, so the state before a change cannot be asked later.
   */
  readonly #conflicted = new Map<string, readonly string[]>();

  private constructor(doc: Doc, opts: ReplicaOptions) {
    this.resource = opts.resource;
    this.#principal = opts.principal;
    this.#actor = actorHex(opts);
    this.actorId = fromHex(this.#actor);
    this.#minSeq = opts.minSeq ?? 0;
    this.#doc = doc;
    for (const meta of A.getChangesMetaSince(doc, [])) this.#noteSeq(meta.actor, meta.seq);
    for (const [id, object] of Object.entries(this.#objects() ?? {}))
      if (isMap(object as Json)) this.#conflicted.set(id, conflictedFields(object as AMap));
  }

  /**
   * §11.2: the depths of the objects `change` creates (object ID → depth),
   * in operation order, given the objects of the document and `prior` (the
   * same batch). Refuses an object deeper than MAX_DOCUMENT_DEPTH, or one
   * written into an object the document does not have, before the engine.
   */
  /** The document as the admission module reads it (§14.1). */
  #sequences(): DocumentSequences {
    return {
      hasChange: (hash) => A.hasHeads(this.#doc, [hash]),
      latestSeq: (actor) => this.#seqs.get(actor) ?? 0,
    };
  }

  #createdDepths(change: CheckedChange, prior: ReadonlyMap<string, number>): Map<string, number> {
    const decoded = A.decodeChange(change.bytes);
    const created = new Map<string, number>();
    decoded.ops.forEach((op, i) => {
      if (!MAKE_ACTIONS.has(op.action)) return;
      const parent =
        op.obj === "_root"
          ? 0
          : (created.get(op.obj) ?? prior.get(op.obj) ?? this.#depthOf(op.obj));
      if (parent === undefined)
        throw new ProfileInvalidError(
          "INVALID_AUTOMERGE_BYTES",
          `the change writes into object ${op.obj}, which this document does not have (§11.2)`,
        );
      if (parent + 1 > MAX_DOCUMENT_DEPTH)
        throw new ProfileInvalidError(
          "INVALID_AUTOMERGE_BYTES",
          `the change creates an object deeper than ${MAX_DOCUMENT_DEPTH} levels (§11.2)`,
        );
      created.set(`${decoded.startOp + i}@${decoded.actor}`, parent + 1);
    });
    return created;
  }

  /**
   * The depth of an object of the document: cached, else its path (objects
   * never move, so the path of a live object has one element per level), else
   * (a deleted object) every object's depth from the history, once.
   */
  #depthOf(obj: string): number | undefined {
    const known = this.#depths.get(obj);
    if (known !== undefined) return known;
    let path: readonly unknown[] | undefined;
    try {
      path = A.getBackend(this.#doc).objInfo(obj as never).path;
    } catch {
      return undefined; // not an object of this document
    }
    if (path !== undefined) {
      this.#depths.set(obj, path.length);
      return path.length;
    }
    for (const bytes of A.getAllChanges(this.#doc)) {
      const c = A.decodeChange(bytes);
      c.ops.forEach((op, i) => {
        if (!MAKE_ACTIONS.has(op.action)) return;
        const parent = op.obj === "_root" ? 0 : this.#depths.get(op.obj);
        if (parent !== undefined) this.#depths.set(`${c.startOp + i}@${c.actor}`, parent + 1);
      });
    }
    return this.#depths.get(obj);
  }

  #noteSeq(actor: string, seq: number): void {
    if (seq > (this.#seqs.get(actor) ?? 0)) this.#seqs.set(actor, seq);
  }

  /** §16: a new Resource document. The initial change is the Resource's first Data Unit. */
  static create(opts: ReplicaOptions): { replica: SharedObjectsReplica; change: LocalChange } {
    const replica = SharedObjectsReplica.empty(opts);
    const change = replica.#commit("profile.init", [], (d) => {
      d.profile = scalarString(PROFILE_ID);
      d.objects = {};
      d.extensions = {};
    });
    if (change === null) throw new Error("profile.init made no change");
    return { replica, change };
  }

  /** A replica with no state yet, that receives the Resource's changes. */
  static empty(opts: ReplicaOptions): SharedObjectsReplica {
    return new SharedObjectsReplica(A.init({ actor: actorHex(opts) }), opts);
  }

  /**
   * Loads an Automerge full save: a received Snapshot image (§13), checked
   * against `limits` (§13.1, at least the floor) before Automerge loads it,
   * or this device's own persisted state ("local-state", not limited).
   * Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES.
   */
  static fromSave(
    save: Uint8Array,
    opts: ReplicaOptions,
    limits: SnapshotLimits | "local-state" = SNAPSHOT_LIMITS_FLOOR,
  ): SharedObjectsReplica {
    checkSaveHeader(save);
    if (limits !== "local-state") checkSnapshotExpansion(save, limits);
    let doc: Doc;
    try {
      doc = A.load(save, { actor: actorHex(opts) });
    } catch (e) {
      return loadFailure(e, "invalid Automerge save (§13)");
    }
    return new SharedObjectsReplica(doc, opts);
  }

  /** §13: loads a Snapshot plaintext [1, save]; later Data Units are received after it. */
  static fromSnapshot(plaintext: Uint8Array, opts: ReplicaOptions): SharedObjectsReplica {
    return SharedObjectsReplica.fromSave(unframeSnapshot(plaintext), opts);
  }

  /**
   * The replica of exactly an accepted change set: its state depends only
   * on the set, not on the order. Changes whose dependencies are not in the
   * set are returned as unapplied.
   */
  // §14.1 (G-EP7): replica state is a deterministic function of the set
  // of accepted changes, so a unit quarantined after it was merged can be taken
  // out by rebuilding (rebuildWithout). LFCP-033 drives it.
  static fromChanges(changes: Iterable<Uint8Array>, opts: ReplicaOptions): BuiltReplica {
    const replica = SharedObjectsReplica.empty(opts);
    const r = replica.receiveChanges([...changes].map(checkChange));
    const refused = r.refused[0];
    if (refused !== undefined) throw refused.error;
    return { replica, unapplied: r.waiting };
  }

  /**
   * §14.1 (G-EP7): this replica rebuilt from its own changes minus
   * `exclude` (change hashes). Changes that depend on an excluded change are
   * unapplied too. An excluded change of this actor is not lost state (§9):
   * the rebuilt replica writes on from its own sequence, reusing the
   * sequence numbers of the removed changes. A replica that was already
   * behind its persisted sequence stays refused.
   */
  rebuildWithout(exclude: Iterable<string>): BuiltReplica {
    const out = new Set(exclude);
    const kept = A.getAllChanges(this.#doc).filter((c) => !out.has(A.decodeChange(c).hash));
    return SharedObjectsReplica.fromChanges(kept, {
      resource: this.resource,
      principal: this.#principal,
      minSeq: this.writable ? 0 : this.#minSeq,
    });
  }

  /**
   * This replica merged with an Automerge full save (a loaded Snapshot,
   * §13): the save's document plus every change of this replica, so local
   * work the Snapshot does not hold is kept. The §9 sequence carries over.
   * Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES when the save does not load.
   */
  mergeSave(save: Uint8Array): BuiltReplica {
    const merged = SharedObjectsReplica.fromSave(save, {
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    });
    const r = merged.receiveChanges(this.changes().map(checkChange));
    const refused = r.refused[0];
    if (refused !== undefined) throw refused.error;
    return { replica: merged, unapplied: r.waiting };
  }

  /** An empty replica of the same Resource and actor that keeps the §9 sequence (nothing reused). */
  emptied(): SharedObjectsReplica {
    return SharedObjectsReplica.empty({
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    });
  }

  /** The highest change sequence of this replica's own actor in its state. */
  get actorSeq(): number {
    return this.#seqs.get(this.#actor) ?? 0;
  }

  /** §9: false when the state is behind the persisted sequence, so local writes are refused. */
  get writable(): boolean {
    return this.actorSeq >= this.#minSeq;
  }

  /** Hex hashes of the current heads, sorted. */
  heads(): string[] {
    return [...A.getHeads(this.#doc)].sort();
  }

  hasChange(hash: string): boolean {
    return A.hasHeads(this.#doc, [hash]);
  }

  /** Every change of the state, dependencies first. */
  changes(): Uint8Array[] {
    return A.getAllChanges(this.#doc);
  }

  /** The Automerge full save of the state. */
  save(): Uint8Array {
    return A.save(this.#doc);
  }

  /** §13: the Snapshot plaintext [1, save]. */
  snapshot(): Uint8Array {
    return frameProfilePayload(this.save());
  }

  /**
   * The logical root: scalar strings (and Text) read as strings, object keys
   * in canonical order, so JSON.stringify(root()) is comparable across
   * replicas holding the same state.
   */
  root(): Json {
    return canonical(plain(this.#doc));
  }

  /** The logical object stored under `id` (its visible value), if any. */
  getObject(id: string): Json | undefined {
    const objects = this.#objects();
    return objects !== undefined && id in objects ? plain(objects[id]) : undefined;
  }

  objectIds(): string[] {
    return Object.keys(this.#objects() ?? {}).sort();
  }

  #objects(): AMap | undefined {
    const objects = this.#doc.objects;
    return objects !== null && typeof objects === "object" && !A.isImmutableString(objects)
      ? (objects as AMap)
      : undefined;
  }

  /** §45: every conflicted top-level field of every object, with its concurrent values sorted. */
  conflicts(): Record<string, Record<string, Json[]>> {
    const out: Record<string, Record<string, Json[]>> = {};
    const objects = this.#objects() ?? {};
    for (const [id, object] of Object.entries(objects)) {
      if (!isMap(object as Json)) continue;
      for (const field of conflictedFields(object as AMap)) {
        out[id] ??= {};
        out[id][field] = valuesOf(object as AMap, field)
          .map(plain)
          .sort(byJson);
      }
    }
    return out;
  }

  /** §21: Object IDs under which concurrent objects were created. */
  collisions(): string[] {
    const objects = this.#objects();
    if (objects === undefined) return [];
    return Object.keys(objects)
      .filter((id) => A.getConflicts(objects, id) !== undefined)
      .sort();
  }

  /** §73-§77 validation of the visible state, every concurrent scalar value and G-SC3, plus §21 collisions. */
  validate(): ReplicaValidation {
    const base = validateRoot(this.root());
    const extraRoot: ProfileProblem[] = [];
    // §30 (G-SC3): the root profile value is a scalar string too.
    if ("profile" in this.#doc && hasTextValue(this.#doc, this.#doc, "profile"))
      extraRoot.push(
        problem(
          "INVALID_ROOT",
          "/profile",
          "profile is collaborative Text, not a scalar string (G-SC3)",
        ),
      );
    const perObject = new Map(base.objects);
    const objects = this.#objects() ?? {};
    for (const [id, problems] of base.objects) {
      const stored = objects[id];
      if (!isMap(stored as Json)) continue;
      const more = [
        ...textProblems(this.#doc, stored as AMap, id),
        ...conflictValueProblems(stored as AMap, id),
      ].filter(
        (p) => !problems.some((q) => q.pointer === p.pointer && q.diagnostic === p.diagnostic),
      );
      // §74.1: one diagnostic per field, the first in table order over every value.
      perObject.set(
        id,
        Object.freeze(firstPerField([...problems, ...more], `/objects/${pointerToken(id)}`)),
      );
    }
    const rootProblems = base.problems.filter((p) => !p.pointer.startsWith("/objects/"));
    const all = [...rootProblems, ...extraRoot, ...[...perObject.values()].flat()];
    return Object.freeze({
      valid: all.length === 0,
      problems: Object.freeze(all),
      objects: perObject,
      collisions: Object.freeze(this.collisions()),
    });
  }

  /** §99: the Task under `id` with conflict metadata, or undefined if there is no object or it is not a Task. */
  task(id: string): TaskView | undefined {
    return taskView(this.#doc, this.#objects(), id);
  }

  /**
   * Applies one intent as exactly one Automerge change (§10) and returns it,
   * or null when the intent changes nothing (removing an absent tag,
   * clearing an absent date). The resulting object must be profile-valid;
   * an object already invalid or collided is not written (§76, §21) unless
   * the write repairs it.
   */
  apply(intent: ReplicaIntent): LocalChange | null {
    const objects = this.#objects();
    const rootProblems = validateRoot(this.root()).problems.filter(
      (p) => !p.pointer.startsWith("/objects/"),
    );
    if (objects === undefined || rootProblems.length > 0)
      throw new ProfileError(
        rootProblems.length > 0 ? rootProblems : [problem("INVALID_ROOT", "/", "no root (§15)")],
      );

    const prepared = prepareTaskIntent(this.#doc, objects, intent);
    return this.#commit(intent.intent, [prepared.id], (d) => prepared.perform(d.objects as AMap));
  }

  #commit(message: string, ids: readonly string[], fn: (d: AMap) => void): LocalChange | null {
    if (!this.writable)
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `the replica is at actor sequence ${this.actorSeq}, behind ${this.#minSeq} already used (§9)`,
      );
    if (A.getActorId(this.#doc) !== this.#actor)
      throw new Error("the document actor is not the §8 actor");
    const before = A.getHeads(this.#doc);
    const next = A.change(this.#doc, { message, time: 0 }, fn);
    if (A.getHeads(next).join() === before.join()) {
      this.#doc = next;
      return null;
    }
    const bytes = A.getLastLocalChange(next);
    if (bytes === undefined) throw new Error("Automerge made no local change");
    let checked: CheckedChange;
    let created: Map<string, number>;
    try {
      checked = checkChange(bytes);
      created = this.#createdDepths(checked, new Map());
    } catch (e) {
      // §11.1: a writer never emits a change over the limits. The handle
      // this replica held is outdated by A.change: rebuild it without the change.
      const hash = A.decodeChange(bytes).hash;
      this.#doc = A.applyChanges(
        A.init({ actor: this.#actor }),
        A.getAllChanges(next).filter((c) => A.decodeChange(c).hash !== hash),
      )[0];
      throw new LfcpError(
        "CHANGE_TOO_LARGE",
        `the transaction "${message}" is larger than one change may be (§11.1: ${(e as Error).message}); split it into several (§12)`,
      );
    }
    if (checked.seq !== this.actorSeq + 1)
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `actor sequence ${checked.seq} after ${this.actorSeq} (§9)`,
      );
    this.#doc = next;
    this.#noteSeq(checked.actor, checked.seq);
    for (const [id, d] of created) this.#depths.set(id, d);
    return Object.freeze({
      intent: message,
      change: checked.bytes,
      plaintext: frameProfilePayload(checked.bytes),
      hash: checked.hash,
      seq: checked.seq,
      objects: this.#objectChanges(before, "local", ids),
    });
  }

  /** §11: receives a Data Unit plaintext [1, change]. Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES for invalid bytes. */
  receive(plaintext: Uint8Array): ReceiveResult {
    return this.#receive(unframeChange(plaintext));
  }

  /** Receives one bare Automerge change (persisted or reference bytes). */
  receiveChange(bytes: Uint8Array): ReceiveResult {
    return this.#receive(checkChange(bytes));
  }

  /**
   * Receives many changes at once: store replay, catch-up, a Snapshot's
   * remainder. Same rules as receiveChange (§14.1: no change with a
   * missing dependency reaches Automerge; a taken sequence is
   * ACTOR_EQUIVOCATION; a skipped one INVALID_AUTOMERGE_BYTES), but the
   * admitted changes go to Automerge in ONE call: one change per call is
   * quadratic (10 000 changes: ~12 s against ~70 ms as one batch).
   *
   * The changes may come in any order, duplicated: each is admitted once
   * its dependencies inside the batch are (Kahn's order). A refused change
   * does not stop the others; changes that depend on it wait. If Automerge
   * fails anyway, the document is restored and the admitted changes are
   * received one at a time, which isolates the failing one.
   */
  receiveChanges(changes: Iterable<Uint8Array | CheckedChange>): BatchReceiveResult {
    const refused: { change: CheckedChange; error: LfcpError }[] = [];
    const all: CheckedChange[] = [];
    const seen = new Set<string>();
    for (const c of changes) {
      const checked = c instanceof Uint8Array ? checkChange(c) : c;
      if (seen.has(checked.hash)) continue;
      seen.add(checked.hash);
      all.push(checked);
    }
    // §11.1, §14.1 (the admission module both profiles share), then §11.2:
    // the depths of the objects a change creates, given the document and
    // the batch so far.
    const batchDepths = new Map<string, number>();
    const decided = admitBatch(all, this.#sequences(), (c) => {
      for (const [id, d] of this.#createdDepths(c, batchDepths)) batchDepths.set(id, d);
    });
    for (const r of decided.refused) refused.push({ change: r.change, error: r.error });
    const admitted = [...decided.admitted];
    const duplicates = [...decided.duplicates];
    const waiting = [...decided.waiting];
    const before = A.getHeads(this.#doc);
    let applied: CheckedChange[] = admitted;
    if (admitted.length > 0) {
      const batch = applyBatchChecked(this.#doc, admitted);
      if ("next" in batch) {
        this.#doc = batch.next;
        for (const c of admitted) this.#noteSeq(c.actor, c.seq);
        for (const [id, d] of batchDepths) this.#depths.set(id, d);
      } else {
        this.#doc = batch.restored;
        applied = [];
        for (const c of admitted) {
          try {
            const r = this.#receive(c);
            if (r.status === "applied") applied.push(c);
            else if (r.status === "missing_dependencies") waiting.push(c);
          } catch (e) {
            refused.push({
              change: c,
              error:
                e instanceof LfcpError
                  ? e
                  : new ProfileInvalidError("INVALID_AUTOMERGE_BYTES", String(e)),
            });
          }
        }
      }
    }
    return Object.freeze({
      applied: Object.freeze(applied),
      duplicates: Object.freeze(duplicates),
      waiting: Object.freeze(waiting),
      refused: Object.freeze(refused),
      objects: Object.freeze(applied.length > 0 ? this.#objectChanges(before, "remote") : []),
    });
  }

  #receive(change: CheckedChange): ReceiveResult {
    // §11.1, §14.1 before Automerge sees it (the admission module both
    // profiles share): Automerge 3.5.0 records a skipping change in its graph
    // without its operations, so the document no longer saves loadably
    // (automerge-rs 0.12 aborts), and aborts on an unknown actor. A taken
    // sequence is an equivocation (or, for our own actor, a lost-state fork, §9).
    const admission = admitChange(change, this.#sequences());
    if (admission.kind === "duplicate") return Object.freeze({ status: "duplicate", change });
    if (admission.kind === "missing")
      return Object.freeze({
        status: "missing_dependencies",
        change,
        missing: admission.missing,
      });
    if (admission.kind === "held" || admission.kind === "invalid") throw admission.error;
    // §11.2: no object deeper than MAX_DOCUMENT_DEPTH, before the engine.
    const created = this.#createdDepths(change, new Map());
    const before = A.getHeads(this.#doc);
    const applied = applyChecked(this.#doc, change.bytes);
    if ("error" in applied) {
      this.#doc = applied.restored;
      throw new ProfileInvalidError(
        "INVALID_AUTOMERGE_BYTES",
        `Automerge rejected the change (§11): ${applied.error.message}`,
      );
    }
    const next = applied.next;
    this.#doc = next;
    this.#noteSeq(change.actor, change.seq);
    for (const [id, d] of created) this.#depths.set(id, d);
    return Object.freeze({
      status: "applied",
      change,
      objects: this.#objectChanges(before, "remote"),
    });
  }

  /** §100 notifications for the objects changed since `before`. */
  #objectChanges(
    before: A.Heads,
    origin: "local" | "remote",
    hint: readonly string[] = [],
  ): ObjectChange[] {
    const after = A.getHeads(this.#doc);
    const fields = new Map<string, Set<string>>(hint.map((id) => [id, new Set<string>()]));
    for (const patch of A.diff(this.#doc, before, after)) {
      const [top, id, field] = patch.path;
      if (top !== "objects" || typeof id !== "string") continue;
      const set = fields.get(id) ?? new Set<string>();
      if (typeof field === "string") set.add(field);
      fields.set(id, set);
    }
    const objects = this.#objects() ?? {};
    const out: ObjectChange[] = [];
    for (const [id, set] of [...fields].sort(([a], [b]) => (a < b ? -1 : 1))) {
      const now = objects[id];
      if (!isMap(now as Json)) continue;
      if (set.size === 0) for (const f of Object.keys(now as AMap)) set.add(f);
      const nowConflicts = conflictedFields(now as AMap);
      const wasConflicts = this.#conflicted.get(id) ?? [];
      this.#conflicted.set(id, nowConflicts);
      out.push(
        Object.freeze({
          resource: this.resource,
          objectId: id,
          objectType:
            typeof plain((now as AMap).type) === "string"
              ? (plain((now as AMap).type) as string)
              : undefined,
          fields: Object.freeze([...set].sort()),
          conflictsAppeared: Object.freeze(nowConflicts.filter((f) => !wasConflicts.includes(f))),
          conflictsDisappeared: Object.freeze(
            wasConflicts.filter((f) => !nowConflicts.includes(f)),
          ),
          origin,
        }),
      );
    }
    return out;
  }
}
