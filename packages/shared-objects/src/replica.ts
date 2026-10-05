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
} from "./automerge-bytes.js";
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

/** Base fields (§23) and Task fields (§30) whose values are profile strings (G-SC3). */
const BASE_STRING_FIELDS = ["id", "type", "lifecycle", "created_by", "created_at"];
const TASK_STRING_FIELDS = ["title", "status", "due", "scheduled", "completion_date", "priority"];

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

/** A logical value as Automerge input: every string becomes a scalar string (G-SC3). */
function scalarize(value: Json): unknown {
  if (typeof value === "string") return scalarString(value);
  if (Array.isArray(value)) return value.map(scalarize);
  if (isMap(value))
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scalarize(v)]));
  return value;
}

/** An Automerge value as logical JSON: scalar strings and Text read as strings. */
function plain(value: unknown): Json {
  if (A.isImmutableString(value)) return value.toString();
  if (value instanceof A.Counter) return value.value;
  if (Array.isArray(value)) return value.map(plain);
  if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof Uint8Array) &&
    !(value instanceof Date)
  )
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  return value as Json;
}

/** Collaborative Text: in Automerge 3 JS a Text property reads as a plain JS string. */
const isText = (value: unknown): boolean => typeof value === "string";

const byJson = (a: Json, b: Json): number => {
  const [x, y] = [JSON.stringify(a), JSON.stringify(b)];
  return x < y ? -1 : x > y ? 1 : 0;
};

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

/** G-SC3 problems of one stored object: known string fields with a Text value. */
function textProblems(object: AMap, key: string): ProfileProblem[] {
  const fields =
    object.type !== undefined && plain(object.type) === "task"
      ? [...BASE_STRING_FIELDS, ...TASK_STRING_FIELDS]
      : BASE_STRING_FIELDS;
  return fields
    .filter((f) => valuesOf(object, f).some(isText))
    .map((f) =>
      // §30 (G-SC3)
      problem(
        "INVALID_FIELD_TYPE",
        `/objects/${pointerToken(key)}/${pointerToken(f)}`,
        `${f} is collaborative Text, not a scalar string (§30, G-SC3)`,
      ),
    );
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

function loadFailure(e: unknown, what: string): never {
  if (e instanceof LfcpError) throw e;
  throw new LfcpError("PROFILE_FRAMING", `${what}: ${(e as Error).message}`);
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

  /** Loads an Automerge full save (persisted state, or a Snapshot image, §13). Throws PROFILE_FRAMING. */
  static fromSave(save: Uint8Array, opts: ReplicaOptions): SharedObjectsReplica {
    checkSaveHeader(save);
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
    let waiting = [...changes].map(checkChange);
    for (let progress = true; progress && waiting.length > 0; ) {
      progress = false;
      const still: CheckedChange[] = [];
      for (const c of waiting) {
        const result = replica.receiveChange(c.bytes);
        if (result.status === "missing_dependencies") still.push(c);
        else progress = true;
      }
      waiting = still;
    }
    return { replica, unapplied: waiting };
  }

  /**
   * §14.1 (G-EP7): this replica rebuilt from its own changes minus
   * `exclude` (change hashes). Changes that depend on an excluded change are
   * unapplied too. If an excluded change is this actor's own, the rebuilt
   * replica refuses local writes (§9): its sequences are already used.
   */
  rebuildWithout(exclude: Iterable<string>): BuiltReplica {
    const out = new Set(exclude);
    const kept = A.getAllChanges(this.#doc).filter((c) => !out.has(A.decodeChange(c).hash));
    return SharedObjectsReplica.fromChanges(kept, {
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    });
  }

  /**
   * This replica merged with an Automerge full save (a loaded Snapshot,
   * §13): the save's document plus every change of this replica, so local
   * work the Snapshot does not hold is kept. The §9 sequence carries over.
   * Throws PROFILE_FRAMING when the save does not load.
   */
  mergeSave(save: Uint8Array): BuiltReplica {
    const merged = SharedObjectsReplica.fromSave(save, {
      resource: this.resource,
      principal: this.#principal,
      minSeq: Math.max(this.#minSeq, this.actorSeq),
    });
    const unapplied: CheckedChange[] = [];
    for (const change of this.changes()) {
      const r = merged.receiveChange(change);
      if (r.status === "missing_dependencies") unapplied.push(r.change);
    }
    return { replica: merged, unapplied };
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

  /** The logical root: scalar strings (and Text) read as strings. */
  root(): Json {
    return plain(this.#doc);
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
    if ("profile" in this.#doc && valuesOf(this.#doc, "profile").some(isText))
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
        ...textProblems(stored as AMap, id),
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

  #objectProblems(id: string, stored: AMap): ProfileProblem[] {
    const at = `/objects/${pointerToken(id)}`;
    const all = [
      ...objectProblems(plain(stored), id).filter((p) => p.pointer.startsWith(at)),
      ...textProblems(stored, id),
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

  /** §99: the Task under `id` with conflict metadata, or undefined if there is no object or it is not a Task. */
  task(id: string): TaskView | undefined {
    const objects = this.#objects();
    const stored = objects?.[id];
    if (objects === undefined || !isMap(stored as Json)) return undefined;
    const object = stored as AMap;
    if (plain(object.type) !== "task") return undefined;
    const collided = A.getConflicts(objects, id) !== undefined;
    const problems = this.#objectProblems(id, object);
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

    if (intent.intent === "task.create") {
      const task = intent.task as unknown as Record<string, Json>;
      const id = String(task.id);
      // §21: a local create never reuses an Object ID this replica already holds.
      if (id in objects) throw new ObjectIdCollisionError(id);
      const problems = objectProblems(task, id);
      if (problems.length > 0) throw new ProfileError(problems);
      return this.#commit(intent.intent, [id], (d) => {
        (d.objects as AMap)[id] = scalarize(task); // §53: the whole Task in one change
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
      ...textProblems(object, id).filter((p) => !touched.has(p.pointer.split("/").pop() as string)),
    ];
    if (problems.length > 0) throw new ProfileError(problems);
    return this.#commit(intent.intent, [id], (d) =>
      perform((d.objects as AMap)[id] as AMap, writes),
    );
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
    const checked = checkChange(bytes);
    if (checked.seq !== this.actorSeq + 1)
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `actor sequence ${checked.seq} after ${this.actorSeq} (§9)`,
      );
    this.#doc = next;
    this.#noteSeq(checked.actor, checked.seq);
    return Object.freeze({
      intent: message,
      change: checked.bytes,
      plaintext: frameProfilePayload(checked.bytes),
      hash: checked.hash,
      seq: checked.seq,
      objects: this.#objectChanges(before, "local", ids),
    });
  }

  /** §11: receives a Data Unit plaintext [1, change]. Throws PROFILE_FRAMING for invalid bytes. */
  receive(plaintext: Uint8Array): ReceiveResult {
    return this.#receive(unframeChange(plaintext));
  }

  /** Receives one bare Automerge change (persisted or reference bytes). */
  receiveChange(bytes: Uint8Array): ReceiveResult {
    return this.#receive(checkChange(bytes));
  }

  #receive(change: CheckedChange): ReceiveResult {
    if (A.hasHeads(this.#doc, [change.hash])) return Object.freeze({ status: "duplicate", change });
    const missing = change.deps.filter((d) => !A.hasHeads(this.#doc, [d]));
    if (missing.length > 0)
      return Object.freeze({
        status: "missing_dependencies",
        change,
        missing: Object.freeze(missing),
      });
    // Same actor and sequence, different change: an equivocation (or, for our
    // own actor, a lost-state fork, §9). Checked before Automerge sees it.
    if (change.seq <= (this.#seqs.get(change.actor) ?? 0))
      throw new LfcpError(
        "ACTOR_EQUIVOCATION",
        `actor ${change.actor} sequence ${change.seq} already has a different change (§26.2)`,
      );
    const before = A.getHeads(this.#doc);
    let next: Doc;
    try {
      [next] = A.applyChanges(this.#doc, [change.bytes]);
    } catch (e) {
      throw new LfcpError(
        "PROFILE_FRAMING",
        `Automerge rejected the change (§11): ${(e as Error).message}`,
      );
    }
    this.#doc = next;
    this.#noteSeq(change.actor, change.seq);
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
