import {
  generateObjectId,
  isObjectId,
  LfcpError,
  type ObjectId,
  type PrincipalId,
} from "@openlfcp/core";
import { isMap, type Json, objectProblems, type ProfileProblem } from "./validate.js";
import { isLocalDate, isPrincipalRef, type PrincipalRef, principalRef } from "./values.js";

/**
 * The version-1 Task (SHARED-OBJECTS-PROFILE-01 §23, §30-§43) over logical
 * state, and the §59 Task intents.
 *
 * A Task is its logical JSON object: the known fields typed, every other
 * field kept as is. Mutators never rebuild the object; they copy it and
 * change only the field the intent names, so unknown fields and extension
 * namespaces survive any mutation (§70-§72). Each mutator returns the new
 * state and the intent that produced it; the Automerge binding (LFCP-031)
 * maps intents to Automerge changes. Conflict state (several concurrent
 * values of a register, §45) only exists in the Automerge document, so
 * task.resolve_field_conflict is LFCP-031 work.
 */

export type TaskStatus = "todo" | "in_progress" | "done" | "cancelled" | `x/${string}`;
export type TaskPriority = "lowest" | "low" | "normal" | "high" | "highest" | `x/${string}`;

export interface Task {
  readonly id: ObjectId;
  readonly type: "task";
  readonly lifecycle: "active" | "deleted";
  readonly created_by: PrincipalRef;
  readonly created_at?: string;
  readonly title: string;
  readonly status: TaskStatus;
  readonly due?: string | null;
  readonly scheduled?: string | null;
  readonly completion_date?: string | null;
  readonly priority: TaskPriority;
  /** Add-wins set: tag -> true (§39). */
  readonly tags: { readonly [tag: string]: true };
  /** Add-wins set: Principal reference -> true (§42). */
  readonly assignees: { readonly [ref: string]: true };
  readonly extensions: { readonly [namespace: string]: Json };
  /** Unknown Task fields are preserved (§72). */
  readonly [unknown: string]: Json | undefined;
}

/** A §59 intent: what a mutation means, for the Automerge binding. */
export type TaskIntent =
  | { readonly intent: "task.create"; readonly task: Task }
  | { readonly intent: "task.set_title"; readonly id: ObjectId; readonly title: string }
  | { readonly intent: "task.set_status"; readonly id: ObjectId; readonly status: TaskStatus }
  | { readonly intent: "task.complete"; readonly id: ObjectId; readonly completionDate?: string }
  | { readonly intent: "task.reopen"; readonly id: ObjectId }
  | { readonly intent: "task.cancel"; readonly id: ObjectId }
  | {
      readonly intent: "task.set_due" | "task.set_scheduled";
      readonly id: ObjectId;
      readonly date: string;
    }
  | { readonly intent: "task.clear_due" | "task.clear_scheduled"; readonly id: ObjectId }
  | { readonly intent: "task.set_priority"; readonly id: ObjectId; readonly priority: TaskPriority }
  | {
      readonly intent: "task.add_tag" | "task.remove_tag";
      readonly id: ObjectId;
      readonly tag: string;
    }
  | {
      readonly intent: "task.add_assignee" | "task.remove_assignee";
      readonly id: ObjectId;
      readonly assignee: PrincipalRef;
    }
  | { readonly intent: "task.delete" | "task.restore"; readonly id: ObjectId };

/** A mutation result: the new Task and the intent. */
export interface TaskChange {
  readonly task: Task;
  readonly intent: TaskIntent;
}

/** Thrown for a value a writer must not create: PROFILE_INVALID with the §74.1 problems. */
export class ProfileError extends LfcpError {
  readonly problems: readonly ProfileProblem[];
  constructor(problems: readonly ProfileProblem[]) {
    super(
      "PROFILE_INVALID",
      problems.map((p) => `${p.diagnostic} at ${p.pointer}: ${p.message}`).join("; "),
    );
    this.name = "ProfileError";
    this.problems = problems;
  }
}

export type ParsedTask =
  | { readonly valid: true; readonly task: Task }
  | { readonly valid: false; readonly problems: readonly ProfileProblem[] };

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

const copy = <T extends Json>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/**
 * Validates a Task stored under `key` (default: its own id) and returns it
 * as a Task (a frozen copy with every field, known or not), or its
 * problems with pointers relative to the object ("/title", ...).
 */
export function parseTask(object: Json | undefined, key?: string): ParsedTask {
  if (!isMap(object) || object.type !== "task") {
    const problems = isMap(object)
      ? [
          {
            code: "PROFILE_INVALID" as const,
            diagnostic: "INVALID_FIELD_TYPE" as const,
            pointer: "/type",
            message: "not a Task (type must be task)",
          },
        ]
      : objectProblems(object, key ?? "", "");
    return { valid: false, problems };
  }
  const problems = objectProblems(object, key ?? String(object.id), "");
  if (problems.length > 0) return { valid: false, problems };
  return { valid: true, task: deepFreeze(copy(object)) as unknown as Task };
}

/** The Task as logical JSON (it already is; this returns a deep copy). */
export const taskToJson = (task: Task): Json => copy(task as unknown as Json);

function checked(task: Record<string, Json | undefined>): Task {
  const problems = objectProblems(task as Json, String(task.id), "");
  if (problems.length > 0) throw new ProfileError(problems);
  return deepFreeze(task) as unknown as Task;
}

/** A copy of `task` with `changes` applied; `undefined` deletes a property (§36: writers delete cleared dates). */
function edit(task: Task, changes: Record<string, Json | undefined>): Task {
  const next: Record<string, Json | undefined> = copy(task as unknown as Json) as Record<
    string,
    Json
  >;
  for (const [field, value] of Object.entries(changes)) {
    if (value === undefined) delete next[field];
    else next[field] = value;
  }
  return checked(next);
}

export interface NewTask {
  readonly title: string;
  /** The creating Principal (§27). */
  readonly createdBy: PrincipalId;
  readonly status?: TaskStatus;
  readonly priority?: TaskPriority;
  readonly due?: string;
  readonly scheduled?: string;
  readonly tags?: readonly string[];
  readonly assignees?: readonly (PrincipalId | PrincipalRef)[];
  /** RFC 3339 UTC; omitted when no reliable clock is available (§53). */
  readonly createdAt?: string;
  /** A UUIDv7 Object ID; generated client-side when absent (§19, §60). */
  readonly id?: ObjectId;
}

const tagKey = (tag: string): string => tag.normalize("NFC"); // §40, §67: SHOULD normalize to NFC
const refOf = (who: PrincipalId | PrincipalRef): PrincipalRef =>
  typeof who === "string" ? (who as PrincipalRef) : principalRef(who);

/** task.create (§53, §60): a new active Task with every required field, in one change. */
export function createTask(input: NewTask): TaskChange {
  const id = input.id ?? generateObjectId();
  if (!isObjectId(id))
    throw new LfcpError("INVALID_UUIDV7", "a Task id must be a canonical UUIDv7");
  const object: Record<string, Json | undefined> = {
    id,
    type: "task",
    lifecycle: "active",
    created_by: principalRef(input.createdBy),
    ...(input.createdAt !== undefined ? { created_at: input.createdAt } : {}),
    title: input.title,
    status: input.status ?? "todo",
    ...(input.due !== undefined ? { due: input.due } : {}),
    ...(input.scheduled !== undefined ? { scheduled: input.scheduled } : {}),
    priority: input.priority ?? "normal",
    tags: Object.fromEntries((input.tags ?? []).map((t) => [tagKey(t), true])),
    assignees: Object.fromEntries((input.assignees ?? []).map((a) => [refOf(a), true])),
    extensions: {},
  };
  const task = checked(object);
  return { task, intent: { intent: "task.create", task } };
}

const change = (task: Task, intent: TaskIntent): TaskChange => Object.freeze({ task, intent });

export const setTitle = (task: Task, title: string): TaskChange =>
  change(edit(task, { title }), { intent: "task.set_title", id: task.id, title });

/** task.set_status (§62): changes only the status. */
export const setStatus = (task: Task, status: TaskStatus): TaskChange =>
  change(edit(task, { status }), { intent: "task.set_status", id: task.id, status });

/** task.complete (§63): status done and, when supplied, the completion date. */
export function complete(task: Task, completionDate?: string): TaskChange {
  const next = edit(
    task,
    completionDate === undefined
      ? { status: "done" }
      : { status: "done", completion_date: completionDate },
  );
  return change(next, {
    intent: "task.complete",
    id: task.id,
    ...(completionDate !== undefined ? { completionDate } : {}),
  });
}

/** task.reopen (§64): status todo and no completion date. */
export const reopen = (task: Task): TaskChange =>
  change(edit(task, { status: "todo", completion_date: undefined }), {
    intent: "task.reopen",
    id: task.id,
  });

/** task.cancel (§65): status cancelled; the completion date is cleared. */
export const cancel = (task: Task): TaskChange =>
  change(edit(task, { status: "cancelled", completion_date: undefined }), {
    intent: "task.cancel",
    id: task.id,
  });

function date(field: "due" | "scheduled", task: Task, value: string): TaskChange {
  // §66: "MUST validate the Local Date grammar before creating a change".
  if (!isLocalDate(value))
    throw new ProfileError([
      {
        code: "PROFILE_INVALID",
        diagnostic: "INVALID_LOCAL_DATE",
        pointer: `/${field}`,
        message: `${value} is not a Gregorian YYYY-MM-DD date (§35)`,
      },
    ]);
  return change(edit(task, { [field]: value }), {
    intent: `task.set_${field}`,
    id: task.id,
    date: value,
  });
}

export const setDue = (task: Task, value: string): TaskChange => date("due", task, value);
export const setScheduled = (task: Task, value: string): TaskChange =>
  date("scheduled", task, value);
/** task.clear_due (§66): deletes the property. */
export const clearDue = (task: Task): TaskChange =>
  change(edit(task, { due: undefined }), { intent: "task.clear_due", id: task.id });
export const clearScheduled = (task: Task): TaskChange =>
  change(edit(task, { scheduled: undefined }), { intent: "task.clear_scheduled", id: task.id });

export const setPriority = (task: Task, priority: TaskPriority): TaskChange =>
  change(edit(task, { priority }), { intent: "task.set_priority", id: task.id, priority });

/** task.add_tag (§67): tags[tag] = true, after NFC normalization. */
export function addTag(task: Task, tag: string): TaskChange {
  const key = tagKey(tag);
  return change(edit(task, { tags: { ...task.tags, [key]: true } }), {
    intent: "task.add_tag",
    id: task.id,
    tag: key,
  });
}

/** task.remove_tag (§67): deletes the key (never stores false, §39). */
export function removeTag(task: Task, tag: string): TaskChange {
  const key = tagKey(tag);
  const tags: Record<string, true> = { ...task.tags };
  delete tags[key];
  return change(edit(task, { tags }), { intent: "task.remove_tag", id: task.id, tag: key });
}

function assigneeRef(who: PrincipalId | PrincipalRef): PrincipalRef {
  const ref = refOf(who);
  // §68: "MUST validate the Principal reference encoding before mutation".
  if (!isPrincipalRef(ref))
    throw new ProfileError([
      {
        code: "PROFILE_INVALID",
        diagnostic: "INVALID_PRINCIPAL_REF",
        pointer: "/assignees",
        message: "not a Principal reference (§27)",
      },
    ]);
  return ref;
}

/** task.add_assignee (§68). */
export function assign(task: Task, who: PrincipalId | PrincipalRef): TaskChange {
  const ref = assigneeRef(who);
  return change(edit(task, { assignees: { ...task.assignees, [ref]: true } }), {
    intent: "task.add_assignee",
    id: task.id,
    assignee: ref,
  });
}

/** task.remove_assignee (§68): deletes the key. */
export function unassign(task: Task, who: PrincipalId | PrincipalRef): TaskChange {
  const ref = assigneeRef(who);
  const assignees: Record<string, true> = { ...task.assignees };
  delete assignees[ref];
  return change(edit(task, { assignees }), {
    intent: "task.remove_assignee",
    id: task.id,
    assignee: ref,
  });
}

/** task.delete (§54): lifecycle = deleted, a tombstone; the object stays. */
export const deleteTask = (task: Task): TaskChange =>
  change(edit(task, { lifecycle: "deleted" }), { intent: "task.delete", id: task.id });

/** task.restore (§55): lifecycle = active. */
export const restoreTask = (task: Task): TaskChange =>
  change(edit(task, { lifecycle: "active" }), { intent: "task.restore", id: task.id });
