import { isObjectId } from "@openlfcp/core";
import {
  isLocalDate,
  isNamespacedValue,
  isPrincipalRef,
  isReverseDomain,
  isUtcTimestamp,
  PROFILE_ID,
} from "./values.js";

/**
 * Profile validation of Shared Objects logical state (SHARED-OBJECTS-
 * PROFILE-01 §73-§77): the JSON an Automerge document of this profile
 * materializes to. Every failure is PROFILE_INVALID with exactly one §74.1
 * diagnostic, at a JSON Pointer (RFC 6901); a field value that breaks
 * several rules gets the first in §74.1 table order. One invalid object never makes
 * the others unusable (§77); unknown fields, extension namespaces, object
 * types and x/…/… values are accepted and preserved (§70-§72).
 */

/** §74.1 diagnostics. */
export type ProfileDiagnostic =
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
  | "IMMUTABLE_FIELD_MUTATED"
  /** §8, §11: a Data Unit's Automerge change is not of its signer's actor; it is not merged. */
  | "CHANGE_ACTOR_MISMATCH"
  /** §11, §13: a plaintext's framing or Automerge bytes are invalid (chunk type, checksum, parse, load); nothing is merged. */
  | "INVALID_AUTOMERGE_BYTES";

/** One profile validation failure: PROFILE_INVALID with its §74.1 diagnostic. */
export interface ProfileProblem {
  readonly code: "PROFILE_INVALID";
  readonly diagnostic: ProfileDiagnostic;
  /** JSON Pointer of the offending value (of its container, for a missing field). */
  readonly pointer: string;
  readonly message: string;
}

/** The §74.1 registry in table order: structure and value rules first, IMMUTABLE_FIELD_MUTATED last. */
export const DIAGNOSTIC_ORDER: readonly ProfileDiagnostic[] = Object.freeze([
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
  "IMMUTABLE_FIELD_MUTATED",
  "CHANGE_ACTOR_MISMATCH",
  "INVALID_AUTOMERGE_BYTES",
]);

/**
 * §74.1 precedence for the fields of the object at `object` (its JSON
 * Pointer): "When one value breaks several rules, its diagnostic is the
 * first that applies in the order of this table", and a field with
 * concurrent values (§45) gets the diagnostic of its first invalid value in
 * that order. Of several problems at one field pointer, those with the
 * first diagnostic are kept, at every pointer below the object (fields,
 * set members, values inside extensions). Problems at the object itself
 * (its key, a missing field) are kept as they are.
 */
export function firstPerField(
  problems: readonly ProfileProblem[],
  object: string,
): ProfileProblem[] {
  const rank = (p: ProfileProblem) => DIAGNOSTIC_ORDER.indexOf(p.diagnostic);
  // Every value below the object (a field, a set member, a value inside extensions).
  const isField = (pointer: string) => pointer.startsWith(`${object}/`);
  const best = new Map<string, number>();
  for (const p of problems)
    if (isField(p.pointer))
      best.set(p.pointer, Math.min(best.get(p.pointer) ?? Number.POSITIVE_INFINITY, rank(p)));
  return problems.filter((p) => !isField(p.pointer) || rank(p) === best.get(p.pointer));
}

export { ProfileInvalidError } from "./profile-invalid.js";

export type Json =
  | null
  | boolean
  | number
  | string
  | readonly Json[]
  | { readonly [key: string]: Json };
type JsonMap = { readonly [key: string]: Json };

export const isMap = (v: unknown): v is JsonMap =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/** RFC 6901 escaping of one reference token. */
export const pointerToken = (key: string): string => key.replace(/~/g, "~0").replace(/\//g, "~1");

const problem = (diagnostic: ProfileDiagnostic, pointer: string, message: string): ProfileProblem =>
  Object.freeze({ code: "PROFILE_INVALID", diagnostic, pointer, message });

const STATUSES = new Set(["todo", "in_progress", "done", "cancelled"]);
const PRIORITIES = new Set(["lowest", "low", "normal", "high", "highest"]);
const LIFECYCLES = new Set(["active", "deleted"]);
const BASE_REQUIRED = ["id", "type", "lifecycle", "created_by", "extensions"];
const TASK_REQUIRED = ["title", "status", "priority", "tags", "assignees"];
const DATE_FIELDS = ["due", "scheduled", "completion_date"];

function extensionProblems(
  value: Json | undefined,
  at: string,
  onType: ProfileDiagnostic,
): ProfileProblem[] {
  if (!isMap(value)) return [problem(onType, at, "extensions must be a map (§18, §29)")];
  return Object.keys(value)
    .filter((ns) => !isReverseDomain(ns))
    .map((ns) =>
      problem(
        "INVALID_EXTENSION_NAMESPACE",
        `${at}/${pointerToken(ns)}`,
        `"${ns}" is not a reverse-domain namespace (§18)`,
      ),
    );
}

function setProblems(
  value: Json | undefined,
  at: string,
  what: string,
  keyCheck: (key: string) => ProfileProblem | null,
): ProfileProblem[] {
  if (!isMap(value))
    return [
      problem(
        "INVALID_COLLECTION_REPRESENTATION",
        at,
        `${what} must be a map of key -> true (§39, §42)`,
      ),
    ];
  const out: ProfileProblem[] = [];
  for (const [key, member] of Object.entries(value)) {
    const keyProblem = keyCheck(key);
    if (keyProblem !== null) out.push(keyProblem);
    if (member !== true)
      out.push(
        problem(
          "INVALID_COLLECTION_REPRESENTATION",
          `${at}/${pointerToken(key)}`,
          `a ${what} member's value must be true (§39, §42)`,
        ),
      );
  }
  return out;
}

/**
 * Problems of one Shared Object stored under `key` in `objects`, with
 * pointers below `at` (default "/objects/<key>"). Non-Task types are
 * checked for the base fields only (§23, §71).
 */
export function objectProblems(
  object: Json | undefined,
  key: string,
  at = `/objects/${pointerToken(key)}`,
): ProfileProblem[] {
  return firstPerField(allObjectProblems(object, key, at), at);
}

function allObjectProblems(object: Json | undefined, key: string, at: string): ProfileProblem[] {
  const out: ProfileProblem[] = [];
  if (!isObjectId(key))
    out.push(
      problem("INVALID_OBJECT_ID", at, `the objects key "${key}" is not a canonical UUIDv7 (§19)`),
    );
  if (!isMap(object)) {
    out.push(problem("INVALID_FIELD_TYPE", at, "a Shared Object must be a map (§23)"));
    return out;
  }
  const o = object;
  const required = o.type === "task" ? [...BASE_REQUIRED, ...TASK_REQUIRED] : BASE_REQUIRED;
  for (const field of required) {
    if (!(field in o))
      out.push(
        problem("MISSING_REQUIRED_FIELD", at, `the required field ${field} is missing (§23, §31)`),
      );
  }
  if ("id" in o) {
    if (typeof o.id !== "string" || !isObjectId(o.id))
      out.push(problem("INVALID_OBJECT_ID", `${at}/id`, "id is not a canonical UUIDv7 (§19)"));
    if (o.id !== key)
      out.push(
        problem("OBJECT_ID_MISMATCH", `${at}/id`, "id differs from its objects key (§20, §24)"),
      );
  }
  if ("type" in o && (typeof o.type !== "string" || o.type.length === 0))
    out.push(problem("INVALID_FIELD_TYPE", `${at}/type`, "type must be non-empty text (§25)"));
  if ("lifecycle" in o && !(typeof o.lifecycle === "string" && LIFECYCLES.has(o.lifecycle)))
    out.push(
      problem("INVALID_ENUM_VALUE", `${at}/lifecycle`, "lifecycle must be active or deleted (§26)"),
    );
  if ("created_by" in o && !isPrincipalRef(o.created_by))
    out.push(
      problem(
        "INVALID_PRINCIPAL_REF",
        `${at}/created_by`,
        "created_by is not a Principal reference (§27)",
      ),
    );
  // created_at is a base field (§23, §28), so it is checked on every object type.
  if ("created_at" in o && !isUtcTimestamp(o.created_at))
    out.push(
      problem(
        "INVALID_TIMESTAMP",
        `${at}/created_at`,
        "created_at is not an RFC 3339 UTC timestamp (§28)",
      ),
    );
  if ("extensions" in o)
    out.push(...extensionProblems(o.extensions, `${at}/extensions`, "INVALID_FIELD_TYPE"));
  if (o.type !== "task") return out;

  if ("title" in o && typeof o.title !== "string")
    out.push(problem("INVALID_FIELD_TYPE", `${at}/title`, "title must be text (§32)"));
  if (
    "status" in o &&
    !(typeof o.status === "string" && (STATUSES.has(o.status) || isNamespacedValue(o.status)))
  )
    out.push(
      problem(
        "INVALID_ENUM_VALUE",
        `${at}/status`,
        "status is neither standard nor x/<reverse-domain>/<value> (§33)",
      ),
    );
  if (
    "priority" in o &&
    !(
      typeof o.priority === "string" &&
      (PRIORITIES.has(o.priority) || isNamespacedValue(o.priority))
    )
  )
    out.push(
      problem(
        "INVALID_ENUM_VALUE",
        `${at}/priority`,
        "priority is neither standard nor x/<reverse-domain>/<value> (§38)",
      ),
    );
  for (const field of DATE_FIELDS) {
    // §36: missing and null both mean no date.
    if (field in o && o[field] !== null && !isLocalDate(o[field]))
      out.push(
        problem(
          "INVALID_LOCAL_DATE",
          `${at}/${field}`,
          `${field} is not a Gregorian YYYY-MM-DD date (§35)`,
        ),
      );
  }
  if ("tags" in o)
    out.push(
      ...setProblems(o.tags, `${at}/tags`, "tag", (tag) =>
        tag.length === 0 || tag.startsWith("#")
          ? problem(
              "INVALID_TAG",
              `${at}/tags/${pointerToken(tag)}`,
              "a tag must be non-empty without a leading # (§40)",
            )
          : null,
      ),
    );
  if ("assignees" in o)
    out.push(
      ...setProblems(o.assignees, `${at}/assignees`, "assignee", (ref) =>
        isPrincipalRef(ref)
          ? null
          : problem(
              "INVALID_PRINCIPAL_REF",
              `${at}/assignees/${pointerToken(ref)}`,
              "an assignee key is not a Principal reference (§42)",
            ),
      ),
    );
  return out;
}

/** The result of validating a root: root-level problems and problems per object (§77 isolation). */
export interface RootValidation {
  readonly valid: boolean;
  readonly problems: readonly ProfileProblem[];
  /** Problems per objects key; an object with none is usable. */
  readonly objects: ReadonlyMap<string, readonly ProfileProblem[]>;
}

/** Validates a whole root (§15, §74). Unknown top-level keys are preserved, not rejected (§17). */
export function validateRoot(root: Json | undefined): RootValidation {
  const rootProblems: ProfileProblem[] = [];
  const perObject = new Map<string, readonly ProfileProblem[]>();
  if (!isMap(root)) {
    rootProblems.push(problem("INVALID_ROOT", "/", "the root must be a map (§15)"));
  } else {
    if (!("profile" in root) || root.profile !== PROFILE_ID)
      rootProblems.push(
        problem(
          "INVALID_ROOT",
          "profile" in root ? "/profile" : "/",
          `profile must be ${PROFILE_ID} (§15)`,
        ),
      );
    if (!("objects" in root))
      rootProblems.push(problem("INVALID_ROOT", "/", "objects is missing (§15)"));
    else if (!isMap(root.objects))
      rootProblems.push(problem("INVALID_ROOT", "/objects", "objects must be a map (§15)"));
    else
      for (const [key, object] of Object.entries(root.objects))
        perObject.set(key, objectProblems(object, key));
    if (!("extensions" in root))
      rootProblems.push(problem("INVALID_ROOT", "/", "extensions is missing (§15)"));
    else rootProblems.push(...extensionProblems(root.extensions, "/extensions", "INVALID_ROOT"));
  }
  const all = [...rootProblems, ...[...perObject.values()].flat()];
  return Object.freeze({
    valid: all.length === 0,
    problems: Object.freeze(all),
    objects: perObject,
  });
}

const IMMUTABLE = ["id", "type", "created_by"];

/**
 * §75: id, type and created_by never change. Problems for every object
 * present in both states whose immutable field differs, unless the new
 * value breaks a structure or value rule: §74.1 puts
 * IMMUTABLE_FIELD_MUTATED last, so that value's diagnostic is the one
 * objectProblems reports.
 */
export function validateTransition(
  before: Json | undefined,
  after: Json | undefined,
): readonly ProfileProblem[] {
  if (!isMap(before) || !isMap(after) || !isMap(before.objects) || !isMap(after.objects)) return [];
  const out: ProfileProblem[] = [];
  for (const [key, old] of Object.entries(before.objects)) {
    const now = after.objects[key];
    if (!isMap(old) || !isMap(now)) continue;
    const at = `/objects/${pointerToken(key)}`;
    const broken = new Set(objectProblems(now, key, at).map((p) => p.pointer));
    for (const field of IMMUTABLE) {
      // A removed field is MISSING_REQUIRED_FIELD, an earlier diagnostic.
      if (!(field in now) || broken.has(`${at}/${field}`)) continue;
      if (field in old && JSON.stringify(old[field]) !== JSON.stringify(now[field]))
        out.push(
          problem(
            "IMMUTABLE_FIELD_MUTATED",
            `${at}/${field}`,
            `${field} changed (§24, §25, §27, §75)`,
          ),
        );
    }
  }
  return out;
}
