// SHARED-OBJECTS-TEST-VECTORS-01 handlers for sdk-ts through LFCP-030.
//
// Deterministic vectors (Dxx) are checked byte for byte; validation
// vectors (Ixx, D06-D08) must fail with PROFILE_INVALID and the exact
// §74.1 diagnostic; behavioral scenarios (Sxx) are checked only for the
// validity of every state and value they state or write (what the spec's
// own LFCP-006 contract checks). Their merge outcomes need the Automerge
// binding and are pending (LFCP-032, LFCP-037).

import { fromHex, isObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import {
  deriveActorId,
  frameProfilePayload,
  isMap,
  isPrincipalRef,
  type Json,
  objectProblems,
  PROFILE_ID,
  type ProfileProblem,
  parsePrincipalRef,
  pointerToken,
  principalRef,
  unframeProfilePayload,
  validateRoot,
  validateTransition,
} from "@openlfcp/shared-objects";
import { bytesCheck, check, equalCheck, outcomeCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, VectorCase } from "../runner.js";

type Fields = Readonly<Record<string, unknown>> | undefined;

function hexOf(fields: Fields, name: string): Uint8Array {
  const v = fields?.[name] as { hex?: unknown } | undefined;
  if (typeof v?.hex !== "string") throw new Error(`field ${name} is not a {hex} value`);
  return fromHex(v.hex);
}

// ---------------------------------------------------------------------------
// deterministic bytes (D01-D05)

const actorId: Handler = (c) => ({
  checks: [
    bytesCheck(
      "actor_id",
      hexOf(c.expected, "actor_id"),
      deriveActorId(
        resourceId(hexOf(c.inputs, "resource_hex")),
        principalId(hexOf(c.inputs, "principal_hex")),
      ),
    ),
  ],
});

const principalReference: Handler = (c) => {
  const id = principalId(hexOf(c.inputs, "principal_id"));
  const expected = String(c.expected.principal_ref);
  return {
    checks: [
      equalCheck("principal_ref", expected, principalRef(id)),
      check("principal_ref/parse", () => toHex(parsePrincipalRef(expected)) === toHex(id)),
    ],
  };
};

function framing(inputField: string): Handler {
  return (c) => {
    const inner = hexOf(c.inputs, inputField);
    const framed = hexOf(c.expected, "framed_cbor");
    return {
      checks: [
        bytesCheck("framed_cbor", framed, frameProfilePayload(inner)),
        check("framed_cbor/unframe", () => toHex(unframeProfilePayload(framed)) === toHex(inner)),
        bytesCheck("sha256", hexOf(c.expected, "sha256"), sha256(framed)),
      ],
    };
  };
}

// ---------------------------------------------------------------------------
// validation (D06-D08, I01-I07)

/** The PROFILE_INVALID outcome: "PROFILE_INVALID/<diagnostic>" if the expected diagnostic is among the problems, else the first. */
function outcomeOf(problems: readonly ProfileProblem[], expected: string | null): string | null {
  if (problems.length === 0) return null;
  const hit = problems.find((p) => `${p.code}/${p.diagnostic}` === expected);
  const p = hit ?? (problems[0] as ProfileProblem);
  return `${p.code}/${p.diagnostic}`;
}

function expectedOutcome(c: VectorCase): string | null {
  const e = c.expected as { valid?: boolean; error?: { code?: string; diagnostic?: string } };
  return e.valid === false ? `${e.error?.code}/${e.error?.diagnostic}` : null;
}

const objectIdValidation: Handler = (c) => {
  const id = String(c.inputs?.object_id);
  const expected = expectedOutcome(c);
  const problems = objectProblems({}, id).filter(
    (p) => p.pointer === `/objects/${pointerToken(id)}`,
  );
  const actual = outcomeOf(problems, expected);
  return {
    checks: [
      expected === null
        ? equalCheck("outcome", true, isObjectId(id))
        : outcomeCheck("outcome", expected, actual),
    ],
  };
};

/** The Task the I cases mutate: S01's expected object (schema README: "a mutation of the S01 Task"). */
function s01Task(context: HandlerContext): { key: string; task: Json } {
  const objects = (
    context.caseById("S01")?.expected as { objects?: Record<string, Json> } | undefined
  )?.objects;
  const [key, task] = Object.entries(objects ?? {})[0] ?? [];
  if (key === undefined || task === undefined) throw new Error("S01 has no expected Task");
  return { key, task };
}

const rootOf = (objects: Record<string, Json>): Json => ({
  profile: PROFILE_ID,
  objects,
  extensions: {},
});

const profileValidation: Handler = (c, context) => {
  const m = c.inputs?.mutation as { object_key: string; field?: string; value: Json };
  const { key, task } = s01Task(context);
  const before = rootOf({ [key]: task });
  const after =
    m.field === undefined
      ? rootOf({ [m.object_key]: m.value })
      : rootOf({ [m.object_key]: { ...(task as Record<string, Json>), [m.field]: m.value } });
  const at =
    m.field === undefined
      ? `/objects/${pointerToken(m.object_key)}`
      : `/objects/${pointerToken(m.object_key)}/${pointerToken(m.field)}`;
  // Problems at the mutated value: the state itself, then the transition (§75).
  const problems = [...validateRoot(after).problems, ...validateTransition(before, after)].filter(
    (p) => p.pointer === at || p.pointer.startsWith(`${at}/`),
  );
  const expected = expectedOutcome(c);
  return { checks: [outcomeCheck("outcome", expected, outcomeOf(problems, expected))] };
};

// ---------------------------------------------------------------------------
// behavioral scenarios (S01-S14): stated values must be valid; merges pending

/** The scenario's base Task (inline fields or base_state.task), else S01's Task. */
function baseTask(c: VectorCase, context: HandlerContext): Record<string, Json> {
  const base = c.inputs?.base_state as Record<string, Json> | undefined;
  if (base !== undefined && typeof base.id === "string") return base;
  if (base !== undefined && isMap(base.task)) return base.task as Record<string, Json>;
  return s01Task(context).task as Record<string, Json>;
}

/** Problems of `field = value` inside an otherwise valid base Task. */
function fieldProblems(
  task: Record<string, Json>,
  field: string,
  value: Json,
): readonly ProfileProblem[] {
  return objectProblems({ ...task, [field]: value }, String(task.id), "").filter(
    (p) => p.pointer === `/${field}` || p.pointer.startsWith(`/${field}/`),
  );
}

const describeProblems = (problems: readonly ProfileProblem[]): string =>
  problems.map((p) => `${p.diagnostic} at ${p.pointer}`).join("; ");

function valid(name: string, problems: readonly ProfileProblem[]): Check {
  return problems.length === 0
    ? { name, ok: true }
    : { name, ok: false, message: describeProblems(problems) };
}

function objectsProblems(objects: Json): ProfileProblem[] {
  if (!isMap(objects))
    return validateRoot({ profile: PROFILE_ID, objects, extensions: {} })
      .problems as ProfileProblem[];
  return Object.entries(objects).flatMap(([k, o]) => objectProblems(o, k));
}

/** The validity check for one expected key, or null when the key states a behavior, not a value. */
function expectedValueProblems(
  key: string,
  value: Json,
  task: Record<string, Json>,
): readonly ProfileProblem[] | null {
  if (key === "objects") return objectsProblems(value);
  if (key === "tags" && Array.isArray(value))
    return value.flatMap((tag) => fieldProblems(task, "tags", { [String(tag)]: true }));
  if (key === "assignees" && Array.isArray(value))
    return value.flatMap((ref) =>
      isPrincipalRef(ref) ? [] : fieldProblems(task, "assignees", { [String(ref)]: true }),
    );
  const set = /^(.*)_(conflict_set|values_may_include)$/.exec(key);
  if (set !== null && Array.isArray(value))
    return value.flatMap((v) => fieldProblems(task, set[1] as string, v));
  if (key === "task_status") return fieldProblems(task, "status", value);
  if (
    ["title", "status", "lifecycle", "priority", "due", "scheduled", "completion_date"].includes(
      key,
    )
  )
    return fieldProblems(task, key, value);
  return null;
}

const scenario: Handler = (c, context) => {
  const task = baseTask(c, context);
  const inputs = c.inputs as {
    base_state?: Record<string, Json>;
    branches?: Record<string, Json>[];
  };
  const inputProblems: ProfileProblem[] = [];
  const base = inputs.base_state ?? {};
  if (typeof base.id === "string") inputProblems.push(...objectProblems(base, base.id, ""));
  if (isMap(base.task)) inputProblems.push(...objectProblems(base.task, String(base.task.id), ""));
  if (isMap(base.objects)) inputProblems.push(...objectsProblems(base.objects));
  for (const b of inputs.branches ?? []) {
    if (isMap(b.args)) inputProblems.push(...objectProblems(b.args, String(b.args.id), ""));
    if (isMap(b.object)) inputProblems.push(...objectProblems(b.object, String(b.object.id), ""));
    if (isMap(b.writes))
      for (const [f, v] of Object.entries(b.writes))
        inputProblems.push(...fieldProblems(task, f, v));
    if (typeof b.tag === "string")
      inputProblems.push(...fieldProblems(task, "tags", { [b.tag]: true }));
    if (typeof b.principal === "string" && !isPrincipalRef(b.principal))
      inputProblems.push(...fieldProblems(task, "assignees", { [b.principal]: true }));
  }
  const checks: Check[] = [valid("inputs/valid", inputProblems)];
  const pending: string[] = [];
  for (const [key, value] of Object.entries(c.expected)) {
    const problems = expectedValueProblems(key, value as Json, task);
    if (problems !== null) checks.push(valid(`${key}/valid`, problems));
    pending.push(`${key}/merge`);
  }
  return { checks, pending };
};

export const SHARED_OBJECTS_HANDLERS: Readonly<Record<string, Handler>> = {
  "bytes/actor_id": actorId,
  "bytes/principal_ref": principalReference,
  "bytes/profile_change_framing": framing("automerge_change_hex"),
  "bytes/profile_snapshot_framing": framing("automerge_save_hex"),
  "validation/object_id_validation": objectIdValidation,
  "validation/profile_validation": profileValidation,
  "behavioral/shared_object_scenario": scenario,
};
