import * as A from "@automerge/automerge";
import { fromBase64url, principalId } from "@openlfcp/core";
import { isIdentityDescriptor, isResourceRef } from "../identity/values.js";
import { pointerToken } from "../validate.js";
import { isPrincipalRef, isUtcTimestamp } from "../values.js";
import { isMapValue, isStr, isUint, ScReader, type ScValue } from "./reader.js";
import {
  deviceFingerprint,
  EVENT_STATES,
  type EventState,
  FINAL_EVENT_STATES,
  isHash32,
  isOp,
  isUuid7,
  SERVICE_CONTROL_PROFILE_ID,
  SERVICE_CONTROL_ROOT_KEYS,
  type ServiceControlAnswer,
  type ServiceControlApproval,
  type ServiceControlCancel,
  type ServiceControlEvent,
  type ServiceControlPairing,
  type ServiceControlQuestion,
  type ServiceControlRecord,
  type ServiceControlRequest,
  WHOLE_CONTAINERS,
} from "./values.js";

/** §5, in table order: the first that applies is reported. */
export const SERVICE_CONTROL_DIAGNOSTIC_ORDER = Object.freeze([
  "INVALID_ROOT",
  "MISSING_REQUIRED_FIELD",
  "INVALID_FIELD_TYPE",
  "INVALID_RESOURCE_REF",
  "INVALID_PRINCIPAL_REF",
  "INVALID_KEY",
  "INVALID_ENUM_VALUE",
  "INVALID_TIMESTAMP",
  "INVALID_DESCRIPTOR",
  "LIMIT_EXCEEDED",
] as const);
export type ServiceControlDiagnostic = (typeof SERVICE_CONTROL_DIAGNOSTIC_ORDER)[number];

/** §4 Sizes: the limit of an entry, and of `service`, `status`, `lifecycle` as wholes. */
export const ENTRY_LIMIT = 4096;
export const PAIRING_ENTRY_LIMIT = 8192;
export const MAX_EXAMPLE_SCALARS = 80;
export const MAX_ITEMS = 5;

// Field types of §2.1: s string, u uint, b boolean, t timestamp, r ResourceRef,
// p PrincipalRef, h Hash32, id Uuid, op Op, x Example, m any map.
type Scalar = "s" | "u" | "b" | "t" | "r" | "p" | "h" | "id" | "op" | "x" | "m";
type FieldType =
  | Scalar
  | { readonly enum: readonly string[] }
  | { readonly list: FieldType; readonly max?: number }
  | { readonly mapOf: FieldType }
  | { readonly fields: Readonly<Record<string, FieldType>> };
const fields = (f: Readonly<Record<string, FieldType>>) => ({ fields: f });
/** §2.1 `list<Example>` of a question or preview: at most five (§4 SC7). */
const EXAMPLES: FieldType = { list: "x", max: MAX_ITEMS };
/** §2.1 `map<string, uint>`. */
const COUNTS: FieldType = { mapOf: "u" };

/** §2.1; a key ending in "?" is optional. */
const SCHEMA: Readonly<Record<string, FieldType>> = {
  approvals: fields({
    role: { enum: ["base", "section"] },
    resource: "r",
    principal: "p",
    certDigest: "h",
    certId: "h",
    generation: "u",
    origin: "s",
    at: "t",
    "revoked?": fields({ at: "t" }),
  }),
  service: fields({
    instance: "s",
    kind: "s",
    label: "s",
    platform: "s",
    app: "s",
    protocol: fields({ v: "u", ops: { list: "s" }, questionKinds: { list: "s" } }),
    artifactSliceId: "s",
    macos: "s",
    cert: fields({ state: "s", manifestSeq: "u", certTestMode: "b" }),
    capacity: fields({ sections: "u", max: "u", devicesFree: "u" }),
  }),
  status: fields({ state: "s", since: "t", heartbeatAt: "t", "message?": "s" }),
  bindings: fields({
    state: "s",
    generation: "u",
    list: "s",
    filter: "s",
    "lastCompleteCheckAt?": "t",
    pending: fields({ toApple: "u", toLfcp: "u" }),
    refused: "u",
    unconfirmed: "u",
    "preview?": fields({
      id: "s",
      planHash: "s",
      filter: "s",
      list: "s",
      "items?": EXAMPLES,
      "counts?": COUNTS,
    }),
    "needsAttention?": fields({ code: "s" }),
    "lifecycle?": "s",
  }),
  pairing: fields({ descriptor: "s", principal: "p", fp: "s" }),
  questions: fields({
    binding: "r",
    generation: "u",
    kind: "s",
    anomalyId: "s",
    snapshotHash: "s",
    items: EXAMPLES,
    counts: COUNTS,
    "actor?": "s",
    options: { list: "s" },
    at: "t",
    "resolved?": fields({ answerId: "id", choice: "s", at: "t" }),
    "superseded?": fields({ by: "s" }),
  }),
  requests: fields({
    op: "op",
    "binding?": "r",
    "generation?": "u",
    args: "m",
    client: fields({ app: "s", protocol: "u" }),
    at: "t",
  }),
  answers: fields({ qid: "id", snapshotHash: "s", choice: "s", at: "t" }),
  cancels: fields({ reason: { enum: ["user", "mismatch", "expired"] }, at: "t" }),
  events: fields({ state: { enum: EVENT_STATES }, "code?": "s", "detail?": "s", at: "t" }),
  lifecycle: fields({
    "op?": { enum: ["remove", "uninstall"] },
    "bindings?": { list: fields({ binding: "r", generation: "u" }) },
    "at?": "t",
  }),
};

const UUID_KEYED = new Set(["pairing", "questions", "requests", "answers", "cancels", "events"]);

function checkValue(
  reader: ScReader,
  type: FieldType,
  v: ScValue | undefined,
  found: Set<ServiceControlDiagnostic>,
): void {
  if (v === undefined) return;
  if (typeof type === "string") {
    if (type === "u") return void (isUint(v) || found.add("INVALID_FIELD_TYPE"));
    if (type === "b") return void (v[0] === "boolean" || found.add("INVALID_FIELD_TYPE"));
    if (type === "m") return void (isMapValue(v) || found.add("INVALID_FIELD_TYPE"));
    if (!isStr(v)) return void found.add("INVALID_FIELD_TYPE");
    const s = v[1];
    if (type === "t" && !isUtcTimestamp(s)) found.add("INVALID_TIMESTAMP");
    if (type === "r" && !isResourceRef(s)) found.add("INVALID_RESOURCE_REF");
    if (type === "p" && !isPrincipalRef(s)) found.add("INVALID_PRINCIPAL_REF");
    if (type === "h" && !isHash32(s)) found.add("INVALID_FIELD_TYPE");
    if (type === "id" && !isUuid7(s)) found.add("INVALID_FIELD_TYPE");
    if (type === "op" && !isOp(s)) found.add("INVALID_ENUM_VALUE");
    if (type === "x" && [...s].length > MAX_EXAMPLE_SCALARS) found.add("LIMIT_EXCEEDED");
    return;
  }
  if ("enum" in type) {
    if (!isStr(v)) found.add("INVALID_FIELD_TYPE");
    else if (!type.enum.includes(v[1])) found.add("INVALID_ENUM_VALUE");
    return;
  }
  if ("list" in type) {
    if (v[0] !== "list") return void found.add("INVALID_FIELD_TYPE");
    const id = String(v[1]);
    const length = reader.length(id);
    if (type.max !== undefined && length > type.max) found.add("LIMIT_EXCEEDED");
    for (let i = 0; i < length; i++) checkValue(reader, type.list, reader.get(id, i), found);
    return;
  }
  if ("mapOf" in type) {
    if (!isMapValue(v)) return void found.add("INVALID_FIELD_TYPE");
    // Every concurrent value of every key (SOP §45).
    for (const k of reader.keys(v[1]))
      for (const e of reader.all(v[1], k)) checkValue(reader, type.mapOf, e, found);
    return;
  }
  if (!isMapValue(v)) return void found.add("INVALID_FIELD_TYPE");
  for (const [k, t] of Object.entries(type.fields)) {
    const name = k.endsWith("?") ? k.slice(0, -1) : k;
    const field = reader.get(v[1], name);
    if (field === undefined) {
      if (!k.endsWith("?")) found.add("MISSING_REQUIRED_FIELD");
    } else checkValue(reader, t, field, found);
  }
}

/**
 * §5 for one value: `container[key]`, or `container` itself for `service`,
 * `status` and `lifecycle` (key undefined), its size of §4 included. Nested
 * fields are read by their projection; other conflicts are §5 rule 3's
 * (validateServiceControl), not this function's. `resource` is C's
 * ResourceRef (a base approval names it).
 */
export function entryDiagnostics(
  reader: ScReader,
  container: string,
  key: string | undefined,
  v: ScValue | undefined,
  resource: string,
): Set<ServiceControlDiagnostic> {
  const found = new Set<ServiceControlDiagnostic>();
  const schema = SCHEMA[container];
  if (schema === undefined || v === undefined) return found;
  // §5 rule 1: an empty service, status or lifecycle means "not reported yet".
  if (WHOLE_CONTAINERS.has(container) && isMapValue(v) && reader.keys(v[1]).length === 0)
    return found;
  checkValue(reader, schema, v, found);
  // §4 Sizes, on the state read: concurrent values of a field count, so an
  // entry merged from changes admitted apart can exceed its limit (§5).
  if (reader.size(v) > limitOf(container)) found.add("LIMIT_EXCEEDED");
  if (key !== undefined) {
    if (UUID_KEYED.has(container) && !isUuid7(key)) found.add("INVALID_KEY");
    if (container === "bindings" && !isResourceRef(key)) found.add("INVALID_RESOURCE_REF");
  }
  if (!isMapValue(v)) return found;
  const field = (name: string) => {
    const f = reader.get(v[1], name);
    return isStr(f) ? f[1] : undefined;
  };
  if (container === "approvals") {
    if (field("principal") !== key) found.add("INVALID_KEY");
    if (field("role") === "base" && field("resource") !== resource) found.add("INVALID_ENUM_VALUE");
  }
  if (container === "pairing") {
    const descriptor = field("descriptor");
    const principal = field("principal");
    if (descriptor !== undefined && !validPairing(descriptor, principal, field("fp")))
      found.add("INVALID_DESCRIPTOR");
  }
  return found;
}

/** §5 INVALID_DESCRIPTOR: a valid W §7 descriptor whose ID is `principal`, and its fingerprint. */
function validPairing(
  descriptor: string,
  principal: string | undefined,
  fp: string | undefined,
): boolean {
  if (principal === undefined || !isIdentityDescriptor(descriptor, principal)) return false;
  return fp === deviceFingerprint(principalId(fromBase64url(principal.slice(2))));
}

/** The first §5 diagnostic of a set, or undefined. */
export const firstDiagnostic = (found: ReadonlySet<string>): ServiceControlDiagnostic | undefined =>
  SERVICE_CONTROL_DIAGNOSTIC_ORDER.find((d) => found.has(d));

/** §4 Sizes: the limit of an entry of `container`. */
export const limitOf = (container: string): number =>
  container === "pairing" ? PAIRING_ENTRY_LIMIT : ENTRY_LIMIT;

/** §5 rule 3: the order of §6.2; the highest of concurrent values is read. */
export function eventStateOf(reader: ScReader, event: string): EventState | undefined {
  let best = -1;
  for (const v of reader.all(event, "state"))
    if (isStr(v)) best = Math.max(best, EVENT_STATES.indexOf(v[1] as EventState));
  return best < 0 ? undefined : EVENT_STATES[best];
}

/** §3, §5 rule 3: an event is final when any of its concurrent states is final. */
export function eventIsFinal(reader: ScReader, event: string): boolean {
  return reader.all(event, "state").some((v) => isStr(v) && FINAL_EVENT_STATES.has(v[1]));
}

const APPROVAL_IDENTITY = ["role", "resource", "principal", "certDigest", "certId", "generation"];

/**
 * §5 rule 3: the one approval `approvals[key]` reads as, or undefined when it
 * is absent or invalid. Concurrent maps are one approval when every one is
 * valid and their role, resource, principal, certDigest, certId and
 * generation are equal; a `revoked` value in any of them means revoked.
 */
export function readApproval(
  reader: ScReader,
  approvals: string,
  key: string,
  resource: string,
): ServiceControlApproval | undefined {
  const maps = reader.all(approvals, key);
  if (maps.length === 0) return undefined;
  const signature = (v: ScValue) =>
    APPROVAL_IDENTITY.map((f) => {
      const values = reader.all(String(v[1]), f);
      return values.length === 1 ? `${values[0]?.[0]}:${String(values[0]?.[1])}` : "conflict";
    }).join("\n");
  const first = maps[0] as ScValue;
  for (const v of maps) {
    if (!isMapValue(v)) return undefined;
    if (firstDiagnostic(entryDiagnostics(reader, "approvals", key, v, resource)) !== undefined)
      return undefined;
    if (signature(v).includes("conflict") || signature(v) !== signature(first)) return undefined;
  }
  const plain = reader.plain(first) as Record<string, unknown>;
  const revoked = maps.some((v) => reader.all(String(v[1]), "revoked").length > 0);
  return Object.freeze({
    role: plain.role as "base" | "section",
    resource: plain.resource as string,
    principal: plain.principal as string,
    certDigest: plain.certDigest as string,
    certId: plain.certId as string,
    generation: plain.generation as number | bigint,
    origin: plain.origin as string,
    at: plain.at as string,
    revoked,
  });
}

export interface ServiceControlProblem {
  readonly code: "PROFILE_INVALID";
  readonly diagnostic: ServiceControlDiagnostic;
  readonly pointer: string;
  readonly message: string;
}

/** The readable state of C (§5): invalid entries are left out, the rest stays usable. */
export interface ServiceControlValidation {
  /** False only for an invalid root: C is unusable. */
  readonly usable: boolean;
  readonly problems: readonly ServiceControlProblem[];
  readonly approvals: Readonly<Record<string, ServiceControlApproval>>;
  /** Absent until the service's first write (§5 rule 1). */
  readonly service?: ServiceControlRecord;
  readonly status?: ServiceControlRecord;
  readonly lifecycle?: ServiceControlRecord;
  readonly bindings: Readonly<Record<string, ServiceControlRecord>>;
  readonly pairing: Readonly<Record<string, ServiceControlPairing>>;
  readonly questions: Readonly<Record<string, ServiceControlQuestion>>;
  readonly requests: Readonly<Record<string, ServiceControlRequest>>;
  readonly answers: Readonly<Record<string, ServiceControlAnswer>>;
  readonly cancels: Readonly<Record<string, ServiceControlCancel>>;
  readonly events: Readonly<Record<string, ServiceControlEvent>>;
}

/** Entries created by root or personal: a conflict anywhere in them makes them invalid (§5 rule 3). */
const HUMAN_ENTRIES = new Set(["requests", "answers", "cancels"]);

/** True when a value, or any field or element below it, holds concurrent values. */
function conflicted(reader: ScReader, v: ScValue): boolean {
  if (v[0] === "map") {
    const id = String(v[1]);
    return reader.keys(id).some((k) => {
      const all = reader.all(id, k);
      return all.length > 1 || (all[0] !== undefined && conflicted(reader, all[0]));
    });
  }
  if (v[0] === "list") {
    const id = String(v[1]);
    for (let i = 0; i < reader.length(id); i++) {
      const all = reader.all(id, i);
      if (all.length > 1 || (all[0] !== undefined && conflicted(reader, all[0]))) return true;
    }
  }
  return false;
}

const at = (...parts: string[]) => parts.map((p) => `/${pointerToken(p)}`).join("");

/**
 * §5 on the whole document, as a reader sees it (now, or at `heads`).
 * `resource` is C's ResourceRef. Validation is per entry (rule 1); an
 * invalid root makes C unusable.
 */
export function validateServiceControl(
  doc: A.Doc<unknown>,
  resource: string,
  heads?: readonly string[],
): ServiceControlValidation {
  const reader = new ScReader(A.getBackend(doc), heads);
  const problems: ServiceControlProblem[] = [];
  const fail = (diagnostic: ServiceControlDiagnostic, pointer: string) =>
    problems.push(
      Object.freeze({
        code: "PROFILE_INVALID",
        diagnostic,
        pointer,
        message: `SERVICE-CONTROL-PROFILE-01 §5: ${diagnostic} at ${pointer || "/"}`,
      }),
    );
  const empty = {
    approvals: {},
    bindings: {},
    pairing: {},
    questions: {},
    requests: {},
    answers: {},
    cancels: {},
    events: {},
  };
  const profile = reader.all("_root", "profile");
  const rootOk =
    profile.length === 1 &&
    isStr(profile[0]) &&
    profile[0][1] === SERVICE_CONTROL_PROFILE_ID &&
    SERVICE_CONTROL_ROOT_KEYS.slice(1).every((k) => {
      const all = reader.all("_root", k);
      return all.length === 1 && isMapValue(all[0]);
    });
  if (!rootOk) {
    fail("INVALID_ROOT", "");
    return Object.freeze({ usable: false, problems: Object.freeze(problems), ...empty });
  }
  const container = (k: string) => reader.map("_root", k) as string;

  const whole = (name: string): ServiceControlRecord | undefined => {
    const v = reader.get("_root", name) as ScValue;
    const d = firstDiagnostic(entryDiagnostics(reader, name, undefined, v, resource));
    if (d !== undefined) {
      fail(d, at(name));
      return undefined;
    }
    if (reader.keys(container(name)).length === 0) return undefined;
    return Object.freeze(reader.plain(v) as ServiceControlRecord);
  };

  const approvals: Record<string, ServiceControlApproval> = {};
  const approvalsId = container("approvals");
  for (const key of reader.keys(approvalsId)) {
    const a = readApproval(reader, approvalsId, key, resource);
    if (a === undefined) {
      const v = reader.get(approvalsId, key) as ScValue;
      fail(
        firstDiagnostic(entryDiagnostics(reader, "approvals", key, v, resource)) ??
          "INVALID_FIELD_TYPE",
        at("approvals", key),
      );
    } else approvals[key] = a;
  }

  const table = <T>(name: string, read: (v: ScValue, id: string) => T): Record<string, T> => {
    const out: Record<string, T> = {};
    const id = container(name);
    for (const key of reader.keys(id)) {
      const all = reader.all(id, key);
      const v = reader.get(id, key) as ScValue;
      const d = firstDiagnostic(entryDiagnostics(reader, name, key, v, resource));
      if (d !== undefined) {
        fail(d, at(name, key));
        continue;
      }
      if (HUMAN_ENTRIES.has(name) && (all.length > 1 || conflicted(reader, v))) {
        fail("INVALID_FIELD_TYPE", at(name, key));
        continue;
      }
      out[key] = read(v, String(v[1]));
    }
    return out;
  };
  const plain = <T>(v: ScValue) => Object.freeze(reader.plain(v)) as T;

  const events = table("events", (v, id) => {
    const states = new Set(
      reader
        .all(id, "state")
        .filter(isStr)
        .map((s) => s[1]),
    );
    const finals = [...states].filter((s) => FINAL_EVENT_STATES.has(s));
    return finals.length > 1
      ? undefined
      : Object.freeze({ ...(reader.plain(v) as object), state: eventStateOf(reader, id) });
  });
  for (const [key, e] of Object.entries(events))
    if (e === undefined) {
      fail("INVALID_ENUM_VALUE", at("events", key));
      delete events[key];
    }

  const questions = table("questions", (v, id) => {
    const q = reader.plain(v) as Record<string, unknown>;
    // §5 rule 3: both markers read as resolved.
    if (q.resolved !== undefined && reader.all(id, "superseded").length > 0) delete q.superseded;
    return Object.freeze(q) as ServiceControlQuestion;
  });

  // Every entry is read before the problems are frozen.
  const state = {
    approvals: Object.freeze(approvals),
    ...optional("service", whole("service")),
    ...optional("status", whole("status")),
    ...optional("lifecycle", whole("lifecycle")),
    bindings: Object.freeze(table("bindings", (v) => plain<ServiceControlRecord>(v))),
    pairing: Object.freeze(table("pairing", (v) => plain<ServiceControlPairing>(v))),
    questions: Object.freeze(questions),
    requests: Object.freeze(table("requests", (v) => plain<ServiceControlRequest>(v))),
    answers: Object.freeze(table("answers", (v) => plain<ServiceControlAnswer>(v))),
    cancels: Object.freeze(table("cancels", (v) => plain<ServiceControlCancel>(v))),
    events: Object.freeze(events as Record<string, ServiceControlEvent>),
  };
  return Object.freeze({ usable: true, problems: Object.freeze(problems), ...state });
}

const optional = <K extends string, V>(key: K, value: V | undefined) =>
  (value === undefined ? {} : { [key]: value }) as Partial<Record<K, V>>;
