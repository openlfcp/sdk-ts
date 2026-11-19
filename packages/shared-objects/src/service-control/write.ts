import * as A from "@automerge/automerge";
import { dataEpoch, LfcpError } from "@openlfcp/core";
import {
  SERVICE_CONTROL_PROFILE_ID,
  SERVICE_CONTROL_ROOT_KEYS,
  type ServiceControlRootKey,
} from "./values.js";

/**
 * The writes of SERVICE-CONTROL-PROFILE-01 §3, as intents: one change
 * carries one or several of them (e.g. the service deleting a final
 * request with its event, cancel and pairing entry). Values are plain
 * JavaScript: strings are written as ImmutableString, non-negative
 * integers (number or bigint) as uint, booleans, arrays as lists and
 * objects as maps. In `*.put` intents a field set to `null` is deleted;
 * fields not named are left as they are (writers never delete another
 * writer's field, §11). Which intents a writer may use is the mutation
 * table's business: ServiceControlReplica.write admits the change before
 * it is returned, so a change admission would refuse is never sent.
 */
export type ServiceControlIntent =
  /** §2.2: the initial change, by the Genesis signer in its unit 1. */
  | { readonly intent: "initialize"; readonly attemptId: string; readonly createdAt: string }
  // root / personal
  | {
      readonly intent: "approval.create";
      readonly approval: {
        readonly role: "base" | "section";
        readonly resource: string;
        readonly principal: string;
        readonly certDigest: string;
        readonly certId: string;
        readonly generation: number | bigint;
        readonly origin: string;
        readonly at: string;
      };
    }
  | { readonly intent: "approval.revoke"; readonly principal: string; readonly at: string }
  | {
      readonly intent: "request.create";
      readonly rid: string;
      readonly request: {
        readonly op: string;
        readonly binding?: string;
        readonly generation?: number | bigint;
        readonly args: Readonly<Record<string, unknown>>;
        readonly client: { readonly app: string; readonly protocol: number | bigint };
        readonly at: string;
      };
    }
  | {
      readonly intent: "answer.create";
      readonly aid: string;
      readonly answer: {
        readonly qid: string;
        readonly snapshotHash: string;
        readonly choice: string;
        readonly at: string;
      };
    }
  | {
      readonly intent: "cancel.create";
      readonly rid: string;
      readonly cancel: { readonly reason: "user" | "mismatch" | "expired"; readonly at: string };
    }
  // service
  | {
      readonly intent: "service.put" | "status.put" | "lifecycle.put";
      readonly fields: Readonly<Record<string, unknown>>;
    }
  | {
      readonly intent: "binding.put";
      readonly binding: string;
      readonly fields: Readonly<Record<string, unknown>>;
    }
  | {
      readonly intent: "pairing.create";
      readonly rid: string;
      readonly pairing: {
        readonly descriptor: string;
        readonly principal: string;
        readonly fp: string;
        /** Fields this version does not name (§2.1), within the size limit. */
        readonly [unknownField: string]: unknown;
      };
    }
  | {
      readonly intent: "question.create";
      readonly qid: string;
      readonly question: Readonly<Record<string, unknown>>;
    }
  | {
      readonly intent: "question.resolve";
      readonly qid: string;
      readonly resolved: {
        readonly answerId: string;
        readonly choice: string;
        readonly at: string;
      };
    }
  | { readonly intent: "question.supersede"; readonly qid: string; readonly by: string }
  /**
   * §6.2: creates `events[id]`, or moves it on: `state` and `at` are
   * written, `code` and `detail` written when given and deleted otherwise
   * (a retryable code does not outlive its state).
   */
  | {
      readonly intent: "event.put";
      readonly id: string;
      readonly state: string;
      readonly code?: string;
      readonly detail?: string;
      readonly at: string;
    }
  | {
      readonly intent: "delete";
      readonly container:
        | "bindings"
        | "pairing"
        | "questions"
        | "requests"
        | "answers"
        | "cancels"
        | "events";
      readonly key: string;
    };

type Doc = Record<string, unknown>;
type Backend = ReturnType<typeof A.getBackend>;

/** Writes `value` at `target[key]` as §2.1 types it (ImmutableString, uint, map, list). */
export function putScValue(
  target: Doc | unknown[],
  key: string | number,
  value: unknown,
  backend: Backend,
): void {
  const map = target as Doc;
  if (typeof value === "string") map[key] = new A.ImmutableString(value);
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0)
      throw new LfcpError("PROFILE_INVALID", `${String(key)}: ${value} is not a uint`);
    map[key] = new A.Uint(value);
  } else if (typeof value === "bigint") {
    // Uint's JS wrapper is limited to safe numbers; the backend takes the full uint64.
    const id = A.getObjectId(target) as string;
    const n = dataEpoch(value);
    if (Array.isArray(target) && Number(key) === backend.length(id))
      backend.insert(id, Number(key), n, "uint");
    else backend.put(id, key, n, "uint");
  } else if (typeof value === "boolean") map[key] = value;
  else if (Array.isArray(value)) {
    map[key] = [];
    value.forEach((v, i) => {
      putScValue(map[key] as unknown[], i, v, backend);
    });
  } else if (value !== null && typeof value === "object") {
    map[key] = {};
    for (const [k, v] of Object.entries(value))
      if (v !== undefined) putScValue(map[key] as Doc, k, v, backend);
  } else
    throw new LfcpError("PROFILE_INVALID", `${String(key)}: ${String(value)} has no §2.1 type`);
}

const containerOf = (d: Doc, key: ServiceControlRootKey): Doc => {
  const c = d[key];
  if (c === null || typeof c !== "object" || Array.isArray(c))
    throw new LfcpError("PROFILE_INVALID", `C has no ${key} map: initialize it first`);
  return c as Doc;
};

/** Writes each named field (null deletes it); the map is created when absent. */
function putFields(
  parent: Doc,
  key: string,
  fields: Readonly<Record<string, unknown>>,
  b: Backend,
) {
  let entry = parent[key];
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    parent[key] = {};
    entry = parent[key];
  }
  const map = entry as Doc;
  for (const [field, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (value === null) delete map[field];
    else putScValue(map, field, value, b);
  }
}

/** Creates `parent[key]` as one whole map (§3: the creating change writes all its fields). */
function create(parent: Doc, key: string, value: Readonly<Record<string, unknown>>, b: Backend) {
  putScValue(parent, key, value, b);
}

/** Applies one intent to a live document proxy. */
export function applyServiceControlIntent(d: Doc, i: ServiceControlIntent): void {
  const b = A.getBackend(d as A.Doc<Doc>);
  switch (i.intent) {
    case "initialize":
      if (Object.keys(d).length > 0) throw new LfcpError("PROFILE_INVALID", "C is initialized");
      putScValue(d, "profile", SERVICE_CONTROL_PROFILE_ID, b);
      putScValue(d, "meta", { attemptId: i.attemptId, createdAt: i.createdAt }, b);
      for (const key of SERVICE_CONTROL_ROOT_KEYS.slice(2)) d[key] = {};
      return;
    case "approval.create":
      create(containerOf(d, "approvals"), i.approval.principal, i.approval, b);
      return;
    case "approval.revoke": {
      const entry = containerOf(d, "approvals")[i.principal];
      if (entry === null || typeof entry !== "object")
        throw new LfcpError("PROFILE_INVALID", `no approval ${i.principal} to revoke`);
      putScValue(entry as Doc, "revoked", { at: i.at }, b);
      return;
    }
    case "request.create":
      create(containerOf(d, "requests"), i.rid, i.request, b);
      return;
    case "answer.create":
      create(containerOf(d, "answers"), i.aid, i.answer, b);
      return;
    case "cancel.create":
      create(containerOf(d, "cancels"), i.rid, i.cancel, b);
      return;
    case "service.put":
    case "status.put":
    case "lifecycle.put": {
      const key = i.intent.slice(0, -4) as "service" | "status" | "lifecycle";
      const c = containerOf(d, key);
      for (const [field, value] of Object.entries(i.fields)) {
        if (value === undefined) continue;
        if (value === null) delete c[field];
        else putScValue(c, field, value, b);
      }
      return;
    }
    case "binding.put":
      putFields(containerOf(d, "bindings"), i.binding, i.fields, b);
      return;
    case "pairing.create":
      create(containerOf(d, "pairing"), i.rid, i.pairing, b);
      return;
    case "question.create":
      create(containerOf(d, "questions"), i.qid, i.question, b);
      return;
    case "question.resolve":
    case "question.supersede": {
      const q = containerOf(d, "questions")[i.qid];
      if (q === null || typeof q !== "object")
        throw new LfcpError("PROFILE_INVALID", `no question ${i.qid}`);
      if (i.intent === "question.resolve") putScValue(q as Doc, "resolved", i.resolved, b);
      else putScValue(q as Doc, "superseded", { by: i.by }, b);
      return;
    }
    case "event.put": {
      const events = containerOf(d, "events");
      const fields = {
        state: i.state,
        ...(i.code === undefined ? {} : { code: i.code }),
        ...(i.detail === undefined ? {} : { detail: i.detail }),
        at: i.at,
      };
      const e = events[i.id];
      if (e === null || typeof e !== "object") {
        create(events, i.id, fields, b);
        return;
      }
      putFields(events, i.id, { code: null, detail: null, ...fields }, b);
      return;
    }
    case "delete": {
      const c = containerOf(d, i.container);
      if (!Object.hasOwn(c, i.key))
        throw new LfcpError("PROFILE_INVALID", `no ${i.container} entry ${i.key} to delete`);
      delete c[i.key];
      return;
    }
  }
}
