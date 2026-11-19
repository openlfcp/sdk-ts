// SERVICE-CONTROL-TEST-VECTORS-01 handlers (SERVICE-CONTROL-PROFILE-01 §12):
// admission SC0 to SC7 of every change against its causal history, and the
// delivery orders of the behavioral cases through the replica, all through
// @openlfcp/shared-objects/service-control. The writer's class is derived
// here, as the SDK's caller derives it: the signer's class from C's Control
// state at the unit's control_ref (fixtures.control_states), then `service`
// from the approvals of the change's pre-state; it must be the class the
// case states.

import { fromBase64url, fromHex, type PrincipalId, principalId, resourceId } from "@openlfcp/core";
import { checkChange } from "@openlfcp/shared-objects/admission";
import {
  checkServiceControlUnit,
  ServiceControlAdmission,
  type ServiceControlOptions,
  ServiceControlReplica,
  type ServiceControlValidation,
  type ServiceControlWriter,
  serviceControlSignerClass,
} from "@openlfcp/shared-objects/service-control";
import { check, equalCheck, outcomeCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, VectorCase } from "../runner.js";

// biome-ignore lint/suspicious/noExplicitAny: corpus JSON
type Json = any;

interface Device {
  readonly kind: number;
  readonly root: string;
  readonly bound_in_c: boolean;
  readonly active: boolean;
}
interface ControlState {
  readonly owner: string;
  readonly genesis_signer: string;
  readonly devices: Readonly<Record<string, Device>>;
}
export interface Fixtures {
  readonly resources: Readonly<Record<string, string>>;
  readonly principals: Readonly<Record<string, { readonly id_hex: string; readonly ref: string }>>;
  readonly control_states: Readonly<Record<string, ControlState>>;
}

export const fixturesOf = (context: HandlerContext) => context.suite.fixtures as Fixtures;
const idOf = (f: Fixtures, label: string): PrincipalId => {
  const p = f.principals[label];
  if (p === undefined) throw new Error(`no principal ${label}`);
  return principalId(fromHex(p.id_hex));
};

/** C's options for a unit decided at `controlRef`: its Genesis owner and signer. */
export function optionsAt(f: Fixtures, controlRef: string): ServiceControlOptions {
  const state = f.control_states[controlRef];
  if (state === undefined) throw new Error(`no control state ${controlRef}`);
  return {
    resource: resourceId(fromBase64url(f.resources.C as string)),
    root: idOf(f, state.owner),
    genesisSigner: idOf(f, state.genesis_signer),
  };
}

/** The verified unit's writer: the signer's class at control_ref, from C's Control state. */
export function writerOf(f: Fixtures, c: VectorCase): ServiceControlWriter {
  const i = c.inputs as Json;
  const state = f.control_states[i.control_ref] as ControlState;
  const device = state.devices[i.writer];
  const signer = idOf(f, i.writer);
  return {
    signer,
    actorSeq: BigInt(i.unit_actor_seq),
    signerClass: serviceControlSignerClass({
      owner: idOf(f, state.owner),
      signer,
      ...(device === undefined
        ? {}
        : {
            device: {
              kind: device.kind,
              root: idOf(f, device.root),
              boundInC: device.bound_in_c,
              active: device.active,
            },
          }),
    }),
  };
}

export const bytesOf = (c: VectorCase) => fromHex((c.inputs as Json).automerge_change.hex);

/** Admits one change case into `admission`: the per-unit checks, then §4. Returns the class. */
export function admit(admission: ServiceControlAdmission, f: Fixtures, c: VectorCase) {
  const change = checkChange(bytesOf(c));
  const writer = writerOf(f, c);
  checkServiceControlUnit(change, writer, optionsAt(f, (c.inputs as Json).control_ref));
  return admission.accept(change, writer);
}

const caseOf = (context: HandlerContext, id: string): VectorCase => {
  const c = context.caseById(id);
  if (c === undefined) throw new Error(`no case ${id}`);
  return c;
};

/** The change's own facts: its hash, actor, Automerge sequence and dependencies. */
function changeFacts(c: VectorCase): Check {
  const i = c.inputs as Json;
  return check("outcome/change", () => {
    const change = checkChange(bytesOf(c));
    if (change.hash !== i.change_hash) return `hash ${change.hash}, not ${i.change_hash}`;
    if (change.actor !== i.automerge_actor) return `actor ${change.actor}`;
    if (change.seq !== i.automerge_seq) return `seq ${change.seq}`;
    return JSON.stringify([...change.deps].sort()) === JSON.stringify([...i.deps].sort()) || "deps";
  });
}

/** §4: a change against its causal history (every history change admitted first). */
export const profileChange: Handler = (c, context) => {
  const f = fixturesOf(context);
  const i = c.inputs as Json;
  const admission = new ServiceControlAdmission(optionsAt(f, i.control_ref));
  const checks: Check[] = [changeFacts(c)];
  for (const h of ((c.context as Json)?.history ?? []) as { case: string }[]) {
    try {
      admit(admission, f, caseOf(context, h.case));
    } catch (e) {
      return {
        checks: [...checks, { name: "outcome", ok: false, message: `history ${h.case}: ${e}` }],
      };
    }
  }
  const change = checkChange(bytesOf(c));
  checks.push(
    equalCheck(
      "outcome/writer_class",
      i.writer_class,
      admission.writerClassAt(change.deps, writerOf(f, c)),
    ),
  );
  let refusal: { code: string; diagnostic: string; message: string } | undefined;
  try {
    admit(admission, f, c);
  } catch (e) {
    const err = e as { code?: string; diagnostic?: string; message?: string };
    refusal = {
      code: err.code ?? "?",
      diagnostic: err.diagnostic ?? "?",
      message: err.message ?? String(e),
    };
  }
  const expected = c.expected as Json;
  if (expected.valid === true)
    checks.push(
      check(
        "outcome",
        () => refusal === undefined || `refused: ${refusal.diagnostic} (${refusal.message})`,
      ),
    );
  else {
    checks.push(outcomeCheck("outcome", expected.error.code, refusal?.code ?? null));
    checks.push(
      equalCheck("outcome/diagnostic", expected.error.diagnostic, refusal?.diagnostic ?? null),
    );
  }
  return {
    checks,
    report:
      refusal === undefined
        ? { outcome: "accept" }
        : { outcome: refusal.code, diagnostic: refusal.diagnostic },
  };
};

// ---------------------------------------------------------------------------
// behavioral: delivery orders through the replica

const Q1 = "0196f2a0-0000-7000-8000-000000000011";
const A1 = "0196f2a0-0000-7000-8000-000000000021";
const A2 = "0196f2a0-0000-7000-8000-000000000022";
const R1 = "0196f2a0-0000-7000-8000-000000000001";
const R2 = "0196f2a0-0000-7000-8000-000000000002";

interface Run {
  readonly admitted: string[];
  readonly refused: Record<string, string>;
  readonly replica: ServiceControlReplica;
  /** The state readers saw after each admitted step, by case name. */
  readonly after: Map<string, ServiceControlValidation>;
}

function deliver(context: HandlerContext, names: readonly string[]): Run {
  const f = fixturesOf(context);
  const first = caseOf(context, names[0] as string);
  const replica = ServiceControlReplica.empty(optionsAt(f, (first.inputs as Json).control_ref));
  const byHash = new Map<string, string>();
  const admitted: string[] = [];
  const refused: Record<string, string> = {};
  const after = new Map<string, ServiceControlValidation>();
  for (const name of names) {
    const c = caseOf(context, name);
    byHash.set((c.inputs as Json).change_hash, name);
    const r = replica.receiveChanges([{ ...writerOf(f, c), bytes: bytesOf(c) }]);
    for (const h of r.admitted) {
      const n = byHash.get(h) ?? h;
      admitted.push(n);
      after.set(n, replica.validate());
    }
    for (const x of r.refused)
      refused[x.hash === undefined ? name : (byHash.get(x.hash) ?? x.hash)] = x.diagnostic;
  }
  return { admitted, refused, replica, after };
}

/** An event as the corpus states it: absent, its state, or state{code}. */
const eventOf = (s: ServiceControlValidation, id: string) => {
  const e = s.events[id];
  return e === undefined ? "absent" : e.code === undefined ? e.state : `${e.state}{${e.code}}`;
};

type StateField = (run: Run, s: ServiceControlValidation, context: HandlerContext) => unknown;
const json = (v: unknown) => JSON.stringify(v);
const STATE: Readonly<Record<string, StateField>> = {
  question: (_r, s) => {
    const q = s.questions[Q1];
    if (q === undefined) return "absent";
    if (q.resolved !== undefined) return `resolved by ${q.resolved.answerId}`;
    return q.superseded !== undefined ? "superseded" : "open";
  },
  event_a1: (_r, s) => eventOf(s, A1),
  event_a2: (_r, s) => eventOf(s, A2),
  // The raw markers of questions[q1], §5 rule 3 aside.
  holds_resolved: (r) => r.replica.valuesAt(["questions", Q1, "resolved"]).length > 0,
  holds_superseded: (r) => r.replica.valuesAt(["questions", Q1, "superseded"]).length > 0,
  // The concurrent maps held at approvals[p:<B>].
  approval_maps: (r, _s, context) =>
    r.replica.valuesAt(["approvals", fixturesOf(context).principals.B?.ref as string]).length,
  status_state: (_r, s) => s.status?.state,
  base_approvals_unrevoked: (_r, s) =>
    Object.values(s.approvals).filter((a) => a.role === "base" && !a.revoked).length,
  heartbeatAt: (_r, s) => s.status?.heartbeatAt,
  message: (_r, s) => s.status?.message,
  request: (_r, s) => (s.requests[R1] === undefined ? "absent" : "present"),
  // unknown_op_no_effect names r2; request_deleted_before_and_after_final r1.
  event: (_r, s) => {
    const e = s.events[R2] ?? s.events[R1];
    return e === undefined ? "absent" : e.state;
  },
  code: (_r, s) => s.events[R2]?.code,
  ...Object.fromEntries(
    (["bindings", "service", "status"] as const).map((k) => [
      `${k}_unchanged`,
      ((r: Run, s: ServiceControlValidation) =>
        json(s[k]) === json(r.after.get("unknown_op_request")?.[k])) as StateField,
    ]),
  ),
};

/** §3, §5, §10 across delivery orders: what is admitted, refused, and the state readers see. */
export const controlDocument: Handler = (c, context) => {
  const i = c.inputs as Json;
  const e = c.expected as Json;
  const runs = (i.orders as { case: string }[][]).map((o) =>
    deliver(
      context,
      o.map((x) => x.case),
    ),
  );
  const checks: Check[] = [];
  for (const [n, run] of runs.entries()) {
    const at = runs.length === 1 ? "" : `/order-${n + 1}`;
    const state = run.replica.validate();
    checks.push(equalCheck(`admitted${at}`, [...e.admitted].sort(), [...run.admitted].sort()));
    checks.push(equalCheck(`refused${at}`, e.refused, run.refused));
    for (const [k, want] of Object.entries(e.state as Record<string, unknown>)) {
      const read = STATE[k];
      checks.push(
        read === undefined
          ? { name: `state/${k}${at}`, ok: false, message: `no reader for ${k}` }
          : equalCheck(`state/${k}${at}`, want, read(run, state, context)),
      );
    }
  }
  if (runs.length > 1) {
    const [a, b] = runs as [Run, Run];
    checks.push(equalCheck("state/same_document", a.replica.heads(), b.replica.heads()));
    checks.push(
      equalCheck("state/same_state", json(a.replica.validate()), json(b.replica.validate())),
    );
  }
  return { checks, report: { admitted: runs[0]?.admitted, refused: runs[0]?.refused } };
};

export const SERVICE_CONTROL_HANDLERS: Readonly<Record<string, Handler>> = {
  "validation/profile_change": profileChange,
  "behavioral/control_document": controlDocument,
};
