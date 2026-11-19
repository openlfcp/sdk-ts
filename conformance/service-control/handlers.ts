// SERVICE-CONTROL-TEST-VECTORS-01 handlers (SERVICE-CONTROL-PROFILE-01 §12):
// admission SC0 to SC7 of every change against its causal history, through
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
