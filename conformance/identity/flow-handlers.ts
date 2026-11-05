// IDENTITY-FLOW-FIXTURES-01 handlers (IDENTITY-PROFILE-01 §12.3,
// LFCP-04-412): every flow fixture step by step, with each step's outcome in
// the lfcp-identity-outcomes/1 vocabulary as the handler report.
//
// A step that names a case runs that case (wire or profile) with the
// handlers of this directory and adds the facts its kind derives: after a
// Control Record the device table of §79 (every device's row, activity,
// registration, revocations, the cascade), exposure and the rotation it
// calls for (§8.4), the final frontier of a KEY_EPOCH; after a Data Unit of
// the Identity Resource the change it carries and its writer class (§2.3).
// A step with `bytes_of` sends those exact bytes to a coordinator holding
// every record the flow accepted (W §47 compare-and-swap: the same ACK for
// bytes already in the chain, CONTROL_HEAD_MISMATCH when another record
// took the place). A `phase_input` is classified with the client's §9.2
// classifiers. The other steps are the client's computations
// (reconciliation, ledger, rotator test, feasibility, frontier), each with
// the client API that implements it; a step sdk-ts cannot express on the
// fixture's bytes is N/A with its reason, never a pass.

import {
  candidateEvidence,
  checkIssuance,
  classifyConsume,
  classifyPackage,
  classifyRegister,
  classifyRevoke,
  classifyRotate,
  exposingRevocationsSince,
  identityWriterClass,
  leafPayload,
  MASK_PRESETS,
  planReconciliation,
  readersAt,
  recordSeq,
  rotatorTest,
  signChain,
  verifiedFrontier,
} from "@openlfcp/client";
import { bytesEqual, fromHex, hash32, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { unframeChange } from "@openlfcp/shared-objects/admission";
import {
  activeDevice,
  type ControlRecord,
  type ControlState,
  certificateChain,
  decodeControlRecord,
  deviceCertificatePayloadFromCbor,
  parseDataUnit,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { decodeStrict } from "@openlfcp/wire/cbor";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { equalCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, HandlerResult, VectorCase } from "../runner.js";
import { openSpec } from "../spec.mjs";
import {
  cert,
  chainAt,
  chainOf,
  chainOfCert,
  contextOf,
  type FlowCase,
  type FlowStep,
  idOf,
  party,
  recordOf,
  recordsAt,
  wire,
  wireCase,
} from "./corpus.js";
import { certificateLabel, principalLabel, resourceLabel } from "./labels.js";
import { IDENTITY_PROFILE_HANDLERS } from "./profile-handlers.js";
import { controlState, deviceRow, IDENTITY_WIRE_HANDLERS } from "./wire-handlers.js";

// biome-ignore lint/suspicious/noExplicitAny: corpus JSON
type Json = any;
type Report = Record<string, unknown>;

// ---------------------------------------------------------------------------
// the cases a step names

const PROFILE_PATH = "test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.json";
const profileSuite = openSpec().readJson(PROFILE_PATH) as {
  readonly cases: readonly VectorCase[];
};
const profileById = new Map(profileSuite.cases.map((c) => [c.id, c]));
const wireById = new Map((wire.cases as readonly VectorCase[]).map((c) => [c.id, c]));
const contextFor = (suite: Json, byId: Map<string, VectorCase>): HandlerContext => ({
  suite,
  caseById: (id) => byId.get(id),
});
const WIRE_CONTEXT = contextFor(wire, wireById);
const PROFILE_CONTEXT = contextFor(profileSuite, profileById);

const changeNames = new Map(
  profileSuite.cases
    .filter((c) => c.id.startsWith("change."))
    .map((c) => [(c.inputs as Json).change_hash as string, c.id]),
);

interface CaseRun {
  readonly case: VectorCase;
  readonly result: HandlerResult;
  readonly report: Report;
  readonly ok: boolean;
}

/** Runs a `wire:` or `profile:` case with its handler. */
async function runCase(ref: string): Promise<CaseRun> {
  const [suite, id] = ref.split(":") as [string, string];
  const profile = suite === "profile";
  const c = (profile ? profileById : wireById).get(id);
  if (c === undefined) throw new Error(`no case ${ref}`);
  const handlers = profile ? IDENTITY_PROFILE_HANDLERS : IDENTITY_WIRE_HANDLERS;
  const handler = handlers[`${c.type}/${c.kind}`];
  if (handler === undefined) throw new Error(`no handler for ${c.type}/${c.kind}`);
  const result = await handler(c, profile ? PROFILE_CONTEXT : WIRE_CONTEXT);
  if (result.report === undefined) throw new Error(`${ref} reports nothing`);
  return { case: c, result, report: result.report, ok: result.checks.every((x) => x.ok) };
}

// ---------------------------------------------------------------------------
// facts a step derives

const isControl = (c: { readonly kind: string }) => c.kind === "control_record";

/** The device table of §79 after a Control Record, as the flow steps state it. */
function deviceTable(state: ControlState): Report {
  const rows: Report = {};
  const active: Record<string, boolean> = {};
  const registered: string[] = [];
  const suspended: string[] = [];
  for (const id of state.devices.keys()) {
    const label = principalLabel(fromHex(id));
    const row = deviceRow(state, id);
    rows[label] = row;
    active[label] = row.active as boolean;
    if (row.registered) registered.push(label);
    if (row.suspended) suspended.push(label);
  }
  return {
    ...rows,
    active,
    registered: registered.sort(),
    suspended: suspended.sort(),
    revoked: controlState(state).revoked,
  };
}

/** A KEY_EPOCH's final frontier: a contiguous count, or with its extra ranges (§19.1, W §28.1). */
function frontierOf(record: ControlRecord): Report | undefined {
  if (record.body.type !== "KEY_EPOCH") return undefined;
  return Object.fromEntries(
    record.body.finalFrontier.map((h) => [
      principalLabel(h.principalId),
      h.extras.length === 0
        ? Number(h.contiguous)
        : {
            contiguous: Number(h.contiguous),
            extra_ranges: h.extras.map((r) => r.map(Number)),
          },
    ]),
  );
}

/** Facts of an accepted Control Record step. */
function controlFacts(id: string): Report {
  const chain = chainAt(id);
  const record = decodeControlRecord(recordOf(id));
  const out: Report = deviceTable(chain.state);
  if (record.body.type === "DEVICE_REVOKE") {
    const after = chain.state;
    out.exposing = exposingRevocationsSince(chain).some((e) => e.seq === after.seq);
    // §8.4: an exposing revocation calls for one rotation of the epoch it is in.
    out.rotations = out.exposing ? 1 : 0;
    if (record.body.reason === 3n && record.body.approval !== undefined)
      out.approval = toHex(record.body.approval);
  }
  const f = frontierOf(record);
  if (f !== undefined) out.frontier = f;
  // §9.2: the Register phase of the installation that sent this DEVICE_GRANT.
  if (record.body.type === "DEVICE_GRANT") {
    const own = toHex(record.signed.id);
    out.phase = classifyRegister(chain, {
      root: record.body.root,
      chain: record.body.chain,
      ...(record.body.pairingDevice === undefined ? {} : { pairingPhase2: true }),
      isOwnRecord: (rid) => rid === own,
    });
  }
  return out;
}

/** The change a Data Unit of the Identity Resource carries and its writer's class (§2.3). */
function carries(c: VectorCase, report: Report): Report | undefined {
  const post = report.post_state as { plaintext_hex?: string } | null;
  if (post?.plaintext_hex === undefined) return undefined;
  const unit = parseDataUnit(fromHex((c.inputs as Json).cose_sign1.hex)).payload;
  const chain = chainOf(recordsAt(((c.context as Json).latest as { case: string }).case));
  if (chain.state.dataProfile !== "org.openlfcp.identity.v1") return undefined;
  const change = unframeChange(fromHex(post.plaintext_hex));
  const at = chain.stateAt(unit.controlHead) as ControlState;
  return {
    change: changeNames.get(change.hash) ?? change.hash,
    change_hash: change.hash,
    writer_class: identityWriterClass(at, at.owner.principalId, unit.actor),
  };
}

/** A Data Unit refused for equivocation: every unit of that (actor, sequence) is excluded (W §26.2). */
function equivocationFacts(c: VectorCase, report: Report): Report | undefined {
  if (report.outcome !== "ACTOR_EQUIVOCATION") return undefined;
  const other = ((c.context as Json).accepted_unit as { case: string }).case;
  return { excluded: [other, c.id].sort(), request_seen_by_A: false };
}

// ---------------------------------------------------------------------------
// the coordinator of a flow (W §47)

/**
 * Every record the flow commits (its accepted Control Record steps outside
 * `aside`, with their chains), by record ID hex: the coordinator a
 * `bytes_of` step talks to has seen the whole history of the fixture, in
 * which a competing record may have been committed first (F06).
 */
function coordinatorRecords(f: FlowCase): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of f.inputs.steps) {
    const ref = s.case;
    if (ref === undefined || !ref.startsWith("wire:") || s.aside === true) continue;
    const id = ref.slice(5);
    if (!isControl(wireCase(id)) || validateControlChain(recordsAt(id)).kind !== "linear") continue;
    for (const bytes of recordsAt(id)) {
      const r = decodeControlRecord(bytes);
      const label =
        [...(wire.cases as readonly Json[])].find(
          (x) => x.kind === "control_record" && x.inputs.record_id?.hex === toHex(r.signed.id),
        )?.id ?? toHex(r.signed.id);
      out.set(toHex(r.signed.id), label);
    }
  }
  return out;
}

/** CONTROL_PUT of exact bytes to that coordinator (W §47): same ACK, or CONTROL_HEAD_MISMATCH. */
function sendBytes(f: FlowCase, ref: string): Report {
  const id = ref.slice(5);
  const bytes = recordOf(id);
  const record = decodeControlRecord(bytes);
  const held = coordinatorRecords(f);
  if (held.has(toHex(record.signed.id)))
    return {
      outcome: "same ACK",
      accepted_ids: [toHex(record.signed.id)],
      transition: false,
    };
  // Another record holds this record's place: its previous record is no longer the head.
  for (const [rid, label] of held) {
    const other = decodeControlRecord(
      recordsAt(label).find((b) => toHex(sha256(b)) === rid) as Uint8Array,
    );
    if (
      other.payload.prevControlId !== null &&
      record.payload.prevControlId !== null &&
      bytesEqual(other.payload.prevControlId, record.payload.prevControlId)
    )
      return { outcome: "CONTROL_HEAD_MISMATCH", coordinator_head: label };
  }
  const r = validateControlChain([...contextOf(id), bytes]);
  return r.kind === "linear"
    ? { outcome: "accept", accepted_ids: [toHex(record.signed.id)] }
    : { outcome: r.wireCode };
}

// ---------------------------------------------------------------------------
// phases (§9.2)

function phaseFacts(p: Json): Report {
  const chain = chainAt(String(p.state).replace(/^wire:/, ""));
  let phase: string;
  switch (p.phase) {
    case "consume":
      phase = classifyConsume(chain.state, idOf(p.root), idOf(p.device), hash32(fromHex(p.digest)));
      break;
    case "register": {
      const own = p.own === true;
      phase = classifyRegister(chain, {
        root: idOf(p.root),
        chain: chainOfCert(p.certificate),
        isOwnRecord: () => own,
      });
      break;
    }
    case "revoke":
      phase = classifyRevoke(chain.state, idOf(p.root), idOf(p.device));
      break;
    case "rotate": {
      const at = recordSeq(chain, sha256(recordOf(String(p.revoked_at).replace(/^wire:/, ""))));
      if (at === undefined) throw new Error("the revocation is not on the chain");
      phase = classifyRotate(chain, at, true);
      break;
    }
    default:
      throw new Error(`unknown phase ${p.phase}`);
  }
  return {
    phase,
    proposes: phase === "pending",
    signs: phase !== "superseded",
    not_superseded: phase !== "superseded",
  };
}

// ---------------------------------------------------------------------------
// client computations without a case

type Special = (f: FlowCase, step: FlowStep, done: readonly Report[]) => Promise<Report> | Report;
const na = (reason: string): Report => ({ outcome: "N/A", not_applicable: reason });
const stepOf = (f: FlowCase, n: number) => f.inputs.steps.find((s) => s.n === n) as FlowStep;
const wireId = (s: FlowStep) => String(s.case).replace(/^wire:/, "");

/** The units a replica accepted at a state: each classified at that state (§19.1). */
async function acceptedAt(head: string, units: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  for (const u of units) {
    const c = wireCase(u);
    const r = await IDENTITY_WIRE_HANDLERS["validation/data_unit"]?.(
      {
        ...c,
        context: { ...(c.context as Json), latest: { case: head } },
      } as unknown as VectorCase,
      WIRE_CONTEXT,
    );
    if (r?.report?.outcome === "accept") out.push(u);
  }
  return out;
}

const SPECIALS: Readonly<Record<string, Special>> = {
  // R1 rebuilds at K1: every unit it accepted is classified again at K1 (§19.1, LFCP-023).
  "F01_register_write_revoke_cutoff#9": async (f) => {
    const units = [2, 3, 4, 6].map((n) => wireId(stepOf(f, n)));
    const kept = await acceptedAt(wireId(stepOf(f, 7)), units);
    return {
      outcome: "rebuilt",
      excluded: units.filter((u) => !kept.includes(u)),
      surfaced_as_stale: kept.length < units.length,
    };
  },
  // §7.1 step 3: every epoch of X the reconciler holds, to each of its root's devices not in the ledger.
  "F05_reconciliation#5": (f, step) => {
    const X = chainAt(wireId(stepOf(f, 4)));
    const R = idOf("OWNER");
    const before = step.ledger_before as Record<string, number[]>;
    const after: Record<string, number[]> = {};
    for (const reader of readersAt(X.state)) {
      const d = X.state.devices.get(toHex(reader.principalId));
      if (d === undefined || !bytesEqual(d.root, R)) continue;
      const label = principalLabel(reader.principalId);
      const have = before[label] ?? [];
      const epochs = [...X.state.epochs.keys()].map(Number);
      after[label] = [...new Set([...have, ...epochs])].sort((a, b) => a - b);
    }
    return { outcome: "packages sent", ledger_after: after };
  },
  // §7.1: a second run plans no record, and the ledger holds every package.
  "F05_reconciliation#7": (f) => {
    const I = chainAt(wireId(stepOf(f, 1)));
    const X = chainAt(wireId(stepOf(f, 4)));
    const plan = planReconciliation(I, X);
    return {
      outcome: plan.length === 0 ? "nothing to propose" : "proposes",
      records: plan.length,
      packages: 0,
    };
  },
  // §8.1: DEV_A, its revoke phase complete, runs the rotator test on the new head.
  "F06_concurrent_revokes#6": (f) => {
    const t = rotatorTest(chainAt(wireId(stepOf(f, 3))).state, idOf("DEV_A"));
    return { outcome: "rotation test", rotator: t.rotator };
  },
  "F07_invitation_accepted_by_device#6": () =>
    na(
      "IDENTITY-PROFILE-01 §7.2 step 3 writes the roster of DAVE's Identity Resource, for which the fixture supplies no chain, DEK or document; acceptInvitationAsDevice writes it in packages/client/test/identity/accept.test.ts.",
    ),
  "F09_pairing_service#4": () =>
    na(
      "IDENTITY-PROFILE-01 §5.3 step 8 with every candidate offline needs B's persisted candidates and coordinators that do not answer; completePairing returns this state in packages/client/test/identity/pairing.test.ts, not on fixture bytes.",
    ),
  "F09_pairing_service#16": () =>
    na(
      "IDENTITY-PROFILE-01 §5.3 step 8 / §9: resuming from persisted candidates after a restart needs B's journal and storage; covered by packages/client/test/identity/pairing.test.ts, not expressible on fixture bytes.",
    ),
  "F10_request_feasibility#3": () =>
    na(
      "IDENTITY-PROFILE-01 §5.3 step 4: re-confirmation when the descriptor changes is a property of A's approval journal and UI (approvePairing compares the journaled tuple); the fixture gives no request change to replay.",
    ),
  "F10_request_feasibility#7": () =>
    na(
      "IDENTITY-PROFILE-01 §5.3 step 4: a service scope trimmed to nothing is refused by approvePairing before any consume; the fixture gives no request or session to run it on.",
    ),
  "F10_request_feasibility#8": () =>
    na(
      "IDENTITY-PROFILE-01 §5.3 step 5: the re-check after a head change happens inside approvePairing's phase loop; the fixture gives no head change to replay.",
    ),
  // §9.4: a DEK sealed at I8 to a reader of I8 that is not a reader of I9 is not used.
  "F13_durable_phases#10": () => {
    const reads = (id: string) =>
      readersAt(chainAt(id).state).some((r) => bytesEqual(r.principalId, idOf("DEV_A")));
    const DEV_A_reads = { I8: reads("I8_bridge_grant"), I9: reads("I9_device_revoke_dev_a") };
    return {
      outcome: DEV_A_reads.I8 && !DEV_A_reads.I9 ? "fresh DEK (§9.4)" : "same DEK",
      DEV_A_reads,
    };
  },
  "F13_durable_phases#15": (_f, step) => {
    // §9.2: a KEY_EPOCH is committed and no package of it was ledgered: readers wait.
    const ledger = (step.ledger ?? []) as unknown[];
    return { outcome: ledger.length === 0 ? "awaiting key holder" : "packages pending" };
  },
  // §8.3: the frontier from the units the server lets the rotator fetch and that verify.
  "F14_frontier_from_verified_set#5": async () => {
    const server = new MemoryCoordinator();
    const Y = server.seed(recordsAt("Yb1_bridge_out_of_scope"));
    const hosted = server.hosted.get(toHex(Y));
    if (hosted === undefined) throw new Error("not hosted");
    for (const id of [
      "flow.y_dev_a_seq1",
      "flow.y_dev_a_seq2",
      "flow.y_dev_a_seq4",
      "D_bridge_in_y",
    ]) {
      const bytes = fromHex(wireCase(id).inputs.cose_sign1.hex);
      const p = parseDataUnit(bytes).payload;
      hosted.units.set(`${toHex(p.actor)}:${p.actorSeq}`, bytes);
    }
    const chain = chainAt("Yb1_bridge_out_of_scope");
    const channel = await server.network().connect(party("OWNER"), "wss://y.test");
    const frontier = await verifiedFrontier(channel, chain);
    const sets = frontier.map((h) => {
      const seqs: bigint[] = [];
      for (let s = 1n; s <= h.contiguous; s++) seqs.push(s);
      for (const [a, b] of h.extras) for (let s = a; s <= b; s++) seqs.push(s);
      return `${principalLabel(h.principalId)} {${seqs.join(", ")}}`;
    });
    return { outcome: `verified accepted set ${sets.join("; ")}` };
  },
  // §8.4: several exposing revocations in one epoch: one rotation covers them.
  "F15_rotation_policy_by_exposure#7": () => {
    const n = exposingRevocationsSince(chainAt("I13_owner_expels_dev_c")).length;
    return { outcome: n >= 2 ? "one rotation" : `${n} exposing revocation(s)` };
  },
  // W §13.2: both branches known: the chain is in CONTROL_CONFLICT.
  "F16_device_grant_fork#4": (f) => {
    const branches = [2, 3].map((n) => wireId(stepOf(f, n)));
    const r = validateControlChain([
      ...recordsAt(wireId(stepOf(f, 1))),
      ...branches.map((b) => recordOf(b)),
    ]);
    return r.kind === "conflict"
      ? { outcome: "CONTROL_CONFLICT", competing: branches.sort() }
      : { outcome: r.kind === "linear" ? "accept" : r.wireCode };
  },
  "F16_device_grant_fork#5": () =>
    na(
      "IDENTITY-PROFILE-01 §9.7: the client suspends approval, reconciliation and rotation on a conflicted chain (syncChain throws IdentityConflict, covered by packages/client/test/identity/*.test.ts); the fixture gives no operation to suspend.",
    ),
  "F17_revoked_device#5": () =>
    na(
      "LFCP-WIRE-01 §69: the order of pushes and the end of a subscription are the server's; sdk-ts is a client and its identity flows open Resources without a subscription.",
    ),
  "F18_barrier#5": () =>
    na(
      "LFCP-WIRE-01 §100.1: a blocked (herald) client writing on its last validated head is a pre-identity client generation; sdk-ts 0.3 is identity-aware and has no blocked mode. W §81 acceptance of an old-head unit until the epoch closes is F01 step 6.",
    ),
  // None of the devices wrote missing_keys: every package was delivered anyway (§7.1).
  "F19_key_bootstrap#4": (_f, _s, done) => ({
    outcome: done.every((d) => d.outcome === "accept") ? "served anyway" : "not served",
  }),
};

/** Step fields sdk-ts does not derive, with why (field-level N/A). */
const FIELD_NA: Readonly<Record<string, string>> = {
  pre_identity:
    "LFCP-WIRE-01 §100.1: the verdict of a pre-identity validator; sdk-ts has no pre-identity validator (its 0.2 line is not part of this build).",
  herald:
    "LFCP-WIRE-01 §100.1: the persisted blocked state of a herald client; sdk-ts 0.3 is identity-aware and has no blocked mode.",
};

// ---------------------------------------------------------------------------
// one step

/** F10: the presets a manager may offer, by the feasibility check of §5.3 step 4. */
function offeredPresets(id: string): string[] {
  const base = contextOf(id);
  const p1 = chainOf(base);
  const m3 = certificateChain([cert("CERT_M3"), cert("CERT_M2"), cert("CERT_A")], idOf("OWNER"));
  const grant = signControlRecord(
    {
      resourceId: p1.state.resourceId,
      controlSeq: p1.state.seq + 1n,
      prevControlId: p1.state.head,
    },
    { type: "DEVICE_GRANT", root: idOf("OWNER"), chain: m3 },
    party("OWNER"),
  );
  const chain = chainOf([...base, grant.bytes]);
  return (["full", "edit", "read"] as const)
    .filter((preset) => {
      const p = MASK_PRESETS[preset];
      return checkIssuance({
        chain,
        issuer: party("DEV_M3"),
        leaf: leafPayload(idOf("OWNER"), party("DEV_H").descriptor, p.kind as 0, p.mask, []),
      }).feasible;
    })
    .map((p) => `${p[0]?.toUpperCase()}${p.slice(1)}`);
}

/** F09: what a candidate's own chain proves about BRIDGE_O's approved certificate. */
function candidateFacts(id: string): Report {
  const D = idOf("BRIDGE_O");
  const result = cert("CERT_SO").payload;
  const e = candidateEvidence(chainAt(id), D, cert("CERT_SO").payloadDigest, result);
  const state = chainAt(id).state;
  const current = state.devices.get(toHex(D))?.leafId;
  const scope = result.scope.map(resourceLabel);
  const resources = Object.keys(wire.fixtures.resources);
  return {
    leaves: e.leaves.map(certificateLabel),
    proven: e.proven,
    ...(e.usable && current !== null && current !== undefined
      ? { uses: certificateLabel(current) }
      : {}),
    used: e.usable,
    status: e.registration === "active" && !e.proven ? "approval not provable here" : undefined,
    // A Resource outside the approved result's scope is never shown as granted (§5.3 step 8).
    ...Object.fromEntries(
      resources
        .filter((r) => !scope.includes(r) && r !== "I")
        .map((r) => [r, "never shown as granted"]),
    ),
  };
}

/** F13 step 4: phase 2 signs exactly the journaled payload. */
function journalSigning(step: FlowStep): Report {
  const j = step.journal as Json;
  const payload = deviceCertificatePayloadFromCbor(
    decodeStrict(fromHex(j.certificate_payload_cbor)),
  );
  const chain = chainAt(String(step.phase_input.state).replace(/^wire:/, ""));
  const signed = signChain(chain.state, party("DEV_A"), payload);
  return {
    signed_certificate: certificateLabel(signed.leaf.id),
    certificate_payload_matches_journal:
      toHex(signed.leaf.signed.payloadBytes) === j.certificate_payload_cbor,
  };
}

async function runStep(
  f: FlowCase,
  step: FlowStep,
  done: readonly Report[],
  accepted: Set<string>,
): Promise<{ report: Report; ok: boolean }> {
  const key = `${f.id}#${step.n}`;
  const special = SPECIALS[key];
  if (special !== undefined)
    return { report: { n: step.n, ...(await special(f, step, done)) }, ok: true };
  let report: Report = { n: step.n };
  let ok = true;
  if (step.bytes_of !== undefined) {
    report = { ...report, ...sendBytes(f, String(step.bytes_of)) };
  } else if (step.case !== undefined) {
    const run = await runCase(String(step.case));
    ok = run.ok;
    const c = run.case;
    if (String(step.case).startsWith("profile:")) {
      // A profile step is the case itself: its bytes, or its expectations, hold.
      const outcome =
        c.type === "bytes"
          ? run.ok
            ? "exact bytes"
            : "bytes differ"
          : c.type === "behavioral"
            ? run.ok
              ? "see case"
              : "case fails"
            : // A refused change's step outcome is its diagnostic (F10 step 2).
              run.report.outcome === "PROFILE_INVALID" && typeof run.report.diagnostic === "string"
              ? run.report.diagnostic
              : run.report.outcome;
      report = { ...report, ...run.report, outcome };
    } else if (c.kind === "rotator_test") {
      report = { ...report, ...run.report, outcome: run.ok ? "see case" : "case fails" };
      report.tables = run.report.post_state;
    } else {
      report = { ...report, ...run.report };
      if (run.report.outcome === "accept") accepted.add(c.id);
      if (isControl(c) && run.report.outcome === "accept") {
        // Exact bytes already in the chain: the same ACK, and no new state to report (W §47).
        if ((run.report.post_state as Json)?.already_in_chain === true)
          report = { ...report, ack: "same ACK", transition: false };
        else report = { ...report, ...controlFacts(c.id) };
      }
      if (c.kind === "data_unit") {
        const carried = carries(c, run.report);
        if (carried !== undefined) report.carries = carried;
        if (run.report.outcome === "ACTOR_EQUIVOCATION") {
          report = { ...report, ...equivocationFacts(c, run.report) };
          const refused = await refusedCarries(c);
          if (refused !== undefined) report.carries = refused;
        }
        if (run.report.outcome === "AUTHORIZATION_FAILED") report.counted = false;
      }
      if (c.kind === "session_read") {
        const post = run.report.post_state as Json;
        if (post?.read === "prefix") {
          report.status = "revocation proven";
          report.head = post.control_head;
        } else if (run.report.outcome !== "accept") report.status = "access refused";
      }
      if (
        c.kind === "key_package" &&
        run.report.outcome === "accept" &&
        f.id === "F09_pairing_service"
      )
        report.status = "ready";
      if (
        f.id === "F09_pairing_service" &&
        isControl(c) &&
        String(step.branch ?? "").startsWith("X")
      )
        Object.assign(report, candidateFacts(c.id));
      if (f.id === "F10_request_feasibility" && c.id === "device_grant_feasibility_full_depth_4")
        report.offered = offeredPresets(c.id);
      // §8.1 pre-check (previewRevocation): the revoker, active before, must stay active after.
      if (f.id === "F11_revoker_chain_through_target" && c.id.includes("unrecertified")) {
        const issuer = idOf(String((c.inputs as Json).issuer));
        const was = activeDevice(chainOf(contextOf(c.id)).state, issuer) !== undefined;
        const is = activeDevice(chainAt(c.id).state, issuer) !== undefined;
        report.client = was && !is ? "refused by the pre-check" : "proposed";
      }
      if (f.id === "F11_revoker_chain_through_target" && step.n === 5)
        report.rotates = rotatorTest(chainAt(c.id).state, idOf("DEV_E")).rotator;
      if (f.id === "F15_rotation_policy_by_exposure" && c.id === "V2_revoke_dev_c")
        report.descendant_receives_new_epoch = readersAt(chainAt(c.id).state).some((r) =>
          bytesEqual(r.principalId, idOf("DEV_E")),
        );
      if (f.id === "F18_barrier") report.identity_aware = run.report.outcome;
      if (f.id === "F13_durable_phases" && step.ledger !== undefined) report.ledger = step.ledger;
      if (f.id === "F13_durable_phases" && step.n === 13) Object.assign(report, packagePhases(f));
    }
  }
  if (step.phase_input !== undefined) {
    report = { ...report, ...phaseFacts(step.phase_input) };
    if (step.case === undefined && report.outcome === undefined) report.outcome = "done";
    if (step.journal !== undefined && step.phase_input.phase === "register")
      report = { ...report, ...journalSigning(step) };
  }
  if (report.outcome === undefined)
    report = {
      ...report,
      ...na("this step names no case, bytes or phase, and sdk-ts has no computation for it"),
    };
  return { report, ok };
}

/**
 * The change a unit refused for equivocation holds: the unit verifies on
 * its own (W §26.2 refuses the pair, not its bytes), so it is opened as a
 * receiver without the other unit would open it.
 */
async function refusedCarries(c: VectorCase): Promise<Report | undefined> {
  const alone = { ...c, context: { ...(c.context as Json), accepted_unit: undefined } };
  const r = await IDENTITY_WIRE_HANDLERS["validation/data_unit"]?.(
    alone as VectorCase,
    WIRE_CONTEXT,
  );
  return r?.report === undefined ? undefined : carries(c, r.report);
}

/** F13 step 13: package phases from the ledger (§9.5), and the ledger after the send. */
function packagePhases(f: FlowCase): Report {
  const K1 = chainAt("K1_key_epoch").state;
  const ledger = (stepOf(f, 12).ledger ?? []) as { recipient: string; epoch: number }[];
  const phases: Record<string, string> = {};
  for (const who of ["BOB", "CAROL"]) {
    const reader = readersAt(K1).some((r) => bytesEqual(r.principalId, idOf(who)));
    phases[who] = String(
      classifyPackage(
        ledger.some((l) => l.recipient === who && l.epoch === 1),
        reader,
      ),
    );
  }
  const sent = wireCase("flow.f13_kp_epoch1_to_carol");
  return {
    package_phases: phases,
    ledger_after: [
      ...ledger,
      {
        resource: "X",
        epoch: 1,
        recipient: "CAROL",
        package_id: (sent.inputs as Json).object_id.hex,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// final facts

type Final = (f: FlowCase, steps: readonly Report[]) => Promise<Report> | Report;
const _last = (f: FlowCase, pred: (s: FlowStep) => boolean) =>
  [...f.inputs.steps].reverse().find(pred) as FlowStep;
const countRecords = (id: string, pred: (r: ControlRecord) => boolean) =>
  chainAt(id).records.filter(pred).length;

const FINALS: Readonly<Record<string, Final>> = {
  F01_register_write_revoke_cutoff: async (f, steps) => {
    const units = [2, 3, 4].map((n) => wireId(stepOf(f, n)));
    const rebuilt = steps.find((s) => s.n === 9) as Json;
    const r1 = [...units, wireId(stepOf(f, 6))].filter((u) => !rebuilt.excluded.includes(u));
    const r2 = await acceptedAt(wireId(stepOf(f, 7)), [...units, wireId(stepOf(f, 8))]);
    return {
      accepted_epoch_0_units_R1: r1,
      accepted_epoch_0_units_R2: r2,
      replicas_converge: JSON.stringify([...r1].sort()) === JSON.stringify([...r2].sort()),
    };
  },
  F02_cascade_recertify: () => ({
    DEV_B: deviceRow(chainAt("I10_recertify_dev_b").state, toHex(idOf("DEV_B"))),
  }),
  F03_stale_head_reevaluation: (f) => ({
    DEV_B_registered:
      chainAt(wireId(stepOf(f, 4))).state.devices.get(toHex(idOf("DEV_B")))?.registered === true,
    records_added:
      chainAt(wireId(stepOf(f, 4))).records.length - chainAt(wireId(stepOf(f, 1))).records.length,
  }),
  F04_root_standing_lost_regained: (f) => ({
    device_records_added:
      countRecords(wireId(stepOf(f, 4)), (r) => r.body.type === "DEVICE_GRANT") -
      countRecords(wireId(stepOf(f, 1)), (r) => r.body.type === "DEVICE_GRANT"),
  }),
  F05_reconciliation: (f) => {
    const X = chainAt(wireId(stepOf(f, 4))).state;
    return {
      X_devices: Object.fromEntries(
        ["DEV_A", "DEV_B"].map((l) => [l, deviceRow(X, toHex(idOf(l)))]),
      ),
      idempotent:
        planReconciliation(chainAt(wireId(stepOf(f, 1))), chainAt(wireId(stepOf(f, 4)))).length ===
        0,
    };
  },
  F06_concurrent_revokes: (f) => ({
    device_revoke_records: countRecords(
      wireId(stepOf(f, 3)),
      (r) => r.body.type === "DEVICE_REVOKE" && bytesEqual(r.body.device, idOf("DEV_B")),
    ),
  }),
  F07_invitation_accepted_by_device: (f) => ({
    claimant_role: chainAt(wireId(stepOf(f, 3))).state.roles.get(toHex(idOf("DAVE"))),
  }),
  F08_pairing_personal: (f) => {
    const I = chainAt(wireId(stepOf(f, 17))).state;
    return {
      DEV_B_registered_in_I: I.devices.get(toHex(idOf("DEV_B")))?.registered === true,
      approved_payloads: [...I.revoked.values()].filter((r) => r.reason === 3n).length,
      DEV_B_epochs: [19, 20]
        .filter((n) => f.inputs.steps.some((s) => s.n === n))
        .map((n) => Number((wireCase(wireId(stepOf(f, n))).inputs as Json).epoch)),
    };
  },
  "F08.link_reuse_and_equivocation": () => ({}),
  "F08.binding_limit": (f) => {
    const I = chainAt(wireId(stepOf(f, 4))).state;
    return { live_devices_of_OWNER: I.liveBound.get(toHex(idOf("OWNER"))) };
  },
  "F08.forty_sessions": (f) => {
    const I = chainAt(wireId(stepOf(f, 3)));
    return {
      cancelled_sessions: I.records.filter(
        (r) => r.body.type === "DEVICE_REVOKE" && r.body.reason === 0n,
      ).length,
      completed: activeDevice(I.state, idOf("DEV_B")) !== undefined,
    };
  },
  F09_pairing_service: () => {
    const I = chainAt("flow.f09_recertify_c1_in_i").state;
    return {
      registered_in_I: I.devices.get(toHex(idOf("BRIDGE_O")))?.registered === true,
      approved_scope: cert("CERT_SO").payload.scope.map(resourceLabel),
    };
  },
  F10_request_feasibility: (_f, steps) => ({
    // Every preset the check refused is not offered, so no consume is proposed for it.
    consume_proposed_for_infeasible_preset: !(steps.find((s) => s.n === 4) as Json)?.offered,
  }),
  F11_revoker_chain_through_target: () => ({}),
  F12_rotation_with_open_session: (_f, steps) => {
    const tables = (steps.find((s) => s.n === 10) as Json).tables as Record<string, Json>;
    return {
      rotators: Object.fromEntries(
        Object.entries(tables).map(([name, t]) => [
          name,
          Object.entries(t.candidates as Record<string, Json>)
            .filter(([, v]) => v.rotator)
            .map(([k]) => k)
            .sort(),
        ]),
      ),
    };
  },
  F13_durable_phases: () => ({}),
  F14_frontier_from_verified_set: (_f, steps) => ({
    frontier: (steps.find((s) => s.n === 7) as Json).frontier,
  }),
  F15_rotation_policy_by_exposure: (_f, steps) => ({
    exposing: Object.fromEntries(
      steps
        .filter((s) => typeof s.exposing === "boolean")
        .map((s) => [String(s.case_id), s.exposing])
        .sort(([a], [b]) => (String(a) < String(b) ? -1 : 1)),
    ),
  }),
  F16_device_grant_fork: (_f, steps) => ({
    state: (steps.find((s) => s.n === 4) as Json).outcome,
  }),
  F17_revoked_device: () => ({}),
  F18_barrier: () => ({}),
  F19_key_bootstrap: (f) => ({
    // The Identity Resource is one of reconciliation's targets: step 2 delivers in I.
    I_is_a_target:
      resourceLabel(fromHex((wireCase(wireId(stepOf(f, 2))).context as Json).resource_id.hex)) ===
      "I",
  }),
};

/** Final fields sdk-ts does not derive, with why. */
const FINAL_NA: Readonly<Record<string, string>> = {
  frontier_rule:
    "explanatory prose (W §28.1); the frontier itself is the final field `frontier`, derived from the KEY_EPOCH sdk-ts verified.",
  server_without_identity_01:
    "LFCP-WIRE-01 §100.1: the verdicts of a pre-identity validator; sdk-ts has no pre-identity validator.",
};

// ---------------------------------------------------------------------------
// the handler

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** The reported value restricted to what the fixture states (tables keep every key; rows keep the stated fields). */
function stated(expected: unknown, got: unknown): unknown {
  if (!isRecord(expected) || !isRecord(got)) return got;
  return Object.fromEntries(
    Object.keys(expected).map((k) => {
      const e = expected[k];
      const g = got[k];
      if (isRecord(e) && isRecord(g))
        return [k, Object.fromEntries(Object.keys(e).map((f) => [f, stated(e[f], g[f])]))];
      return [k, g];
    }),
  );
}

/**
 * Facts sdk-ts derives beyond the state every step reports (its outcome,
 * accepted IDs and post-state, the device table after a Control Record,
 * exposure, rotations, a frontier, the phase of a phase input): exported
 * only where the fixture's step states them, as sdk-rs does, so that the
 * differential compares what both report. The checks see them either way.
 */
const STATED_ONLY = new Set([
  "approval",
  "counted",
  "status",
  "head",
  "leaves",
  "proven",
  "used",
  "uses",
  "offered",
  "rotates",
  "rotator",
  "descendant_receives_new_epoch",
  "identity_aware",
  "ledger",
  "package_phases",
  "ledger_after",
  "client",
  ...Object.keys(wire.fixtures.resources),
]);

/**
 * What a candidate's chain proves (§5.3 step 8) is one group: where a step
 * states any of it, the step reports all of it, and of the Resources only
 * those the flow's fixture names.
 */
const CANDIDATE = new Set(["leaves", "proven", "used", "uses", "status"]);

function statedOnly(
  report: Report,
  expected: Readonly<Record<string, unknown>>,
  step: FlowStep,
  f: FlowCase,
) {
  const named = new Set(f.expected.steps.flatMap((s) => Object.keys(s)));
  const resources = new Set(Object.keys(wire.fixtures.resources));
  const candidate =
    report.leaves !== undefined &&
    Object.keys(expected).some((k) => CANDIDATE.has(k) || resources.has(k));
  for (const k of Object.keys(report)) {
    if (candidate && (CANDIDATE.has(k) || (resources.has(k) && named.has(k)))) continue;
    // The own Register phase of a DEVICE_GRANT step; a phase input's phase is always reported.
    const optional = STATED_ONLY.has(k) || (k === "phase" && step.phase_input === undefined);
    if (optional && !Object.hasOwn(expected, k)) delete report[k];
  }
}

const identityFlow: Handler = async (vector) => {
  const f = vector as unknown as FlowCase;
  const steps: Report[] = [];
  const checks: Check[] = [];
  const notApplicable: Report[] = [];
  const accepted = new Set<string>();
  for (const step of f.inputs.steps) {
    const { report, ok } = await runStep(f, step, steps, accepted);
    const e = f.expected.steps.find((s) => s.n === step.n) ?? {};
    statedOnly(report, e, step, f);
    if (step.case !== undefined && String(step.case).startsWith("wire:"))
      report.case_id = wireId(step);
    steps.push(report);
    const name = `steps/${step.n}`;
    if (report.outcome === "N/A") {
      notApplicable.push({ step: step.n, reason: report.not_applicable });
      continue;
    }
    if (!ok)
      checks.push({ name: `${name}/case`, ok: false, message: `${step.case} fails its checks` });
    for (const k of Object.keys(e)) {
      if (k === "n") continue;
      if (Object.hasOwn(FIELD_NA, k) && report[k] === undefined) {
        notApplicable.push({ step: step.n, field: k, reason: FIELD_NA[k] });
        continue;
      }
      checks.push(equalCheck(`${name}/${k}`, e[k], stated(e[k], report[k])));
    }
  }
  const final: Report = await (FINALS[f.id] ?? (() => ({})))(f, steps);
  const ef = ((f.expected as Json).final ?? {}) as Record<string, unknown>;
  for (const k of Object.keys(ef)) {
    if (Object.hasOwn(FINAL_NA, k)) {
      notApplicable.push({ field: `final.${k}`, reason: FINAL_NA[k] });
      continue;
    }
    checks.push(equalCheck(`final/${k}`, ef[k], stated(ef[k], final[k])));
  }
  if (Object.keys(ef).length === 0) checks.push(equalCheck("final", {}, {}));
  // A final whose every field is N/A is a not-applicable part, never a pass.
  const finalPending =
    Object.keys(ef).length > 0 && Object.keys(ef).every((k) => Object.hasOwn(FINAL_NA, k));
  for (const s of steps) delete s.case_id;
  return {
    checks,
    ...(finalPending
      ? {
          notApplicable: {
            final: Object.keys(ef)
              .map((k) => FINAL_NA[k])
              .join(" "),
          },
        }
      : {}),
    report: {
      outcome: notApplicable.length === 0 ? "accept" : "N/A",
      not_applicable: notApplicable,
      post_state: final,
      steps,
    },
  };
};

export const IDENTITY_FLOW_HANDLERS: Readonly<Record<string, Handler>> = {
  "behavioral/identity_flow": identityFlow,
};
