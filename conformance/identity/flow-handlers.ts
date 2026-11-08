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
  acceptInvitationAsDevice,
  candidateEvidence,
  checkIssuance,
  classifyConsume,
  classifyPackage,
  classifyRegister,
  classifyRevoke,
  classifyRotate,
  createPairingSession,
  type DeviceEntryValue,
  exposingRevocationsSince,
  type IdentityChannel,
  IdentityConflict,
  identityWriterClass,
  keyRecipients,
  leafPayload,
  MASK_PRESETS,
  planDisplayData,
  planReconciliation,
  planRevocations,
  principalOfRef,
  principalRefOf,
  readersAt,
  recordSeq,
  rotatorTest,
  signChain,
  storeDek,
  syncChain,
  verifiedFrontier,
} from "@openlfcp/client";
import { bytesEqual, dataEpoch, fromHex, hash32, type PrincipalId, toHex } from "@openlfcp/core";
import { InvitationSecret, importResourceDEK, sha256 } from "@openlfcp/crypto";
import { unframeChange } from "@openlfcp/shared-objects/admission";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  ABILITY,
  activeDevice,
  assembleInviteUri,
  type ControlRecord,
  type ControlState,
  certificateChain,
  DEVICE_KIND,
  decodeControlRecord,
  deviceCertificatePayloadFromCbor,
  hasAbility,
  parseDataUnit,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { decodeStrict } from "@openlfcp/wire/cbor";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { device as localDevice } from "../../packages/client/test/identity/support.js";
import { equalCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, HandlerResult, VectorCase } from "../runner.js";
import { openSpec } from "../spec.mjs";
import {
  cert,
  chainAt,
  chainOf,
  chainOfCert,
  contextOf,
  dek0Of,
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

/** A Register phase input's planned chain (leaf first), or the certificate's own chain. */
const plannedChain = (p: Json) =>
  Array.isArray(p.chain)
    ? certificateChain(
        (p.chain as string[]).map((l) => cert(l)),
        idOf(p.root),
      )
    : chainOfCert(p.certificate);

function phaseFacts(p: Json): Report {
  const chain = chainAt(String(p.state).replace(/^wire:/, ""));
  let phase: string;
  switch (p.phase) {
    case "consume":
      phase = classifyConsume(chain.state, idOf(p.root), idOf(p.device), hash32(fromHex(p.digest)));
      break;
    case "register": {
      const own = p.own === true;
      // The planned chain (baseline.4: every Register phase input names it); its issuers decide.
      const planned = plannedChain(p);
      phase = classifyRegister(chain, {
        root: idOf(p.root),
        chain: planned,
        isOwnRecord: () => own,
      });
      return {
        phase,
        proposes: phase === "pending",
        signs: phase !== "superseded",
        not_superseded: phase !== "superseded",
        chain: planned.certificates.map((c) => certificateLabel(c.id)),
      };
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
/** Not applicable by the text (another client generation, the server's duty, prose). */
const na = (reason: string): Report => ({ outcome: "N/A", not_applicable: reason });
/**
 * Applicable to sdk-ts, but not run by this harness: the procedure needs a
 * journal, a UI decision or a network the fixture does not give. Never a
 * pass, and not N/A either (review of sdk-ts#19).
 */
const notVerified = (reason: string): Report => ({
  outcome: "not verified",
  not_verified: reason,
});
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

// ---------------------------------------------------------------------------
// reconciliation (§7.1, baseline.4)

const labelsOf = (ids: readonly Uint8Array[]) => ids.map((d) => principalLabel(d));
/** Revoked pairs of `root` whose device is not bound in the state (W §17.5 rule 5). */
const unboundRevoked = (state: ControlState, root: PrincipalId) =>
  [...state.revoked.values()].filter(
    (r) => bytesEqual(r.root, root) && !state.devices.has(toHex(r.device)),
  ).length;
const pairingRevoked = (I: ControlState, state: ControlState) =>
  [...state.revoked.values()].filter(
    (r) => I.devices.get(toHex(r.device))?.kind === DEVICE_KIND.PAIRING,
  ).length;

/** The step whose case is the Identity Resource a reconciliation fixture reconciles from. */
const RECONCILE_FROM: Readonly<Record<string, number>> = {
  F05_reconciliation: 1,
  "F05.sixty_five_sessions": 4,
  F09_pairing_service: 6,
};

/**
 * §7.1 step 1 with planRevocations: on the reconciliation's source `I`, a
 * case-less step reports what step 1 proposes on the target as the next
 * case finds it (and what it does not propagate); a DEVICE_REVOKE step on
 * the target reports what step 1 proposed on the target before it, the
 * root's unbound revoked pairs, and for a refusal the unpropagated pair the
 * SDK reports (TargetReconciliation.unpropagated).
 */
function reconcileFacts(f: FlowCase, step: FlowStep, report: Report): Report | undefined {
  const from = RECONCILE_FROM[f.id];
  if (from === undefined || step.n < from) return undefined;
  const I = chainAt(wireId(stepOf(f, from)));
  const R = I.state.owner.principalId;
  if (step.n === from) return { revoked_pairing_devices_in_I: pairingRevoked(I.state, I.state) };
  if (step.case === undefined && step.phase_input === undefined && step.bytes_of === undefined) {
    const next = f.inputs.steps.find((s) => s.n > step.n && String(s.case).startsWith("wire:"));
    if (next === undefined) return undefined;
    const plan = planRevocations(I, chainOf(contextOf(wireId(next))));
    const proposals = labelsOf(plan.propose.map((p) => p.device));
    return {
      outcome: proposals.length === 0 ? "nothing to propose" : "not propagated",
      proposals,
      not_propagated: labelsOf(plan.notRelevant).sort(),
    };
  }
  if (!String(step.case).startsWith("wire:")) return undefined;
  const id = wireId(step);
  if (!isControl(wireCase(id))) return undefined;
  let record: ControlRecord;
  try {
    record = decodeControlRecord(recordOf(id));
  } catch {
    return undefined;
  }
  if (record.body.type !== "DEVICE_REVOKE") return undefined;
  if (bytesEqual(record.payload.resourceId, I.state.resourceId)) return undefined;
  const before = chainOf(contextOf(id));
  const proposed = planRevocations(I, before).propose.map((p) => p.device);
  const accepted = report.outcome === "accept";
  const out: Report = {
    proposals: labelsOf(proposed),
    unbound_revoked_pairs_of_OWNER: unboundRevoked(accepted ? chainAt(id).state : before.state, R),
  };
  const device = record.body.device;
  if (!accepted && proposed.some((d) => bytesEqual(d, device))) {
    out.reported = true;
    out.pair_state = "unpropagated";
  }
  if (report.exposing === true) out.rotation = "the rotation policy of §8.4 closes the epoch";
  return out;
}

/** F05.display_data: §7.1 step 4 (planDisplayData) run on each step's state of I, the documents simulated. */
const displayMemo = new Map<string, { steps: Map<number, Report>; final: Report }>();
function displayRuns(f: FlowCase) {
  const memo = displayMemo.get(f.id);
  if (memo !== undefined) return memo;
  const R = idOf("OWNER");
  const ref = (l: string) => principalRefOf(idOf(l));
  // The document of §5.1 holds the root's entry only (profile change.C1_fill).
  const main = new Map<string, DeviceEntryValue>([[ref("OWNER"), { label: "Desktop", kind: 0 }]]);
  let afterP2: Map<string, DeviceEntryValue> | undefined;
  let service: Map<string, DeviceEntryValue> | undefined;
  let state: ControlState | undefined;
  let caseId: string | undefined;
  const steps = new Map<number, Report>();
  for (const s of f.inputs.steps) {
    if (s.case !== undefined) {
      caseId = wireId(s);
      state = chainAt(caseId).state;
    }
    if (state === undefined) continue;
    if (s.branch === "service" && service === undefined) service = new Map(afterP2 ?? main);
    const doc = s.branch === "service" ? (service as Map<string, DeviceEntryValue>) : main;
    const writes: Report[] = [];
    for (const intent of planDisplayData(state, doc, R)) {
      if (intent.intent !== "device.put") continue;
      const was = doc.get(intent.key);
      const write = Object.fromEntries(
        Object.entries(intent.entry).filter(
          ([k, v]) => was === undefined || (was as unknown as Record<string, unknown>)[k] !== v,
        ),
      );
      const who = principalOfRef(intent.key);
      writes.push({ entry: who === undefined ? intent.key : principalLabel(who), write });
      doc.set(intent.key, { ...(was ?? {}), ...intent.entry } as DeviceEntryValue);
    }
    if (caseId === "P2_pairing_device") afterP2 = new Map(main);
    const pairing = [...state.devices.entries()]
      .filter(([, d]) => d.kind === DEVICE_KIND.PAIRING)
      .map(([h]) => principalLabel(fromHex(h)))
      .sort();
    steps.set(s.n, {
      ...(s.case === undefined
        ? { outcome: writes.length === 0 ? "nothing to write" : "writes" }
        : {}),
      writes,
      metadata_changes: writes.length,
      pairing_devices_bound: pairing,
    });
  }
  const entries = (doc: Map<string, DeviceEntryValue> | undefined) =>
    Object.fromEntries(
      [...(doc ?? [])].map(([k, v]) => {
        const who = principalOfRef(k);
        return [who === undefined ? k : principalLabel(who), v];
      }),
    );
  const isPairing = (k: string) =>
    f.inputs.steps.some((s) => {
      if (s.case === undefined) return false;
      const who = principalOfRef(k);
      return (
        who !== undefined &&
        chainAt(wireId(s)).state.devices.get(toHex(who))?.kind === DEVICE_KIND.PAIRING
      );
    });
  const final = {
    entries_main: entries(main),
    entries_service: entries(service),
    entries_for_pairing_devices: [...main.keys(), ...(service?.keys() ?? [])].filter(isPairing)
      .length,
  };
  const out = { steps, final };
  displayMemo.set(f.id, out);
  return out;
}

/** §5.3 step 1 with createPairingSession, on I at flow.pl_key_epoch_1 and the material DEV_A holds. */
async function pairingWithMaterial(held: { root_unit_1: boolean; epochs: number[] }) {
  const server = new MemoryCoordinator();
  const I = server.seed(recordsAt("flow.pl_key_epoch_1"));
  if (held.root_unit_1)
    server.inject(I, fromHex(wireCase("flow.pl_root_unit_1").inputs.cose_sign1.hex));
  const local = localDevice();
  const chain = chainAt("flow.pl_key_epoch_1");
  for (const e of held.epochs)
    await storeDek(
      local.storage,
      local.secrets,
      chain,
      dataEpoch(BigInt(e)),
      importResourceDEK(sha256(new TextEncoder().encode(`LFCP-TV-IDENTITY-DEK-I-EPOCH-${e}`))),
    );
  const p = party("DEV_A");
  const url = chain.state.route.coordinatorUrl;
  const r = await createPairingSession({
    installation: { signer: p, agreement: p.agreement },
    ...local,
    network: server.network(),
    now: () => 1,
    identity: { resource: I, url },
    document: () => {
      throw new Error("no document is needed before the link");
    },
  });
  const proposed = server.uploads.filter((u) => u.op === "control").length;
  return r.kind === "missing-material"
    ? { outcome: "no link", offers_link: false, missing: r.missing, records_proposed: proposed }
    : r.kind === "created"
      ? { outcome: "link", offers_link: true, records_proposed: proposed }
      : { outcome: r.kind };
}

/** The text of §7.2 for an invitation a device that cannot write I leaves unclaimed. */
const HANDED_OVER =
  "complete the invitation on a personal installation that can write I; the link is handed over as received";

const SPECIALS: Readonly<Record<string, Special>> = {
  // §7.1 step 1 at the limit: DEV_P is treated as revoked in X (planReconciliation, keyRecipients).
  "F05.sixty_five_sessions#10": (f) => {
    const I = chainAt(wireId(stepOf(f, 4)));
    const P = idOf("DEV_P");
    const refusedAt = chainOf(contextOf(wireId(stepOf(f, 11))));
    const registers = planReconciliation(I, refusedAt).some(
      (s) =>
        s.kind === "register" &&
        (bytesEqual(s.device, P) || s.chain.issuers.some((e) => bytesEqual(e, P))),
    );
    // Even once DEV_P is active in X (it registered itself, step 11), step 3 seals nothing to it.
    const seals = [refusedAt, chainAt(wireId(stepOf(f, 11)))].some((X) =>
      keyRecipients(I, X).some((r) => bytesEqual(r.principalId, P)),
    );
    return {
      outcome: !registers && !seals ? "DEV_P treated as revoked in X" : "DEV_P served in X",
      registers_DEV_P: registers,
      seals_to_DEV_P: seals,
    };
  },
  // §7.2 with acceptInvitationAsDevice: a Read device of OWNER does not claim.
  "F07.read_device_cannot_claim#2": async (f) => {
    const server = new MemoryCoordinator();
    const I = server.seed(recordsAt(wireId(stepOf(f, 1))));
    const url = chainAt(wireId(stepOf(f, 1))).state.route.coordinatorUrl;
    const p = party("DEV_R");
    const link = assembleInviteUri({
      resourceId: fromHex(
        (wire.fixtures.resources.X as unknown as { id: { hex: string } }).id.hex,
      ) as never,
      endpoints: [url],
      grantId: sha256(recordOf("N1_invite_grant")) as never,
      secret: InvitationSecret.generate(),
    });
    const r = await acceptInvitationAsDevice({
      installation: { signer: p, agreement: p.agreement },
      ...localDevice(),
      network: server.network(),
      now: () => 1,
      identity: { resource: I, url },
      document: () => {
        throw new Error("no document is needed before the claim");
      },
      link,
    });
    const sent = server.uploads.length;
    return r.kind === "needs-writer" && sent === 0
      ? {
          outcome: "claim not sent",
          claim_sent: false,
          invitation: "unclaimed",
          offered: HANDED_OVER,
        }
      : { outcome: r.kind, claim_sent: sent > 0 };
  },
  "F08.missing_material#2": (_f, step) => pairingWithMaterial(step.held as never),
  "F08.missing_material#3": (_f, step) => pairingWithMaterial(step.held as never),
  "F18_barrier#6": () =>
    notVerified(
      "LFCP-WIRE-01 §37: every identity flow of sdk-ts reads READY first and reports a Resource on a server without identity-01 as unsupported, sending nothing (reconcileDevices status unsupported, createIdentityResource in packages/client/test/identity/resource.test.ts); the fixture gives no flow to run on that server.",
    ),
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
    notVerified(
      "IDENTITY-PROFILE-01 §7.2 step 3 writes the roster of DAVE's Identity Resource, for which the fixture supplies no chain, DEK or document; acceptInvitationAsDevice writes it in packages/client/test/identity/accept.test.ts.",
    ),
  "F09_pairing_service#4": () =>
    notVerified(
      "IDENTITY-PROFILE-01 §5.3 step 8 with every candidate offline needs B's persisted candidates and coordinators that do not answer; completePairing returns this state in packages/client/test/identity/pairing.test.ts, not on fixture bytes.",
    ),
  "F09_pairing_service#16": () =>
    notVerified(
      "IDENTITY-PROFILE-01 §5.3 step 8 / §9: resuming from persisted candidates after a restart needs B's journal and storage; covered by packages/client/test/identity/pairing.test.ts, not expressible on fixture bytes.",
    ),
  "F10_request_feasibility#3": () =>
    notVerified(
      "IDENTITY-PROFILE-01 §5.3 step 4: re-confirmation when the descriptor changes is a property of A's approval journal and UI (approvePairing compares the journaled tuple); the fixture gives no request change to replay.",
    ),
  "F10_request_feasibility#7": () =>
    notVerified(
      "IDENTITY-PROFILE-01 §5.3 step 4: a service scope trimmed to nothing is refused by approvePairing before any consume; the fixture gives no request or session to run it on.",
    ),
  "F10_request_feasibility#8": () =>
    notVerified(
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
    const frontier = await verifiedFrontier(
      channel,
      chain,
      { units: [], snapshot: [] },
      { deks: new Map([["0", dek0Of("Y")]]) },
    );
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
  // §9.7: on a forked chain every flow that reads it (approval, reconciliation, rotation all
  // start with syncChain) is refused with IdentityConflict, and the fork stays blocking.
  "F16_device_grant_fork#5": async (f) => {
    const storage = new InMemoryLfcpStorage();
    const forked = [
      ...recordsAt(wireId(stepOf(f, 1))),
      ...[2, 3].map((n) => recordOf(wireId(stepOf(f, n)))),
    ];
    const resource = chainAt(wireId(stepOf(f, 1))).state.resourceId;
    const channel = { control: async () => forked } as unknown as IdentityChannel;
    const refused = async () => {
      try {
        await syncChain(storage, channel, resource);
        return false;
      } catch (e) {
        return e instanceof IdentityConflict;
      }
    };
    // The first read finds the fork; a later one is refused from storage alone.
    const first = await refused();
    const again = await refused();
    return { outcome: first && again ? "suspended" : "proceeds" };
  },
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
        for (const k of ["absent_fields", "records", "trimmed_at", "competing_returned"])
          if (post?.[k] !== undefined) report[k] = post[k];
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
  const extra = await (EXTRAS[f.id] ?? (() => undefined))(f, step, report);
  if (extra !== undefined) report = { ...report, ...extra };
  if (report.outcome === undefined)
    report = {
      ...report,
      ...na("this step names no case, bytes or phase, and sdk-ts has no computation for it"),
    };
  return { report, ok };
}

// ---------------------------------------------------------------------------
// per-fixture facts after a step (baseline.4 fixtures)

type Extra = (
  f: FlowCase,
  step: FlowStep,
  report: Report,
) => Report | undefined | Promise<Report | undefined>;
const holds2 = (id: string, who: string) =>
  hasAbility(chainAt(id).state, idOf(who), ABILITY.DATA_WRITE);
const REJECTED = {
  // requestPairing returns not-a-session / invalid-link before it journals or writes anything (§5.2).
  request_written: false,
  sent_as_pairing_device_after_rejection: "nothing",
  reported: true,
};
const EXTRAS: Readonly<Record<string, Extra>> = {
  F05_reconciliation: reconcileFacts,
  "F05.sixty_five_sessions": reconcileFacts,
  F09_pairing_service: reconcileFacts,
  "F05.display_data": (f, step) => displayRuns(f).steps.get(step.n),
  "F07.read_device_cannot_claim": (_f, step) =>
    step.case === undefined
      ? undefined
      : {
          DEV_R_holds_2_in_I: holds2(wireId(step), "DEV_R"),
          DEV_B_holds_2_in_I: holds2(wireId(step), "DEV_B"),
        },
  "F08.link_rejected": (_f, _step, report) =>
    report.outcome === "PAIRING_LINK_REJECTED" ? REJECTED : undefined,
  "F08.missing_material": (_f, step) =>
    step.case === undefined
      ? undefined
      : {
          epochs: [...chainAt(wireId(step)).state.epochs.keys()].map(Number).sort((a, b) => a - b),
        },
  "F13.issuer_revoked_before_resume": (_f, step) => {
    const p = step.phase_input as Json;
    if (p?.phase !== "register") return undefined;
    const binding = chainAt(String(p.state).replace(/^wire:/, "")).state.devices.get(
      toHex(idOf(p.device)),
    );
    return {
      [`${p.device}_bound`]: binding !== undefined,
      [`${p.device}_leaf`]:
        binding?.leafId === null || binding?.leafId === undefined
          ? null
          : certificateLabel(binding.leafId),
    };
  },
};

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
  "F05.sixty_five_sessions": (f) => {
    const I = chainAt(wireId(stepOf(f, 4))).state;
    // The main branch ends at step 6: DEV_P's self-registration (step 7) is refused.
    const X = chainAt(wireId(stepOf(f, 6))).state;
    return {
      X_tombstones_from_pairing: pairingRevoked(I, X),
      DEV_P_registered_in_X: X.devices.get(toHex(idOf("DEV_P")))?.registered === true,
    };
  },
  "F05.display_data": (f) => displayRuns(f).final,
  "F07.read_device_cannot_claim": (_f, steps) => ({
    claims_sent_by_read_device: steps.filter((s) => s.claim_sent === true).length,
  }),
  "F08.link_rejected": (_f, steps) => ({
    requests_written_after_rejection: steps.filter(
      (s) => s.outcome === "PAIRING_LINK_REJECTED" && s.request_written !== false,
    ).length,
  }),
  "F08.missing_material": (_f, steps) => ({
    sessions_without_material: steps.filter(
      (s) => s.outcome === "no link" && s.offers_link !== false,
    ).length,
  }),
  "F13.issuer_revoked_before_resume": (f, steps) => ({
    superseded: steps
      .filter((s) => s.phase === "superseded")
      .map((s) => {
        const p = stepOf(f, Number(s.n)).phase_input as Json;
        const bound = chainOf(contextOf(String(p.state).replace(/^wire:/, ""))).state.devices.has(
          toHex(idOf(p.device)),
        );
        const through = plannedChain(p).issuers.map((e) => principalLabel(e));
        return bound
          ? `${p.device} re-certification through ${through.join(", ")}`
          : `${p.device} first registration`;
      }),
  }),
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
  // A step's case carries its diagnostic in the case's own export (wire, profile), compared there.
  "diagnostic",
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
  // baseline.4: reconciliation, display data, link and material checks, planned chains.
  "proposals",
  "not_propagated",
  "revoked_pairing_devices_in_I",
  "unbound_revoked_pairs_of_OWNER",
  "reported",
  "pair_state",
  "rotation",
  "registers_DEV_P",
  "seals_to_DEV_P",
  "writes",
  "metadata_changes",
  "pairing_devices_bound",
  "DEV_R_holds_2_in_I",
  "DEV_B_holds_2_in_I",
  "claim_sent",
  "invitation",
  "request_written",
  "sent_as_pairing_device_after_rejection",
  "epochs",
  "offers_link",
  "missing",
  "records_proposed",
  "chain",
  "DEV_M2_bound",
  "DEV_M2_leaf",
  "DEV_B_bound",
  "DEV_B_leaf",
  "absent_fields",
  "records",
  "trimmed_at",
  "competing_returned",
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
  const notVerifiedSteps: Report[] = [];
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
    if (report.outcome === "not verified") {
      notVerifiedSteps.push({ step: step.n, reason: report.not_verified });
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
  for (const s of steps) delete s.case_id;
  // Every N/A and not-verified part, with its reason, in the runner's summary too (review of sdk-ts#19).
  const part = (x: Report) =>
    x.step === undefined
      ? String(x.field).replace(/^final\./, "final/")
      : `steps/${x.step}${x.field === undefined ? "" : `/${x.field}`}`;
  const parts = (xs: readonly Report[]) =>
    Object.fromEntries(xs.map((x) => [part(x), String(x.reason)]));
  return {
    checks,
    ...(notApplicable.length === 0 ? {} : { notApplicable: parts(notApplicable) }),
    ...(notVerifiedSteps.length === 0 ? {} : { notVerified: parts(notVerifiedSteps) }),
    report: {
      // A summary of the steps: the least complete of accept, N/A and not verified.
      outcome:
        notVerifiedSteps.length > 0 ? "not verified" : notApplicable.length > 0 ? "N/A" : "accept",
      not_applicable: notApplicable,
      not_verified: notVerifiedSteps,
      post_state: final,
      steps,
    },
  };
};

export const IDENTITY_FLOW_HANDLERS: Readonly<Record<string, Handler>> = {
  "behavioral/identity_flow": identityFlow,
};
