import {
  bytesEqual,
  fromBase64url,
  fromHex,
  type PrincipalId,
  type ResourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { type ControlState, DEVICE_KIND, parsePairingUri, revocationOf } from "@openlfcp/wire";
import { type PairingRequestValue, principalOfRef, principalRefOf } from "./document.js";
import type { LinearChain } from "./phases.js";

/**
 * The approving client's side of a service managed through a control
 * Resource `C` (SERVICE-CONTROL-PROFILE-01 §7–§8, IDENTITY-PROFILE-01 §5.3
 * step 4): the pre-authorised approval of a section installation, the
 * approval record of phase A3, and the only revocations `C` permits.
 *
 * @openlfcp/client does not depend on @openlfcp/shared-objects: `C` reaches
 * these functions through ServiceControlPort, which a client builds over
 * its ServiceControlDataProfile (state(), replica.creatorsOf) and its
 * SyncClient (commit), e.g. with serviceControlPort.
 */

/** §2.3: the class admission judged a change of `C` by (structurally shared-objects' ServiceControlWriterClass). */
export type ServiceControlWriterClass = "root" | "personal" | "service" | "other";

/** §2.4: who created an entry of `C`. */
export interface ServiceControlCreator {
  readonly signer: PrincipalId;
  readonly writerClass: ServiceControlWriterClass;
}

/** §2.1 Approval as readers see it (§5); `revoked` is true when any `revoked` value is present. */
export interface ServiceControlApprovalView {
  readonly role: "base" | "section";
  readonly resource: string;
  readonly principal: string;
  readonly certDigest: string;
  readonly certId: string;
  readonly generation: number | bigint;
  readonly origin: string;
  readonly revoked: boolean;
}

/** The state of `C` readers see (§5), structurally shared-objects' ServiceControlValidation. */
export interface ServiceControlStateView {
  readonly approvals: Readonly<Record<string, ServiceControlApprovalView>>;
  readonly requests: Readonly<
    Record<
      string,
      {
        readonly op: string;
        readonly binding?: string;
        readonly generation?: number | bigint;
        readonly args: Readonly<Record<string, unknown>>;
      }
    >
  >;
  readonly pairing: Readonly<
    Record<string, { readonly descriptor: string; readonly principal: string; readonly fp: string }>
  >;
  readonly cancels: Readonly<Record<string, { readonly reason: string }>>;
  readonly lifecycle?: Readonly<Record<string, unknown>>;
}

/** One value `requests[rid]` held in `C`'s history (structurally shared-objects' ServiceControlRequestRecord). */
export interface ServiceControlRequestRecord {
  readonly rid: string;
  readonly request: ServiceControlStateView["requests"][string];
  /** Whether the entry is in the state readers see now (false: deleted since). */
  readonly present?: boolean;
  /** §2.4: the change that created the value. */
  readonly creators: readonly ServiceControlCreator[];
}

/** What committing one change to `C` came to (§9.1: the A3 phase is done once it is acknowledged). */
export type ServiceControlCommitOutcome =
  /** The coordinator acknowledged the change's unit. */
  | { readonly kind: "acknowledged" }
  /** Durable here and queued; not acknowledged yet. Commit again later with the same operation. */
  | { readonly kind: "queued" }
  | { readonly kind: "rejected"; readonly code: string };

/** `C` as the approving client holds it: its replica and its writes. */
export interface ServiceControlPort {
  readonly resource: ResourceId;
  /** The state readers see (§5); undefined while `C` is not synchronised. */
  state(): ServiceControlStateView | undefined;
  /** §2.4: who created the current value of `container[key]` (ServiceControlReplica.creatorsOf). */
  creatorsOf(
    container: "approvals" | "pairing" | "requests" | "cancels",
    key: string,
  ): readonly ServiceControlCreator[];
  /**
   * Every value `requests[rid]` has held in `C`'s accepted history, deleted
   * ones included, each with the change that created it (§2.4); a value
   * §5 finds invalid, a conflicted one included (rule 3), is left out
   * (ServiceControlReplica.requestHistory). §7.4 condition 1 reads it.
   */
  requestHistory(): readonly ServiceControlRequestRecord[];
  /**
   * Whether the coordinator accepted a change that created the current
   * value of `container[key]` (§7.1, IDENTITY §9.1: a phase ends at its
   * ACK). False when there is no value, or when every change that created
   * it is this client's own, queued or pending (its batch not accepted or
   * acknowledged yet, as commit reports it). A change received from the
   * coordinator is accepted.
   */
  acknowledged(
    container: "approvals" | "pairing" | "requests" | "cancels",
    key: string,
  ): Promise<boolean>;
  /**
   * Commits `intents` (shared-objects' ServiceControlIntent) as one change
   * under `operationId`. The same operation with the same intents writes
   * nothing new and reports the first change's outcome (receipts, §3.3).
   */
  commit(intents: readonly unknown[], operationId: string): Promise<ServiceControlCommitOutcome>;
}

/** Whether every change that created an entry is of one of `classes` (and there is one). */
export const createdBy = (
  creators: readonly ServiceControlCreator[],
  classes: readonly ServiceControlWriterClass[],
): boolean => creators.length > 0 && creators.every((c) => classes.includes(c.writerClass));

// ---------------------------------------------------------------------------
// Pre-authorised approval (IDENTITY-PROFILE-01 §5.3 step 4, SERVICE-CONTROL-PROFILE-01 §8.1)

/** A request entry of `I` that names the pairing device, with the signers of the changes that wrote it. */
export interface IdentityRequestEntry {
  /** `requests[k]`: the PrincipalRef of the requesting device. */
  readonly key: string;
  readonly entry: PairingRequestValue;
  readonly signers: readonly PrincipalId[];
}

export interface SectionApprovalInput {
  readonly root: PrincipalId;
  /** `I`'s verified state at the head the consume would be proposed on. */
  readonly identity: ControlState;
  /** `J`, the pairing device of the session. */
  readonly pairingDevice: PrincipalId;
  /**
   * Whether this installation created `J` (its session journal holds it) for
   * a `requests[rid]` with `op = "pair-section"` that it wrote in `C`.
   */
  readonly ownSession: boolean;
  /** `X`: the `binding` of `requests[rid]`. */
  readonly binding: ResourceId;
  /** The entries of `I`'s `requests` (any writer); those not written by `J` alone are ignored. */
  readonly requests: readonly IdentityRequestEntry[];
  /** `pairing[rid]` in `C`, with the classes of the changes that created it; undefined until it arrives. */
  readonly pairing?: {
    readonly descriptor: string;
    readonly principal: string;
    readonly creators: readonly ServiceControlCreator[];
  };
}

export type SectionApprovalDecision =
  /** Every condition holds: approve with the Service preset and scope exactly `[X]`, without the human. */
  | { readonly kind: "approve"; readonly request: IdentityRequestEntry }
  /** A record has not reached this replica yet (a missing record is never a mismatch): re-check on the next push or open. */
  | { readonly kind: "wait"; readonly reason: string }
  /** An established mismatch: cancel `J` (reason 0) and write `cancels[rid] = {reason: "mismatch"}`. */
  | { readonly kind: "mismatch"; readonly reason: string }
  /** This installation did not create `J`: left to the one that did; nothing is cancelled. */
  | { readonly kind: "not-own" }
  /** `J` is revoked already: consumed (an approval runs) or cancelled; nothing new is cancelled. */
  | { readonly kind: "closed"; readonly consumed: boolean };

/**
 * IDENTITY-PROFILE-01 §5.3 step 4, *pre-authorised approval*: whether a
 * section installation's request in `I` may be approved without the human,
 * from the records as this installation holds them. Pure: the same records
 * give the same decision on every installation. Only an established
 * mismatch (both records present and valid, a condition false) cancels; a
 * request in `I` not written by `J` alone is ignored, as for any request.
 */
export function sectionApprovalDecision(i: SectionApprovalInput): SectionApprovalDecision {
  if (!i.ownSession) return { kind: "not-own" };
  const revoked = revocationOf(i.identity, i.root, i.pairingDevice);
  if (revoked !== undefined) return { kind: "closed", consumed: revoked.reason === 3n };
  const J = principalRefOf(i.pairingDevice);
  const written = i.requests.filter(
    (r) =>
      r.entry.pairing === J &&
      r.signers.length > 0 &&
      r.signers.every((s) => bytesEqual(s, i.pairingDevice)),
  );
  if (written.length === 0) return { kind: "wait", reason: "no request written by J in I yet" };
  if (i.pairing === undefined)
    return { kind: "wait", reason: "pairing[rid] has not reached C yet" };
  if (!createdBy(i.pairing.creators, ["service"]))
    return { kind: "mismatch", reason: "pairing[rid] was not admitted from C's service class" };
  if (written.length > 1) return { kind: "mismatch", reason: "J wrote more than one request in I" };
  const request = written[0] as IdentityRequestEntry;
  const { entry } = request;
  if (entry.kind !== 1) return { kind: "mismatch", reason: "the request is not of kind 1" };
  const X = toBase64url(i.binding);
  if (entry.scope?.length !== 1 || entry.scope[0] !== X)
    return { kind: "mismatch", reason: "the requested scope is not exactly [X]" };
  if (entry.descriptor !== i.pairing.descriptor)
    return { kind: "mismatch", reason: "the descriptor in I is not pairing[rid].descriptor" };
  if (i.pairing.principal !== request.key)
    return { kind: "mismatch", reason: "pairing[rid].principal is not the requesting device" };
  return { kind: "approve", request };
}

// ---------------------------------------------------------------------------
// Phase A3: the approval record (SERVICE-CONTROL-PROFILE-01 §7.1)

/** The journaled facts of the A3 phase: which `C`, which role, and what `origin` and `generation` say. */
export interface ApprovalRecordIntent {
  /** `C` (hex). */
  readonly resource: string;
  readonly role: "base" | "section";
  /** The approval's `resource`: `C` for the base, `X` for a section (base64url ResourceRef). */
  readonly approves: string;
  /** `meta.attemptId` (base) or the `rid` of the `pair-section` request. */
  readonly origin: string;
  /** The binding's generation (decimal); "0" for the base. */
  readonly generation: string;
}

/** The `approval.create` write of A3 for the approved leaf. */
export function approvalRecordWrite(
  intent: ApprovalRecordIntent,
  principal: PrincipalId,
  certDigest: Uint8Array,
  certId: Uint8Array,
  at: string,
): { readonly intent: "approval.create"; readonly approval: Readonly<Record<string, unknown>> } {
  return {
    intent: "approval.create",
    approval: {
      role: intent.role,
      resource: intent.approves,
      principal: principalRefOf(principal),
      certDigest: toBase64url(certDigest),
      certId: toBase64url(certId),
      // A uint: a number while it is a safe integer (receipts hash the intents as JSON).
      generation:
        BigInt(intent.generation) <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(intent.generation)
          : BigInt(intent.generation),
      origin: intent.origin,
      at,
    },
  };
}

/**
 * §7.1 after a crash: `approvals[P]` already present with the same
 * `certDigest` is `complete`; present with another digest the phase cannot
 * happen (`superseded`); absent, it is written (`pending`).
 */
export function classifyApprovalRecord(
  state: ServiceControlStateView,
  principal: PrincipalId,
  certDigest: Uint8Array,
): "pending" | "complete" | "superseded" {
  const a = state.approvals[principalRefOf(principal)];
  if (a === undefined) return "pending";
  return a.certDigest === toBase64url(certDigest) ? "complete" : "superseded";
}

// ---------------------------------------------------------------------------
// Revocation through C (SERVICE-CONTROL-PROFILE-01 §7.2, A§5.3, decision E21)

/** Why a Principal may be revoked because of `C`: the human here, or `lifecycle` of this `C`. */
export type ControlRevocationCause =
  /** (a) The human pressed Remove or Disconnect in this client for `principal`. */
  | { readonly kind: "human"; readonly principal: PrincipalId }
  /** (b) `lifecycle`, written by `service` of this same `C` (only `service` may write it, §3). */
  | { readonly kind: "lifecycle" };

export interface ControlRevocationInput {
  readonly root: PrincipalId;
  /** `I`'s verified state. */
  readonly identity: ControlState;
  readonly control: Pick<ServiceControlPort, "resource" | "state" | "creatorsOf">;
  readonly cause: ControlRevocationCause;
}

export interface ControlRevocationTargets {
  /** The Principals to revoke, in order: sections first, the base last. */
  readonly targets: readonly PrincipalId[];
  /** Approvals the cause named but a condition of §7.2 refused, with why. */
  readonly refused: readonly { readonly principal: string; readonly reason: string }[];
}

/**
 * §7.2: the only revocations `C` permits. A Principal is a target only
 * when `C` holds a valid approval for it without `revoked`, created by
 * `root` or `personal`, for this `C` (a base approval of another control
 * Resource is never one); `I`'s verified chain binds it with kind 1 and
 * root `R`, its leaf's payload digest is the approval's `certDigest`, and
 * it has issued no certificate; and the cause names it. A Principal is
 * never read from a field written by `service`: `lifecycle` contributes
 * only `{binding, generation}` pairs, matched against the approvals.
 */
export function controlRevocationTargets(i: ControlRevocationInput): ControlRevocationTargets {
  const state = i.control.state();
  const refused: { principal: string; reason: string }[] = [];
  if (state === undefined) return { targets: [], refused: [] };
  const C = toBase64url(i.control.resource);
  const named = namedApprovals(state, i.cause);
  const targets: { principal: PrincipalId; base: boolean }[] = [];
  for (const ref of named) {
    const reason = refusal(i, state, ref, C);
    if (reason !== undefined) refused.push({ principal: ref, reason });
    else
      targets.push({
        principal: principalOfRef(ref) as PrincipalId,
        base: state.approvals[ref]?.role === "base",
      });
  }
  targets.sort((a, b) => Number(a.base) - Number(b.base));
  return Object.freeze({
    targets: Object.freeze(targets.map((t) => t.principal)),
    refused: Object.freeze(refused),
  });
}

/** The approval keys a cause names (before the checks of §7.2 conditions 1 and 2). */
function namedApprovals(state: ServiceControlStateView, cause: ControlRevocationCause): string[] {
  if (cause.kind === "human") return [principalRefOf(cause.principal)];
  const l = state.lifecycle;
  if (l?.op === "uninstall")
    return Object.entries(state.approvals)
      .filter(([, a]) => !a.revoked)
      .map(([k]) => k);
  if (l?.op !== "remove" || !Array.isArray(l.bindings)) return [];
  const out = new Set<string>();
  for (const b of l.bindings as unknown[]) {
    if (b === null || typeof b !== "object") continue;
    const { binding, generation } = b as { binding?: unknown; generation?: unknown };
    if (typeof binding !== "string") continue;
    for (const [k, a] of Object.entries(state.approvals))
      if (
        a.role === "section" &&
        a.resource === binding &&
        (typeof generation === "number" || typeof generation === "bigint") &&
        BigInt(a.generation) === BigInt(generation)
      )
        out.add(k);
  }
  return [...out];
}

/** Why §7.2 conditions 1 and 2 refuse `ref`, or undefined when they hold. */
function refusal(
  i: ControlRevocationInput,
  state: ServiceControlStateView,
  ref: string,
  C: string,
): string | undefined {
  const a = state.approvals[ref];
  if (a === undefined) return "C holds no approval for it";
  if (a.revoked) return "its approval is revoked";
  if (a.principal !== ref) return "the approval names another Principal";
  if (a.role === "base" && a.resource !== C) return "a base approval of another control Resource";
  if (!createdBy(i.control.creatorsOf("approvals", ref), ["root", "personal"]))
    return "the approval was not created by root or personal";
  const P = principalOfRef(ref);
  if (P === undefined) return "not a PrincipalRef";
  const d = i.identity.devices.get(toHex(P));
  if (d === undefined) return "not bound in I";
  if (d.kind !== DEVICE_KIND.SERVICE) return "not a service device (kind 1)";
  if (!bytesEqual(d.root, i.root)) return "another root";
  const leaf = d.chain?.leaf;
  if (leaf === undefined || !bytesEqual(leaf.payloadDigest, fromBase64url(a.certDigest)))
    return "its leaf in I is not the approved certificate";
  for (const other of i.identity.devices.values())
    if (other.issuers.some((e) => bytesEqual(e, P))) return "it has issued a certificate";
  return undefined;
}

// ---------------------------------------------------------------------------
// Reconciliation order (SERVICE-CONTROL-PROFILE-01 §7.4, IDENTITY-PROFILE-01 §7.1 step 2)

/** SERVICE-CONTROL-PROFILE-01's Data Profile identifier, as the roster names it. */
export const SERVICE_CONTROL_PROFILE_ID = "org.openlfcp.service-control.v1";

/** A control Resource of the roster, and this client's view of it (undefined: not open here). */
export interface RosterControl {
  readonly resource: ResourceId;
  readonly control?: Pick<ServiceControlPort, "state" | "requestHistory" | "acknowledged">;
}

/**
 * The kind-1 devices `C` names (§7.4 "Reconciliation order"): a device
 * whose scope is exactly `[C]` (a base installation), or one proven by
 * conditions 1 to 3 of the Section rule for some value `requests[rid]` of
 * `C` held now or in its history (`requests`: ServiceControlPort's
 * requestHistory): a `pair-section` request created by `root` or
 * `personal` (§2.4) whose link names a pairing device `J` of `R`, consumed
 * in `I` with digest `d`, and a `DEVICE_GRANT` of `I` with field 2 = `J`
 * binding a leaf with digest `d`, kind 1, root `R`, mask {1, 2}, scope
 * exactly `[X]` (the request's binding). A request deleted from `C` still
 * names its device: the service deletes a request once its event is final
 * with any final state (§3), `failed` before A3 included. The Principal
 * comes from `I`'s chain through `J`; `pairing[rid]` is never read (§5
 * rule 4), and one whose principal is not so proven defers nothing.
 */
export function controlNames(
  identity: LinearChain,
  C: ResourceId,
  requests: readonly ServiceControlRequestRecord[],
): ReadonlySet<string> {
  const I = identity.state;
  const R = I.owner.principalId;
  const out = new Set<string>();
  for (const [hex, d] of I.devices)
    if (
      d.kind === DEVICE_KIND.SERVICE &&
      bytesEqual(d.root, R) &&
      d.scope.length === 1 &&
      bytesEqual(d.scope[0] as ResourceId, C)
    )
      out.add(hex);
  for (const { request, creators } of requests) {
    if (request.op !== "pair-section" || typeof request.binding !== "string") continue;
    if (!createdBy(creators, ["root", "personal"])) continue;
    let J: PrincipalId;
    try {
      J = parsePairingUri(String(request.args.link)).pairingDevice;
    } catch {
      continue;
    }
    const consumed = revocationOf(I, R, J);
    if (consumed?.reason !== 3n || consumed.approval === null || consumed.approval === undefined)
      continue;
    for (const r of identity.records) {
      if (r.body.type !== "DEVICE_GRANT" || r.body.pairingDevice === undefined) continue;
      if (r.body.pairingDevice === null || !bytesEqual(r.body.pairingDevice, J)) continue;
      const leaf = r.body.chain.leaf;
      const p = leaf.payload;
      if (
        bytesEqual(leaf.payloadDigest, consumed.approval) &&
        p.kind === DEVICE_KIND.SERVICE &&
        bytesEqual(p.root, R) &&
        p.mask.length === 2 &&
        p.mask.includes(1n) &&
        p.mask.includes(2n) &&
        p.scope.length === 1 &&
        toBase64url(p.scope[0] as ResourceId) === request.binding
      )
        out.add(toHex(p.device.principalId));
    }
  }
  return out;
}

/**
 * §7.4 for a reconciler that implements the profile: why the registration
 * of kind-1 device `P` is deferred, or undefined when it may go ahead.
 * Every control Resource of the roster must be synchronised (one not open
 * or not synchronised defers every kind-1 registration); when one names
 * `P`, its `approvals[P]` must be present there and accepted by the server
 * (§7.1: A3 before A4 for every client of the profile; IDENTITY §9.1: a
 * phase ends at its ACK). This client's own approval still queued or
 * pending defers, as an absent one does.
 */
export async function controlRegistrationGate(
  identity: LinearChain,
  controls: readonly RosterControl[],
): Promise<(device: PrincipalId) => string | undefined> {
  const waiting = new Map<string, string>();
  for (const c of controls) {
    const state = c.control?.state();
    if (c.control === undefined || state === undefined) {
      const why = `the control Resource ${toHex(c.resource)} is not synchronised`;
      return () => why;
    }
    for (const hex of controlNames(identity, c.resource, c.control.requestHistory())) {
      if (waiting.has(hex)) continue;
      const P = principalRefOf(fromHex(hex) as PrincipalId);
      if (state.approvals[P] === undefined)
        waiting.set(
          hex,
          `the control Resource ${toHex(c.resource)} names it and holds no approval for it yet`,
        );
      else if (!(await c.control.acknowledged("approvals", P)))
        waiting.set(
          hex,
          `the control Resource ${toHex(c.resource)} names it and its approval for it is not accepted by the server yet`,
        );
    }
  }
  return (device) => waiting.get(toHex(device));
}
