import { bytesEqual, fromBase64url, type ResourceId, resourceId } from "@openlfcp/core";
import { parsePairingUri } from "@openlfcp/wire";
import { IdentityConflict } from "./context.js";
import {
  createdBy,
  type IdentityRequestEntry,
  type SectionApprovalDecision,
  type ServiceControlCommitOutcome,
  type ServiceControlPort,
  sectionApprovalDecision,
} from "./control-approval.js";
import { OperationJournal } from "./journal.js";
import { ChannelPool, IdentityUnavailable } from "./network.js";
import {
  type ApprovalResult,
  approvePairing,
  type CancelResult,
  cancelPairing,
  openIdentity,
  readSession,
  resumeApproval,
  reviewOf,
} from "./pairing.js";
import type { IdentityFlowOptions } from "./resource.js";

/**
 * A section installation paired through the control Resource `C`
 * (SERVICE-CONTROL-PROFILE-01 §8.1 step 3, A§4.3): the managing client that
 * created `J_X` and wrote `requests[rid] = {op: "pair-section", binding: X,
 * args: {link}}` re-checks on every push or open of `I` and `C`, approves
 * without the human when sectionApprovalDecision allows it (phases A1–A4,
 * A3 in `C`), and otherwise waits, or cancels `J_X` and writes
 * `cancels[rid]` on an established mismatch or once its local deadline
 * passed. The link in `args.link` is read for its `device` only; it is
 * never journaled or logged (IDENTITY §9.8).
 */

export interface AutoApproveSectionOptions extends IdentityFlowOptions {
  /** The pairing session of `J_X` (createPairingSession). */
  readonly session: string;
  /** The `rid` of the `pair-section` request this installation wrote in `C`. */
  readonly rid: string;
  readonly control: ServiceControlPort;
  /**
   * The attempt's local deadline passed (A§4.1, 30 minutes): a session
   * still waiting is cancelled with `reason: "expired"`.
   */
  readonly expired?: boolean;
}

export type SectionApprovalResult =
  /** A record is missing: call again on the next push or open of `I` or `C`. */
  | { readonly kind: "waiting"; readonly reason: string }
  /** This installation did not create `J_X` for this request: nothing done. */
  | { readonly kind: "not-own"; readonly reason: string }
  /** `J_X` was cancelled already: nothing new is cancelled. */
  | { readonly kind: "closed" }
  /**
   * The approval ran, or a consumed session carried on (no cancellation after
   * the consume, A§4.4): its result, `approved` once A4 is done.
   */
  | { readonly kind: "approval"; readonly approval: ApprovalResult }
  /** `J_X` cancelled (reason 0) and `cancels[rid]` written with `reason`. */
  | {
      readonly kind: "cancelled";
      readonly reason: "mismatch" | "expired";
      readonly detail: string;
      /** The cancel of `J_X`; undefined when it was cancelled by an earlier call. */
      readonly cancel?: CancelResult;
      /** The `cancels[rid]` write; undefined when `C` already held one. */
      readonly written?: ServiceControlCommitOutcome;
    }
  | { readonly kind: "unavailable"; readonly reason: string }
  | { readonly kind: "conflict" };

const iso = (ms: number) => `${new Date(ms).toISOString().slice(0, 19)}Z`;

/** §8.1 step 3: one re-check of a section pairing, and what it led to. */
export async function autoApproveSection(
  o: AutoApproveSectionOptions,
): Promise<SectionApprovalResult> {
  const journal = new OperationJournal(o.storage);
  const known = await journal.get(o.session);
  if (known?.kind !== "pairing-session")
    return { kind: "not-own", reason: "this installation has no such pairing session" };
  // A cancel decided before (journaled before J was revoked, A§4.3): finished first.
  const decided = known.intent.cancelReason;
  if (decided === "mismatch" || decided === "expired")
    return cancel(o, journal, decided, "a cancel decided before is finished");
  const { I, R, J, url } = await readSession(o, o.session);
  const state = o.control.state();
  if (state === undefined) return { kind: "waiting", reason: "C is not synchronised" };

  // requests[rid]: a pair-section request this installation wrote, naming J in its link.
  const me = o.installation.signer;
  const request = state.requests[o.rid];
  const notOwn = (reason: string): SectionApprovalResult => ({ kind: "not-own", reason });
  if (request === undefined) return notOwn("C holds no requests[rid]");
  const creators = o.control.creatorsOf("requests", o.rid);
  if (
    request.op !== "pair-section" ||
    typeof request.binding !== "string" ||
    !createdBy(creators, ["root", "personal"]) ||
    !creators.every((c) => bytesEqual(c.signer, me.descriptor.principalId))
  )
    return notOwn("requests[rid] is not a pair-section request this installation wrote");
  let linked: ReturnType<typeof parsePairingUri>["pairingDevice"];
  try {
    linked = parsePairingUri(String(request.args.link)).pairingDevice;
  } catch {
    return notOwn("requests[rid].args.link is not a pairing link");
  }
  if (!bytesEqual(linked, J)) return notOwn("requests[rid] links another pairing device");
  let X: ResourceId;
  try {
    X = resourceId(fromBase64url(request.binding));
  } catch {
    return notOwn("requests[rid].binding is not a ResourceRef");
  }
  const generation = request.generation ?? 0;

  const pool = new ChannelPool(o.network);
  let decision: SectionApprovalDecision;
  let review: ReturnType<typeof reviewOf>;
  try {
    const channel = await pool.get(me, url);
    const { chain, doc } = await openIdentity(o, channel, I);
    const requests: IdentityRequestEntry[] = [...doc.requests()].map(([key, entry]) => ({
      key,
      entry,
      signers: doc.origins("requests", key).map((w) => w.signer),
    }));
    const pairing = state.pairing[o.rid];
    decision = sectionApprovalDecision({
      root: R,
      identity: chain.state,
      pairingDevice: J,
      ownSession: true,
      binding: X,
      requests,
      ...(pairing === undefined
        ? {}
        : { pairing: { ...pairing, creators: o.control.creatorsOf("pairing", o.rid) } }),
    });
    review =
      decision.kind === "approve"
        ? reviewOf(o, o.session, chain, doc, R, J, I, decision.request.key, decision.request.entry)
        : undefined;
  } catch (e) {
    if (e instanceof IdentityUnavailable) return { kind: "unavailable", reason: e.message };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }

  switch (decision.kind) {
    case "not-own":
      return notOwn("this installation did not create J");
    case "closed":
      // Cancelled by another hand (a cancel of ours is journaled and finished above).
      return decision.consumed
        ? ((await carryOn(o, journal)) ?? { kind: "closed" })
        : { kind: "closed" };
    case "wait":
      return o.expired === true
        ? cancel(o, journal, "expired", decision.reason)
        : { kind: "waiting", reason: decision.reason };
    case "mismatch":
      return cancel(o, journal, "mismatch", decision.reason);
    case "approve": {
      if (review === undefined) return { kind: "waiting", reason: "the request is not reviewable" };
      const pairing = state.pairing[o.rid] as { readonly fp: string };
      return {
        kind: "approval",
        approval: await approvePairing({
          ...o,
          review,
          preset: "service",
          scope: [X],
          approvalRecord: { role: "section", origin: o.rid, generation },
          preAuthorised: { fingerprint: pairing.fp },
        }),
      };
    }
  }
}

/** A consumed session of this installation: its approval carries on (A§4.4). */
async function carryOn(
  o: AutoApproveSectionOptions,
  journal: OperationJournal,
): Promise<SectionApprovalResult | undefined> {
  const own = (await journal.list({ kind: "pairing-approval" })).find(
    (a) => a.intent.session === o.session && a.status !== "superseded",
  );
  if (own === undefined) return undefined;
  return { kind: "approval", approval: await resumeApproval(o, own.id) };
}

/**
 * Step 9 and §6.3: cancel `J_X`, then `cancels[rid]` in `C`; a consumed
 * session carries on instead. The decision (reason and time) is journaled
 * on the session before `J_X` is revoked (§9.1), so a lost answer or a
 * crash at any point is finished by the next call: cancelPairing again
 * (its phases classified by §9.2: the revocation, then the rotation of I),
 * then the same `cancels[rid]` write under the same operation.
 */
async function cancel(
  o: AutoApproveSectionOptions,
  journal: OperationJournal,
  reason: "mismatch" | "expired",
  detail: string,
): Promise<SectionApprovalResult> {
  const op = await journal.load(o.session);
  const at = typeof op.intent.cancelAt === "string" ? op.intent.cancelAt : iso(o.now());
  const why =
    op.intent.cancelReason === "mismatch" || op.intent.cancelReason === "expired"
      ? op.intent.cancelReason
      : reason;
  if (op.intent.cancelAt === undefined)
    await journal.updateIntent(o.session, { cancelAt: at, cancelReason: why });
  const cancelled = await cancelPairing({ ...o, session: o.session });
  if (cancelled.kind === "consumed")
    return (
      (cancelled.operation === undefined
        ? undefined
        : {
            kind: "approval" as const,
            approval: await resumeApproval(o, cancelled.operation),
          }) ?? { kind: "closed" }
    );
  if (cancelled.kind === "unavailable") return { kind: "unavailable", reason: cancelled.reason };
  if (cancelled.kind === "conflict") return { kind: "conflict" };
  if (cancelled.kind === "refused")
    return { kind: "cancelled", reason: why, detail, cancel: cancelled };
  const state = o.control.state();
  if (state === undefined)
    return { kind: "waiting", reason: "J_X is cancelled; cancels[rid] waits for C to synchronise" };
  // Written by another hand: nothing to add. Our own write is committed again until
  // acknowledged (the same operation: a receipt, never a second change).
  const ours = (await journal.load(o.session)).intent.cancelWritten === true;
  if (state.cancels[o.rid] !== undefined && !ours)
    return { kind: "cancelled", reason: why, detail, cancel: cancelled };
  if (!ours) await journal.updateIntent(o.session, { cancelWritten: true });
  const written = await o.control.commit(
    [{ intent: "cancel.create", rid: o.rid, cancel: { reason: why, at } }],
    `${o.session}:cancel`,
  );
  return { kind: "cancelled", reason: why, detail, cancel: cancelled, written };
}
