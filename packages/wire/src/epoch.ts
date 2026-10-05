import {
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  type PrincipalId,
} from "@openlfcp/core";
import {
  dekCommitment as commitmentOf,
  generateResourceDEK,
  type ResourceDEK,
} from "@openlfcp/crypto";
import type { ChainResult, ControlState } from "./chain.js";
import { signControlRecord } from "./control.js";
import type { Signer } from "./cose.js";
import type { ActorHave } from "./have.js";
import type { DataUnitPayload } from "./objects.js";

/**
 * Data Epoch rotation and the strict previous-epoch cutoff (LFCP-WIRE-01
 * §19, §19.1, §26.3 steps 4-5, §75, §88 step 7).
 *
 * After KEY_EPOCH(E + 1) closes epoch E with a final frontier, a Data Unit
 * of epoch E is automatically acceptable only when its actor and sequence
 * are inside that frontier. Anything else is stale offline work: it is
 * quarantined (STALE_DATA_EPOCH), never merged automatically and never
 * dropped silently, and never re-encrypted into a newer epoch. Units within
 * the cutoff stay valid history, and rotation does not take back what a
 * removed member already decrypted (§75).
 *
 * Everything except rotateEpoch (which draws a fresh DEK) is pure.
 */

/** §19 Key Epoch reason codes. Unknown codes are kept by the decoder (structure only). */
export const KEY_EPOCH_REASON = Object.freeze({
  ROUTINE: 0n,
  MEMBER_REVOKED: 1n,
  COMPROMISE: 2n,
  OWNERSHIP_TRANSFER: 3n,
  MANUAL_SECURITY: 4n,
});

/**
 * Whether `seq` of `principal` is inside a final frontier: within the
 * actor's contiguous run (1..contiguous) or one of its explicit extra
 * ranges. An actor absent from the frontier covers nothing (§19.1).
 */
export function isSequenceWithinFrontier(
  principal: PrincipalId,
  seq: bigint,
  frontier: readonly ActorHave[],
): boolean {
  const have = frontier.find((h) => bytesEqual(h.principalId, principal));
  if (have === undefined || seq < 1n) return false;
  return seq <= have.contiguous || have.extras.some(([start, end]) => start <= seq && seq <= end);
}

/** A validated chain, as needed to place a unit: its latest state and its state at any head. */
export type ControlView = Pick<Extract<ChainResult, { kind: "linear" }>, "state" | "stateAt">;

/** The Data Unit fields the epoch rules read. */
export type DataUnitHeader = Pick<
  DataUnitPayload,
  "resourceId" | "dataEpoch" | "actor" | "actorSeq" | "controlHead"
>;

export type EpochClassification =
  | { readonly kind: "accept" }
  /**
   * Stale offline work: never merged automatically, never dropped
   * silently; surface it to the application for manual review (§19.1).
   */
  | {
      readonly kind: "quarantine";
      readonly code: "STALE_DATA_EPOCH";
      readonly reason: "BEYOND_CUTOFF" | "ACTOR_ABSENT";
      readonly epoch: DataEpoch;
      /** The Key Epoch record whose final frontier excludes the unit. */
      readonly closedBy: ControlRecordId;
    }
  | {
      readonly kind: "reject";
      readonly reason: "UNKNOWN_CONTROL_HEAD" | "UNKNOWN_EPOCH" | "OTHER_RESOURCE";
      readonly wireCode: "MISSING_DEPENDENCY" | "MALFORMED_MESSAGE";
    };

/**
 * The epoch-eligibility of a Data Unit (§26.3 steps 4-5).
 *
 * - The unit's referenced Control Head must be on the chain, and its epoch
 *   recognized at that head. Otherwise MISSING_DEPENDENCY (§26.3, G-EP2):
 *   the receiver lacks Control records, or the unit claims a future epoch.
 * - The cutoff is evaluated against the LATEST known state (§19.1, §26.3,
 *   G-EP1). Once a Key Epoch closing the unit's epoch is known, the unit is
 *   held to its final frontier, whichever head the unit referenced (vector
 *   §12.5: D3 is stale "after C6 is known").
 *
 * Signature, data/write authority at the referenced head and AEAD are
 * checked by the Data Unit verifier (LFCP-025), which calls this hook.
 */
export function classifyDataUnit(view: ControlView, unit: DataUnitHeader): EpochClassification {
  if (!bytesEqual(unit.resourceId, view.state.resourceId))
    return Object.freeze({
      kind: "reject",
      reason: "OTHER_RESOURCE",
      wireCode: "MALFORMED_MESSAGE",
    });
  const atHead = view.stateAt(unit.controlHead);
  if (atHead === undefined)
    return Object.freeze({
      kind: "reject",
      reason: "UNKNOWN_CONTROL_HEAD",
      wireCode: "MISSING_DEPENDENCY",
    });
  if (!atHead.epochs.has(String(unit.dataEpoch)))
    return Object.freeze({
      kind: "reject",
      reason: "UNKNOWN_EPOCH",
      wireCode: "MISSING_DEPENDENCY",
    });
  const latest = view.state.epochs.get(String(unit.dataEpoch));
  if (latest === undefined || latest.finalFrontier === null || latest.closedBy === null)
    return Object.freeze({ kind: "accept" });
  if (isSequenceWithinFrontier(unit.actor, unit.actorSeq, latest.finalFrontier))
    return Object.freeze({ kind: "accept" });
  const absent = !latest.finalFrontier.some((h) => bytesEqual(h.principalId, unit.actor));
  return Object.freeze({
    kind: "quarantine",
    code: "STALE_DATA_EPOCH",
    reason: absent ? "ACTOR_ABSENT" : "BEYOND_CUTOFF",
    epoch: unit.dataEpoch,
    closedBy: latest.closedBy,
  });
}

export type DataPutDecision =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly nack: "STALE_DATA_EPOCH" | "MISSING_DEPENDENCY" | "MALFORMED_MESSAGE";
      readonly reason: string;
    };

/**
 * The server's epoch check for one unit of a DATA_PUT (§75: "A server that
 * receives such a unit in DATA_PUT responds NACK(STALE_DATA_EPOCH)"). The
 * other §51 checks (structure, signature, size, hosting policy) are the
 * caller's.
 */
export function serverAcceptsDataPut(view: ControlView, unit: DataUnitHeader): DataPutDecision {
  const c = classifyDataUnit(view, unit);
  if (c.kind === "accept") return Object.freeze({ ok: true });
  if (c.kind === "quarantine")
    return Object.freeze({
      ok: false,
      nack: "STALE_DATA_EPOCH",
      reason: `${c.reason}: outside the final frontier of epoch ${c.epoch}`,
    });
  return Object.freeze({ ok: false, nack: c.wireCode, reason: c.reason });
}

/** A new Key Epoch: the record to submit, and the fresh DEK, which never goes into the record. */
export interface EpochRotation {
  readonly bytes: Uint8Array;
  readonly recordId: ControlRecordId;
  readonly epoch: DataEpoch;
  /** The new epoch's DEK: deliver it in Key Packages (LFCP-024), never in a Control record. */
  readonly dek: ResourceDEK;
  readonly dekCommitment: Hash32;
}

/**
 * Builds KEY_EPOCH(current + 1) on the current head: a fresh random DEK
 * (LFCP-018; never the previous one), its §11 commitment, the closing
 * epoch's canonical final frontier and a §19 reason. Submit it with
 * CONTROL_PUT (proposeControlTransition); the issuer needs key/rotate.
 */
export function rotateEpoch(
  state: ControlState,
  signer: Signer,
  options: {
    readonly reason: bigint;
    readonly finalFrontier: readonly ActorHave[];
    readonly dek?: ResourceDEK;
  },
): EpochRotation {
  const epoch = dataEpoch(state.epoch.epoch + 1n);
  const dek = options.dek ?? generateResourceDEK();
  const dekCommitment = commitmentOf(state.resourceId, epoch, dek);
  const signed = signControlRecord(
    { resourceId: state.resourceId, controlSeq: state.seq + 1n, prevControlId: state.head },
    {
      type: "KEY_EPOCH",
      epoch,
      dekCommitment,
      finalFrontier: options.finalFrontier,
      reason: options.reason,
    },
    signer,
  );
  return Object.freeze({
    bytes: signed.bytes,
    recordId: signed.recordId,
    epoch,
    dek,
    dekCommitment,
  });
}
