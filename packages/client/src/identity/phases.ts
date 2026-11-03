import {
  bytesEqual,
  type ControlRecordId,
  type Hash32,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type CertificateChain,
  type ChainResult,
  type ControlRecord,
  type ControlState,
  DEVICE_KIND,
  type DeviceCertificatePayload,
  revocationOf,
} from "@openlfcp/wire";

/**
 * Phase states of a durable multi-record operation (IDENTITY-PROFILE-01
 * §9.2). After a CONTROL_HEAD_MISMATCH or a restart the client synchronises
 * the Resource and classifies each phase against the accepted chain; one
 * rule applies per kind of phase, first match wins. These functions are
 * pure: the same chain and the same intent give the same state on every
 * installation.
 */
export type PhaseState =
  /** Propose, or propose again on the new head. */
  | "pending"
  /** The chain holds this installation's own record: continue with the next phase. */
  | "committed-own"
  /** The effect exists by someone else's hand and the phase is idempotent: skip it. */
  | "complete"
  /** The chain makes the phase impossible: the operation ends, nothing further is signed. */
  | "superseded"
  /** The rotator test of §8.1 fails on the current head. */
  | "awaiting-rotation"
  /** A KEY_EPOCH is committed whose DEK this client does not hold (§9.2). */
  | "awaiting-key-holder";

export type LinearChain = Extract<ChainResult, { kind: "linear" }>;

const REASON_CONSUMED = 3n;

/** The Consume phase: `DEVICE_REVOKE {R, J, 3, digest}` (§5.3 step 5). */
export function classifyConsume(
  state: ControlState,
  root: PrincipalId,
  pairing: PrincipalId,
  digest: Hash32,
): PhaseState {
  const r = revocationOf(state, root, pairing);
  if (r === undefined) return "pending";
  return r.reason === REASON_CONSUMED && r.approval !== null && bytesEqual(r.approval, digest)
    ? "committed-own"
    : "superseded";
}

/** The Cancel phase of a pairing device: `DEVICE_REVOKE {R, J, 0}` (§5.3 step 9). */
export function classifyCancel(
  state: ControlState,
  root: PrincipalId,
  pairing: PrincipalId,
): PhaseState {
  const r = revocationOf(state, root, pairing);
  if (r === undefined) return "pending";
  return r.reason === REASON_CONSUMED ? "superseded" : "complete";
}

/**
 * The Revoke phase `(R, D)` with a reason in {0, 1, 2}: a revocation with
 * another reason by anyone is `complete` (the operation continues with the
 * rotation test), never `committed-own` or `superseded` (§9.2).
 */
export function classifyRevoke(
  state: ControlState,
  root: PrincipalId,
  device: PrincipalId,
): PhaseState {
  const r = revocationOf(state, root, device);
  if (r === undefined) return "pending";
  return r.reason === REASON_CONSUMED ? "superseded" : "complete";
}

/** Whether a certificate's scope admits `resource` (W §7.3 rule 5; kind 0 has no scope). */
export function certificateInScope(leaf: DeviceCertificatePayload, resource: ResourceId): boolean {
  return leaf.kind === DEVICE_KIND.PERSONAL || leaf.scope.some((r) => bytesEqual(r, resource));
}

const isGrantOf = (record: ControlRecord, leafId: Hash32): boolean =>
  record.body.type === "DEVICE_GRANT" && bytesEqual(record.body.chain.leaf.id, leafId);

/** The accepted DEVICE_GRANT record whose leaf is `leafId`, if any (the latest). */
export function grantRecordOf(chain: LinearChain, leafId: Hash32): ControlRecord | undefined {
  for (let i = chain.records.length - 1; i >= 0; i--) {
    const r = chain.records[i] as ControlRecord;
    if (isGrantOf(r, leafId)) return r;
  }
  return undefined;
}

export interface RegisterPhase {
  readonly root: PrincipalId;
  /** The certificate chain the phase proposes (leaf = the device). */
  readonly chain: CertificateChain;
  /** Phase 2 of a pairing approval: a binding with another leaf is `superseded`. */
  readonly pairingPhase2?: boolean;
  /** Whether a record ID (hex) is one this installation sent for the phase (§9.1: persisted before sending). */
  readonly isOwnRecord: (recordIdHex: string) => boolean;
}

/**
 * The Register or re-certify phase of leaf `D` with certificate `c`
 * (`DEVICE_GRANT`, §9.2). A matching effect (same leaf certificate ID,
 * `registered` agreeing with `c`'s scope here) is `committed-own` when this
 * installation's record produced it, else `complete`; it is never
 * re-proposed as a new transition (W §17.4 rule 5).
 */
export function classifyRegister(chain: LinearChain, phase: RegisterPhase): PhaseState {
  const state = chain.state;
  const leaf = phase.chain.leaf;
  const device = leaf.payload.device.principalId;
  if (revocationOf(state, phase.root, device) !== undefined) return "superseded";
  if (phase.chain.issuers.some((e) => revocationOf(state, phase.root, e) !== undefined))
    return "superseded";
  const d = state.devices.get(toHex(device));
  if (d?.leafId !== null && d?.leafId !== undefined) {
    if (
      bytesEqual(d.leafId, leaf.id) &&
      d.registered === certificateInScope(leaf.payload, state.resourceId)
    ) {
      const record = grantRecordOf(chain, leaf.id);
      return record !== undefined && phase.isOwnRecord(toHex(record.signed.id))
        ? "committed-own"
        : "complete";
    }
    if (!bytesEqual(d.leafId, leaf.id) && phase.pairingPhase2 === true) return "superseded";
  }
  return "pending";
}

/** The control sequence of the record `id` on `chain`, if it is there. */
export function recordSeq(
  chain: LinearChain,
  id: ControlRecordId | Uint8Array,
): bigint | undefined {
  const hex = toHex(id);
  return chain.records.find((r) => toHex(r.signed.id) === hex)?.payload.controlSeq;
}

/**
 * The Rotate phase after a revocation at control sequence `revokedAt`
 * (§9.2, §9.3): `complete` when a KEY_EPOCH is accepted after it;
 * `awaiting-rotation` when the rotator test of §8.1 fails on the current
 * head; otherwise `pending` (the KEY_EPOCH is rebuilt, never re-sent).
 */
export function classifyRotate(
  chain: LinearChain,
  revokedAt: bigint,
  rotator: boolean,
): PhaseState {
  if (keyEpochAfter(chain, revokedAt)) return "complete";
  return rotator ? "pending" : "awaiting-rotation";
}

/** Whether a KEY_EPOCH is accepted at a control sequence greater than `seq` (§8.4: the mark clears). */
export function keyEpochAfter(chain: LinearChain, seq: bigint): boolean {
  return chain.records.some((r) => r.body.type === "KEY_EPOCH" && r.payload.controlSeq > seq);
}

/**
 * A Package phase `(resource, epoch, recipient)` (§9.2): never superseded;
 * `complete` when the ledger records it; a recipient that is no longer a
 * reader at the head is skipped.
 */
export function classifyPackage(ledgered: boolean, readerAtHead: boolean): PhaseState | "skipped" {
  if (ledgered) return "complete";
  return readerAtHead ? "pending" : "skipped";
}
