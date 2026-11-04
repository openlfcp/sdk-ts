import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  fromHex,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { generateResourceDEK } from "@openlfcp/crypto";
import {
  ABILITY,
  actsFor,
  addSequence,
  type ControlState,
  checkDataUnit,
  type HaveVector,
  hasAbility,
  InMemorySeenUnits,
  isExposingRevocation,
  KEY_EPOCH_REASON,
  type PrincipalDescriptor,
  parseDataUnit,
  rotateEpoch,
} from "@openlfcp/wire";
import {
  deliverKeys,
  heldDeks,
  type KeyDelivery,
  readersAt,
  runControlPhase,
  storeDek,
} from "./context.js";
import type { FlowOptions } from "./devices.js";
import {
  getPendingDek,
  OperationJournal,
  PackageLedger,
  pendingDekRef,
  phaseOf,
  putPendingDek,
} from "./journal.js";
import type { IdentityChannel } from "./network.js";
import { keyEpochAfter, type LinearChain, type PhaseState, recordSeq } from "./phases.js";

/**
 * Key rotation after device revocations (IDENTITY-PROFILE-01 §8.1–§8.4,
 * §9.2–§9.4): who may rotate, which revocations call for it, the final
 * frontier from the verified accepted set, and the durable KEY_EPOCH
 * phase with its packages.
 */

/** §8.1: the rotator test of `candidate` on a state (usually the post-state). */
export interface RotatorTest {
  readonly holds6: boolean;
  readonly holds7: boolean;
  /** Every reader of the head acts for the candidate's root (W §25.2 same-root delivery). */
  readonly everyReaderOfOwnRoot: boolean;
  readonly rotator: boolean;
  readonly readers: readonly PrincipalDescriptor[];
}

/**
 * `A` is the rotator of a Resource only when `holds(A, 7)` and it can seal
 * the new DEK to every reader of the head: `holds(A, 6)`, or every reader
 * is of `A`'s root.
 */
export function rotatorTest(state: ControlState, candidate: PrincipalId): RotatorTest {
  const readers = readersAt(state);
  const root = actsFor(state, candidate);
  const holds6 = hasAbility(state, candidate, ABILITY.KEY_DISTRIBUTE);
  const holds7 = hasAbility(state, candidate, ABILITY.KEY_ROTATE);
  const everyReaderOfOwnRoot = readers.every((r) =>
    bytesEqual(actsFor(state, r.principalId), root),
  );
  return Object.freeze({
    holds6,
    holds7,
    everyReaderOfOwnRoot,
    rotator: holds7 && (holds6 || everyReaderOfOwnRoot),
    readers,
  });
}

/** An exposing DEVICE_REVOKE on a chain (W §17.5). */
export interface ExposingRevocation {
  readonly recordId: ControlRecordId;
  readonly seq: bigint;
}

/**
 * §8.4: the exposing revocations committed after the current epoch's
 * KEY_EPOCH (or Genesis). One rotation covers all of them; a revocation
 * that is not exposing never calls for one.
 */
export function exposingRevocationsSince(chain: LinearChain): readonly ExposingRevocation[] {
  const opened = chain.state.epochs.get(String(chain.state.epoch.epoch))?.openedBy;
  const from = opened === undefined ? 0n : (recordSeq(chain, opened) ?? 0n);
  const out: ExposingRevocation[] = [];
  for (let i = 1; i < chain.records.length; i++) {
    const r = chain.records[i];
    if (r === undefined || r.body.type !== "DEVICE_REVOKE" || r.payload.controlSeq <= from)
      continue;
    const before = chain.stateAt(chain.records[i - 1]?.signed.id as Uint8Array);
    const after = chain.stateAt(r.signed.id);
    if (before !== undefined && after !== undefined && isExposingRevocation(before, after))
      out.push({ recordId: controlRecordId(r.signed.id), seq: r.payload.controlSeq });
  }
  return Object.freeze(out);
}

/**
 * §8.3: the final frontier of the closing epoch from this installation's
 * locally verified accepted set, after a Data synchronisation: a server's
 * Have Vector is a fetch hint; a sequence that cannot be fetched and
 * verified, or that fails authorization, stays outside.
 */
export async function verifiedFrontier(
  channel: IdentityChannel,
  chain: LinearChain,
): Promise<HaveVector> {
  const R = chain.state.resourceId;
  const opened = await channel.open(R);
  if (opened.kind === "nack") return [];
  const ranges = opened.haves.flatMap((h) => {
    const out = h.contiguous > 0n ? [{ actor: h.principalId, start: 1n, end: h.contiguous }] : [];
    for (const [start, end] of h.ranges ?? []) out.push({ actor: h.principalId, start, end });
    return out;
  });
  const units = (await channel.dataUnits(R, ranges))
    .map((bytes) => ({ bytes, p: parseDataUnit(bytes).payload }))
    .sort((a, b) => {
      const x = toHex(a.p.actor);
      const y = toHex(b.p.actor);
      return x !== y ? (x < y ? -1 : 1) : a.p.actorSeq < b.p.actorSeq ? -1 : 1;
    });
  const seen = new InMemorySeenUnits();
  let frontier: HaveVector = [];
  for (const { bytes, p } of units) {
    const check = await checkDataUnit(chain, bytes, seen);
    if (check.kind === "valid") frontier = addSequence(frontier, p.actor, p.actorSeq);
  }
  return frontier;
}

export type RotationStatus =
  /** This installation committed the KEY_EPOCH and sealed the new DEK to every reader. */
  | "rotated"
  /** Another writer closed the epoch after the revocation (§9.3). */
  | "complete"
  /** The rotator test fails here: the root or an owner-acting device rotates (§8.1). */
  | "awaiting-rotation"
  /** The new epoch's DEK is not held here: readers wait for its holder (§9.2). */
  | "awaiting-key-holder"
  /** No exposing revocation since the current epoch opened (§8.4). */
  | "not-needed"
  /** The coordinator stopped answering during the rotation: resume the operation (§9.1). */
  | "unreachable"
  | "refused";

export interface RotationOutcome {
  readonly resource: ResourceId;
  readonly status: RotationStatus;
  readonly epoch?: DataEpoch;
  readonly keys?: KeyDelivery;
  readonly code?: string;
}

/**
 * The Rotate phase after a revocation at control sequence `revokedAt`
 * (§8.2, §8.4, §9.2–§9.4), journaled in `operation`. The KEY_EPOCH is
 * always rebuilt on the current head with the current epoch number, the
 * verified frontier and a DEK persisted before the record is sent; a DEK
 * is never sealed before its record is accepted, so a rebuilt record may
 * reuse it (§9.4). After the ACK the DEK goes to every reader of the new
 * head, each package recorded in the ledger; the revoked device, a
 * consumed or cancelled pairing device and suspended devices are not
 * readers and receive nothing.
 */
export async function rotateAfter(
  o: FlowOptions & {
    readonly channel: IdentityChannel;
    readonly operation: string;
    readonly resource: ResourceId;
    readonly revokedAt: bigint;
  },
): Promise<RotationOutcome> {
  const journal = new OperationJournal(o.storage);
  const me = o.installation.signer;
  const R = o.resource;
  const id = `rotate:${toHex(R)}`;
  const outcome = await runControlPhase(o.storage, o.channel, journal, o.operation, {
    id,
    kind: "rotate",
    resource: R,
    facts: { revokedAt: String(o.revokedAt) },
    classify: (chain, isOwn): PhaseState => {
      const own = chain.records.some(
        (r) =>
          r.body.type === "KEY_EPOCH" &&
          r.payload.controlSeq > o.revokedAt &&
          isOwn(toHex(r.signed.id)),
      );
      if (own) return "committed-own";
      if (keyEpochAfter(chain, o.revokedAt)) return "complete";
      return rotatorTest(chain.state, me.descriptor.principalId).rotator
        ? "pending"
        : "awaiting-rotation";
    },
    build: async (chain) => {
      const frontier = await verifiedFrontier(o.channel, chain);
      const dek = (await getPendingDek(o.secrets, R, o.operation)) ?? generateResourceDEK();
      // The DEK before the record that commits to it (§9.1).
      await putPendingDek(o.secrets, R, o.operation, dek);
      return rotateEpoch(chain.state, me, {
        reason: KEY_EPOCH_REASON.COMPROMISE,
        finalFrontier: frontier,
        dek,
      }).bytes;
    },
  });
  if (outcome.state === "refused")
    return { resource: R, status: "refused", code: outcome.code ?? "refused" };
  if (outcome.state === "awaiting-rotation") return { resource: R, status: "awaiting-rotation" };
  const chain = outcome.chain;
  const epoch = chain.state.epoch.epoch;
  if (outcome.state === "committed-own") {
    const dek = await getPendingDek(o.secrets, R, o.operation);
    if (dek !== undefined) {
      await storeDek(o.storage, o.secrets, chain, epoch, dek);
      await o.secrets.delete(pendingDekRef(R, o.operation));
    }
  }
  const deks = await heldDeks(o.secrets, chain);
  if (!deks.has(String(epoch))) return { resource: R, status: "awaiting-key-holder", epoch };
  // The new epoch's DEK to every reader of the head (§8.2); a takeover seals only what it holds (§9.6).
  const keys = await deliverKeys({
    channel: o.channel,
    ledger: new PackageLedger(o.storage),
    chain,
    sender: me,
    recipients: readersAt(chain.state),
    deks: new Map([[String(epoch), deks.get(String(epoch)) as never]]),
  });
  const phase = phaseOf(await journal.load(o.operation), id);
  return {
    resource: R,
    status: phase?.state === "committed-own" ? "rotated" : "complete",
    epoch,
    keys,
  };
}

/** The control sequence of a record ID (hex) on a chain. */
export const seqOf = (chain: LinearChain, recordIdHex: string): bigint | undefined =>
  recordSeq(chain, fromHex(recordIdHex));
