import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  fromHex,
  type PrincipalId,
  type ResourceId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { generateResourceDEK } from "@openlfcp/crypto";
import type { LfcpStorage } from "@openlfcp/storage";
import {
  ABILITY,
  actsFor,
  addSequence,
  type ControlState,
  checkDataUnit,
  type HaveVector,
  hasAbility,
  hasSequence,
  InMemorySeenUnits,
  isExposingRevocation,
  KEY_EPOCH_REASON,
  type PrincipalDescriptor,
  parseDataUnit,
  rotateEpoch,
} from "@openlfcp/wire";
import { resourceSyncState } from "../outbound.js";
import { loadControlChain } from "../storage.js";
import {
  deliverKeys,
  heldDeks,
  type KeyDelivery,
  readersAt,
  runControlPhase,
  storeDek,
  withoutEquivocations,
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
import { type ChannelPool, type IdentityChannel, IdentityUnavailable } from "./network.js";
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
  local: HaveVector = [],
): Promise<HaveVector> {
  const R = chain.state.resourceId;
  const opened = await channel.open(R);
  if (opened.kind === "nack") return local;
  const ranges = opened.haves.flatMap((h) => {
    const out = h.contiguous > 0n ? [{ actor: h.principalId, start: 1n, end: h.contiguous }] : [];
    for (const [start, end] of h.ranges ?? []) out.push({ actor: h.principalId, start, end });
    return out;
  });
  // Both units of an equivocation are excluded (W §26.2), whatever came first.
  const units = withoutEquivocations(
    chain,
    (await channel.dataUnits(R, ranges)).map((bytes) => ({ bytes, parsed: parseDataUnit(bytes) })),
  ).sort((a, b) => {
    const x = toHex(a.parsed.payload.actor);
    const y = toHex(b.parsed.payload.actor);
    return x !== y
      ? x < y
        ? -1
        : 1
      : a.parsed.payload.actorSeq < b.parsed.payload.actorSeq
        ? -1
        : 1;
  });
  const seen = new InMemorySeenUnits();
  const accepted = new Map<string, Set<string>>();
  let frontier: HaveVector = local;
  for (const { bytes, parsed } of units) {
    const p = parsed.payload;
    const check = await checkDataUnit(chain, bytes, seen);
    if (check.kind !== "valid") continue;
    // The actor's hash chain (W §26.2): a unit is accepted when it names an
    // accepted unit of its actor, or none before the actor's first.
    const mine = accepted.get(toHex(p.actor)) ?? new Set<string>();
    const links =
      p.prevDataUnitId === null
        ? mine.size === 0 && !local.some((h) => bytesEqual(h.principalId, p.actor))
        : mine.has(toHex(p.prevDataUnitId)) || hasSequence(local, p.actor, p.actorSeq - 1n);
    if (!links) continue;
    mine.add(toHex(check.unitId));
    accepted.set(toHex(p.actor), mine);
    frontier = addSequence(frontier, p.actor, p.actorSeq);
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
  // The epoch of this operation's own accepted KEY_EPOCH, found by its record ID.
  let ownEpoch: DataEpoch | undefined;
  const outcome = await runControlPhase(o.storage, o.channel, journal, o.operation, {
    id,
    kind: "rotate",
    resource: R,
    facts: { revokedAt: String(o.revokedAt) },
    // §9.3: rebuilt with the current accepted set on every attempt, even on the same head.
    resend: false,
    classify: (chain, isOwn): PhaseState => {
      const own = chain.records.find(
        (r) =>
          r.body.type === "KEY_EPOCH" &&
          r.payload.controlSeq > o.revokedAt &&
          isOwn(toHex(r.signed.id)),
      );
      if (own?.body.type === "KEY_EPOCH") {
        ownEpoch = own.body.epoch;
        return "committed-own";
      }
      if (keyEpochAfter(chain, o.revokedAt)) return "complete";
      return rotatorTest(chain.state, me.descriptor.principalId).rotator
        ? "pending"
        : "awaiting-rotation";
    },
    build: async (chain) => {
      const frontier = await verifiedFrontier(o.channel, chain, await localHave(o, chain));
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
  if (outcome.state === "committed-own" && ownEpoch === undefined)
    // The ACK of this installation's own record (runControlPhase extended the chain with it).
    ownEpoch = chain.state.epoch.epoch;
  if (outcome.state === "committed-own") {
    // The pending DEK is the key of this operation's own epoch, not of the current one:
    // another rotator may have closed it since (§9.2, §9.3).
    const dek = await getPendingDek(o.secrets, R, o.operation);
    if (dek !== undefined && ownEpoch !== undefined) {
      await storeDek(o.storage, o.secrets, chain, ownEpoch, dek);
      await o.secrets.delete(pendingDekRef(R, o.operation));
    }
  }
  const epoch = ownEpoch ?? chain.state.epoch.epoch;
  const deks = await heldDeks(o.secrets, chain);
  if (!deks.has(String(epoch))) return { resource: R, status: "awaiting-key-holder", epoch };
  // Every epoch held from the rotated one on, to every reader of the head (§8.2); a takeover
  // seals only what it holds (§9.6).
  const send = new Map([...deks].filter(([e]) => BigInt(e) >= epoch));
  const keys = await deliverKeys({
    channel: o.channel,
    ledger: new PackageLedger(o.storage),
    chain,
    sender: me,
    recipients: readersAt(chain.state),
    deks: send,
  });
  const phase = phaseOf(await journal.load(o.operation), id);
  return {
    resource: R,
    status: phase?.state === "committed-own" ? "rotated" : "complete",
    epoch,
    keys,
  };
}

/**
 * The accepted set this installation holds locally for the Resource (its
 * stored accepted units and verified Snapshots, when the storage keeps them),
 * merged into the verified frontier (§8.3).
 */
async function localHave(o: FlowOptions, chain: LinearChain): Promise<HaveVector> {
  const s = o.storage as Partial<LfcpStorage>;
  if (
    s.dataUnits === undefined ||
    s.outbound === undefined ||
    s.syncState === undefined ||
    s.snapshots === undefined
  )
    return [];
  return (await resourceSyncState(s as LfcpStorage, chain.state.resourceId)).have;
}

/**
 * Resumes every rotation a journaled operation started and did not adopt:
 * a KEY_EPOCH whose ACK was lost leaves its DEK in the operation's pending
 * slot, whatever operation (revocation, reconciliation, pairing) started
 * it (§9.1, §9.2). Run before planning new work on a Resource.
 */
export async function resumeRotations(
  o: FlowOptions & { readonly pool: ChannelPool },
): Promise<readonly RotationOutcome[]> {
  const journal = new OperationJournal(o.storage);
  const out: RotationOutcome[] = [];
  for (const op of await journal.list())
    for (const phase of op.phases) {
      if (phase.kind !== "rotate" || phase.facts?.revokedAt === undefined) continue;
      const R = resourceId(fromHex(phase.resource));
      if ((await getPendingDek(o.secrets, R, op.id)) === undefined) continue;
      const stored = await loadControlChain(o.storage, R);
      if (stored?.kind !== "linear") continue;
      try {
        const channel = await o.pool.get(o.installation.signer, stored.state.route.coordinatorUrl);
        out.push(
          await rotateAfter({
            ...o,
            channel,
            operation: op.id,
            resource: R,
            revokedAt: BigInt(phase.facts.revokedAt),
          }),
        );
      } catch (e) {
        if (!(e instanceof IdentityUnavailable)) throw e;
        out.push({ resource: R, status: "unreachable" });
      }
    }
  return Object.freeze(out);
}

/** The control sequence of a record ID (hex) on a chain. */
export const seqOf = (chain: LinearChain, recordIdHex: string): bigint | undefined =>
  recordSeq(chain, fromHex(recordIdHex));
