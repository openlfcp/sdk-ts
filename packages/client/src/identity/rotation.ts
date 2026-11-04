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
import { generateResourceDEK, sha256 } from "@openlfcp/crypto";
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
import { snapshotFrontier } from "../outbound.js";
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
  local: LocalAccepted = { units: [], snapshot: [] },
): Promise<HaveVector> {
  const R = chain.state.resourceId;
  const opened = await channel.open(R);
  const ranges =
    opened.kind === "nack"
      ? []
      : opened.haves.flatMap((h) => {
          const out =
            h.contiguous > 0n ? [{ actor: h.principalId, start: 1n, end: h.contiguous }] : [];
          for (const [start, end] of h.ranges ?? []) out.push({ actor: h.principalId, start, end });
          return out;
        });
  // The fetched and the locally stored units together: an equivocation between a
  // stored unit and a fetched one excludes both, like one within the fetch (W §26.2).
  const all = new Map<string, Uint8Array>();
  for (const bytes of [...local.units, ...(await channel.dataUnits(R, ranges))])
    all.set(toHex(sha256(bytes)), bytes);
  const parsedAll = [...all.values()].map((bytes) => ({ bytes, parsed: parseDataUnit(bytes) }));
  // Every unit ID this installation knows of, whatever became of the unit (accepted,
  // excluded as equivocation, or later in this pass): a previous naming one of them
  // is a known fact about the link, never an unknown unit at a Snapshot position.
  const knownIds = new Set(parsedAll.map((u) => toHex(u.parsed.signed.id)));
  const units = withoutEquivocations(chain, parsedAll).sort((a, b) => {
    const x = toHex(a.parsed.payload.actor);
    const y = toHex(b.parsed.payload.actor);
    if (x !== y) return x < y ? -1 : 1;
    return a.parsed.payload.actorSeq < b.parsed.payload.actorSeq ? -1 : 1;
  });
  const seen = new InMemorySeenUnits();
  // Per actor: the latest accepted unit held as bytes.
  const latest = new Map<string, { id: string; seq: bigint }>();
  // Sequences covered by a verified Snapshot count as accepted (W §29.3).
  let frontier: HaveVector = local.snapshot;
  for (const { bytes, parsed } of units) {
    const p = parsed.payload;
    const check = await checkDataUnit(chain, bytes, seen);
    if (check.kind !== "valid") continue;
    const actor = toHex(p.actor);
    const last = latest.get(actor);
    let links: boolean;
    if (hasSequence(local.snapshot, p.actor, p.actorSeq)) links = true;
    else {
      // The actor's last accepted position before this unit: its latest held unit
      // or the highest sequence a verified Snapshot covers, whichever is later.
      const covered = coveredBelow(local.snapshot, p.actor, p.actorSeq);
      const position = (last?.seq ?? 0n) > covered ? (last?.seq ?? 0n) : covered;
      const prev = p.prevDataUnitId === null ? null : toHex(p.prevDataUnitId);
      // W §26.2: the unit names the actor's latest accepted unit (gaps allowed),
      // or none before the actor's first. When that unit is covered by a
      // Snapshot without its bytes here, its ID cannot be compared: the link is
      // taken only when it names no unit known here at all (not an accepted older
      // one, not an excluded twin, not a later unit of this pass).
      if (position === 0n) links = prev === null;
      else if (prev === null) links = false;
      else if (last !== undefined && last.seq === position) links = last.id === prev;
      else links = !knownIds.has(prev);
    }
    if (!links) continue;
    if (last === undefined || last.seq < p.actorSeq)
      latest.set(actor, { id: toHex(check.unitId), seq: p.actorSeq });
    frontier = addSequence(frontier, p.actor, p.actorSeq);
  }
  return frontier;
}

/** The highest sequence of `actor` below `seq` that `vector` covers, or 0. */
function coveredBelow(vector: HaveVector, actor: Uint8Array, seq: bigint): bigint {
  const h = vector.find((x) => bytesEqual(x.principalId, actor));
  if (h === undefined) return 0n;
  let best = h.contiguous < seq ? h.contiguous : seq - 1n;
  for (const [start, end] of h.extras)
    if (start < seq) {
      const top = end < seq ? end : seq - 1n;
      if (top > best) best = top;
    }
  return best;
}

/** This installation's stored units of a Resource and its verified Snapshots' coverage. */
export interface LocalAccepted {
  /** Every signature-valid unit the storage holds for the Resource (exact bytes). */
  readonly units: readonly Uint8Array[];
  /** The sequences verified Snapshots cover (W §29.3). */
  readonly snapshot: HaveVector;
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
      const frontier = await verifiedFrontier(o.channel, chain, await localAccepted(o, chain));
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
async function localAccepted(o: FlowOptions, chain: LinearChain): Promise<LocalAccepted> {
  const st = o.storage as Partial<LfcpStorage>;
  if (st.dataUnits === undefined || st.snapshots === undefined) return { units: [], snapshot: [] };
  const R = chain.state.resourceId;
  // Every stored unit takes part: the storage keeps only signature-valid units,
  // whatever became of their content, and equivocation evidence (both twins,
  // stored as "equivocation") must reach the check (W §26.2).
  const units: Uint8Array[] = [];
  for (const status of [
    "seen",
    "merged",
    "profile-pending",
    "held",
    "quarantined",
    "equivocation",
    "local-failure",
    "profile-held",
    "profile-rejected",
    "profile-unsupported",
  ] as const)
    for (const u of await st.dataUnits.withStatus(R, status)) units.push(u.bytes);
  return { units, snapshot: await snapshotFrontier(st as LfcpStorage, R) };
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
