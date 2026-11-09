import {
  bytesEqual,
  type DataEpoch,
  dataEpoch,
  fromBase64url,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
} from "@openlfcp/core";
import { ABILITY, activeDevice, hasAbility } from "@openlfcp/wire";
import {
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  loadIdentityDocument,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { identityWriterClass, principalOfRef, principalRefOf, resourceRef } from "./document.js";
import { hintAnswered } from "./hint-marks.js";
import { PackageLedger } from "./journal.js";
import { ChannelPool, IdentityRefused, IdentityUnavailable } from "./network.js";
import { reconcileDevices, type TargetReconciliation } from "./reconcile.js";
import { type IdentityFlowOptions, identityTarget, localIdentityResource } from "./resource.js";

/**
 * Key hints (IDENTITY-PROFILE-01 §7.1 step 3, §3 AI5; design 419 (a)): a
 * device that lacks the DEK of an epoch it is a reader of says so in its
 * own entry of the Identity Resource, `devices[p:<D>].missing_keys`, and a
 * managing device that reconciles re-seals those epochs even where its
 * ledger shows a sent package; the device clears its hint when the keys
 * arrive. Only the device itself writes its hint (AI5), and only a writer
 * of `I` can (a personal device with data/write, or the root; a pairing or
 * service device never, AI4). `resendKeys` is the managing side's "Re-send
 * keys" for any device, Read devices included.
 */

export type KeyHintsResult =
  /** The hint was written: the unit is accepted. */
  | { readonly kind: "written" }
  /** The hint already says this: nothing sent. */
  | { readonly kind: "unchanged" }
  /** This installation does not write `I` (a pairing or service device, or no data/write there). */
  | { readonly kind: "not-a-writer" }
  /** The document port has no `keyHints` capability: nothing is written. */
  | { readonly kind: "unsupported" }
  /**
   * Not written now: the coordinator was not reached or refused a read,
   * this device has no entry in `I` yet, or it does not hold the DEK of
   * `I`'s current epoch (then a managing device's resendKeys helps).
   */
  | { readonly kind: "unavailable"; readonly reason: string }
  /** `I` is forked (§9.7). */
  | { readonly kind: "conflict" }
  /** The coordinator refused the unit. */
  | { readonly kind: "refused"; readonly code: string };

const sortedUnique = (epochs: readonly (bigint | number)[]): bigint[] =>
  [...new Set(epochs.map((e) => BigInt(e)))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

const sameEpochs = (a: readonly bigint[], b: readonly bigint[]) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * Makes this installation's `missing_keys` hint in its Identity Resource
 * equal to `missing`: the epochs it lacks, by Resource. A Resource absent
 * from `missing` (or with no epochs) is removed from the hint; an empty map
 * clears it. Writes only the hint field (the port's `keyHints`), one unit,
 * and nothing when the hint already says this. Not journaled: the hint is a
 * statement of the current state, written again by the next call; the
 * actor sequence is reserved durably, so a unit lost on its way only leaves
 * a gap (W §26.2). A unit refused as stale after a rotation of `I` is built
 * again once on the current epoch (W §19.1).
 */
export async function setKeyHints(
  o: IdentityFlowOptions & {
    readonly missing: ReadonlyMap<ResourceId, readonly DataEpoch[]>;
  },
): Promise<KeyHintsResult> {
  // No Identity Resource here (a service device, an installation that never paired): no
  // writer of one. One recorded without its stored chain: later.
  if (o.identity === undefined && (await localIdentityResource(o.storage)) === undefined)
    return { kind: "not-a-writer" };
  let target: Awaited<ReturnType<typeof identityTarget>>;
  try {
    target = await identityTarget(o);
  } catch (e) {
    return { kind: "unavailable", reason: (e as Error).message };
  }
  const me = o.installation.signer;
  const myId = me.descriptor.principalId;
  const pool = new ChannelPool(o.network);
  const wanted = new Map<string, bigint[]>();
  for (const [R, epochs] of o.missing) {
    const list = sortedUnique(epochs);
    if (list.length > 0) wanted.set(resourceRef(R), list);
  }
  try {
    const channel = await pool.get(me, target.url);
    for (let attempt = 0; ; attempt++) {
      const I = await syncChain(o.storage, channel, target.resource);
      const root = genesisOwner(I);
      const writer = identityWriterClass(I.state, root, myId);
      if (
        (writer !== "root" && writer !== "personal") ||
        !hasAbility(I.state, myId, ABILITY.DATA_WRITE)
      )
        return { kind: "not-a-writer" };
      const doc = o.document(target.resource, root);
      if (doc.keyHints === undefined) return { kind: "unsupported" };
      const deks = await fetchDeks(o.storage, o.secrets, channel, I, o.installation);
      if (!deks.has(String(I.state.epoch.epoch)))
        return {
          kind: "unavailable",
          reason: "this device does not hold the current key of its device list",
        };
      const load = await loadIdentityDocument({ channel, chain: I, deks, doc });
      const entry = doc.devices().get(principalRefOf(myId));
      if (entry === undefined)
        return { kind: "unavailable", reason: "this device has no entry in its device list yet" };
      const current = new Map<string, bigint[]>();
      for (const [ref, epochs] of Object.entries(entry.missing_keys ?? {}))
        current.set(ref, sortedUnique(epochs));
      const hints = new Map<string, readonly bigint[] | null>();
      for (const [ref, list] of wanted)
        if (!sameEpochs(current.get(ref) ?? [], list)) hints.set(ref, list);
      for (const ref of current.keys()) if (!wanted.has(ref)) hints.set(ref, null);
      if (hints.size === 0) return { kind: "unchanged" };
      const bytes = await sealIdentityUnit({
        storage: o.storage,
        chain: I,
        deks,
        signer: me,
        doc,
        latest: load.latest,
        intents: [],
        hints,
      });
      const answer = await channel.putDataUnit(target.resource, bytes);
      if (answer.kind === "ack") return { kind: "written" };
      if (answer.code === "STALE_DATA_EPOCH" && attempt === 0) continue;
      return { kind: "refused", code: answer.code };
    }
  } catch (e) {
    if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
      return { kind: "unavailable", reason: e.message };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }
}

/**
 * The key hints in this installation's Identity Resource: for each active
 * device of the root (the root included) whose entry has a valid
 * `missing_keys`, the epochs it lacks by Resource (§4 rule 2: the union of
 * concurrent values). A managing device reads it to decide that
 * reconciliation is due (it re-seals hinted epochs, §7.1 step 3). Throws
 * IdentityUnavailable, IdentityRefused or IdentityConflict as syncChain.
 */
export async function keyHints(
  o: IdentityFlowOptions,
  options: {
    /**
     * Only the hints this installation has not answered yet: changed since
     * its reconciliation last re-sealed them, or answered more than
     * HINT_RESEND_BACKOFF_MS ago (0.5.2, review 419 P2-1). What makes a
     * managing device's reconciliation due.
     */
    readonly unanswered?: boolean;
  } = {},
): Promise<ReadonlyMap<PrincipalId, ReadonlyMap<ResourceId, readonly DataEpoch[]>>> {
  const target = await identityTarget(o);
  const pool = new ChannelPool(o.network);
  try {
    const channel = await pool.get(o.installation.signer, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    const root = genesisOwner(I);
    const doc = o.document(target.resource, root);
    const deks = await fetchDeks(o.storage, o.secrets, channel, I, o.installation);
    await loadIdentityDocument({ channel, chain: I, deks, doc });
    const out = new Map<PrincipalId, Map<ResourceId, DataEpoch[]>>();
    for (const [key, entry] of doc.devices()) {
      const D = principalOfRef(key);
      if (D === undefined || entry.missing_keys === undefined) continue;
      if (!bytesEqual(D, root) && activeDevice(I.state, D) === undefined) continue;
      const byResource = new Map<ResourceId, DataEpoch[]>();
      for (const [ref, epochs] of Object.entries(entry.missing_keys)) {
        let R: ResourceId;
        try {
          R = resourceId(fromBase64url(ref));
        } catch {
          continue;
        }
        const list = sortedUnique(epochs).map((e) => dataEpoch(e));
        if (list.length === 0) continue;
        if (options.unanswered === true && (await hintAnswered(o.storage, R, D, list, o.now())))
          continue;
        byResource.set(R, list);
      }
      if (byResource.size > 0) out.set(principalId(D), byResource);
    }
    return out;
  } finally {
    pool.closeAll();
  }
}

/** What resendKeys did: the ledger entries it forgot, and the reconciliation it ran. */
export interface ResendKeysResult {
  readonly cleared: number;
  readonly operation: string;
  readonly targets: readonly TargetReconciliation[];
}

/**
 * "Re-send keys" (IDENTITY-PROFILE-01 §7.1 step 3): forgets every package
 * this managing installation's ledger records as sent to `device` (in
 * `resource` only, or everywhere), then reconciles (the same targets, no
 * rotation), so every epoch it holds is sealed to that device again. For
 * any device of the root, a Read device that cannot write a hint included.
 */
export async function resendKeys(
  o: IdentityFlowOptions & {
    readonly device: PrincipalId;
    readonly resource?: ResourceId;
  },
): Promise<ResendKeysResult> {
  const cleared = await new PackageLedger(o.storage).clear(o.device, o.resource);
  const r = await reconcileDevices({
    ...o,
    rotate: false,
    ...(o.resource === undefined ? {} : { only: [o.resource] }),
  });
  return { cleared, operation: r.operation, targets: r.targets };
}
