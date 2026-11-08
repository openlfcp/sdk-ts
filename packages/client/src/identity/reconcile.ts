import {
  bytesEqual,
  fromBase64url,
  fromHex,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import {
  activeDevice,
  actsFor,
  type CertificateChain,
  type ControlState,
  DEVICE_KIND,
  type DeviceBinding,
  deviceFingerprint,
  isBound,
  type PrincipalDescriptor,
  revocationOf,
  type Signer,
  signControlRecord,
} from "@openlfcp/wire";
import {
  type DocumentWrite,
  deliverKeys,
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  type KeyDelivery,
  loadIdentityDocument,
  readersAt,
  retiredFlagMissing,
  revokedByIdentity,
  runControlPhase,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { mayManageDevices } from "./devices.js";
import {
  type DeviceEntryValue,
  type IdentityDocumentPort,
  type IdentityIntent,
  principalRefOf,
  resourceRef,
} from "./document.js";
import { newOperationId, OperationJournal, PackageLedger } from "./journal.js";
import {
  ChannelPool,
  IDENTITY_EXTENSION,
  type IdentityChannel,
  IdentityRefused,
  IdentityUnavailable,
} from "./network.js";
import { classifyRegister, classifyRevoke, type LinearChain, type PhaseState } from "./phases.js";
import { type IdentityFlowOptions, identityTarget } from "./resource.js";
import { rotateIfExposed } from "./revocation.js";
import { checkFlowProfiles, type RotationOutcome, resumeRotations } from "./rotation.js";

/**
 * Reconciliation (IDENTITY-PROFILE-01 §7.1): carries the Identity
 * Resource's device records into every roster Resource and keys every
 * device of the root, idempotently. Targets are `{I} ∪ roster`; the input
 * is `I`'s Control state, never the document. Revocations first, then
 * registrations, then keys (by the ledger, unconditionally), then display
 * data. Suspended while `I` or the target is forked (§9.7).
 */

/** One record reconciliation proposes on a target. */
export type ReconcileStep =
  | {
      readonly kind: "revoke";
      readonly root: PrincipalId;
      readonly device: PrincipalId;
      /** Reason 3 is propagated as 0; the approval travels nowhere. */
      readonly reason: bigint;
    }
  | {
      readonly kind: "register";
      readonly root: PrincipalId;
      readonly device: PrincipalId;
      /** `I`'s chain for the device. */
      readonly chain: CertificateChain;
    };

/**
 * §7.1 step 1: whether the revocation of `device` in `I` is relevant in the
 * target `X`. It is when the device is bound in `X` (as a leaf or an
 * intermediate, W §17.4 rule 9), or when it could become registered in `X`
 * or issue a chain there: bound in `I` with kind 0, or with kind 1 and `X`
 * in its scope, or not bound in `I` at all (its kind is unknown). A pairing
 * device, or a service device whose scope does not list `X`, that is not
 * bound in `X` can never act there (W §7.3 c3, c6; N8): its revocation
 * would protect nothing and would take one of the 64 unbound pairs of the
 * root that W §17.5 rule 5 allows in `X` and never frees.
 *
 * `binding` is the device's binding in `I` (undefined when unbound there).
 */
export function revocationRelevant(
  binding: Pick<DeviceBinding, "kind" | "scope"> | undefined,
  target: ControlState,
  device: PrincipalId,
): boolean {
  if (isBound(target, device)) return true;
  if (binding === undefined || binding.kind === DEVICE_KIND.PERSONAL) return true;
  return (
    binding.kind === DEVICE_KIND.SERVICE &&
    binding.scope.some((s) => bytesEqual(s, target.resourceId))
  );
}

/**
 * §7.1 step 1 for one target: the revocations of `I` to propose on `X`
 * (the pairs of `I`'s `revoked` not in `X`'s that are relevant there, those
 * whose device is bound in `X` first, each group in `I`'s chain order), and
 * the devices whose revocation is not relevant in `X` and is not
 * propagated. Empty for the target `I` itself.
 */
export function planRevocations(
  identity: LinearChain,
  target: LinearChain,
): {
  readonly propose: readonly Extract<ReconcileStep, { kind: "revoke" }>[];
  readonly notRelevant: readonly PrincipalId[];
} {
  if (bytesEqual(identity.state.resourceId, target.state.resourceId))
    return { propose: [], notRelevant: [] };
  const R = genesisOwner(identity);
  const I = identity.state;
  const X = target.state;
  const bound: Extract<ReconcileStep, { kind: "revoke" }>[] = [];
  const unbound: Extract<ReconcileStep, { kind: "revoke" }>[] = [];
  const notRelevant: PrincipalId[] = [];
  const seen = new Set<string>();
  for (const r of identity.records) {
    if (r.body.type !== "DEVICE_REVOKE" || !bytesEqual(r.body.root, R)) continue;
    const d = r.body.device;
    if (revocationOf(X, R, d) !== undefined || seen.has(toHex(d))) continue;
    seen.add(toHex(d));
    if (!revocationRelevant(I.devices.get(toHex(d)), X, d)) {
      notRelevant.push(d);
      continue;
    }
    (isBound(X, d) ? bound : unbound).push({
      kind: "revoke",
      root: R,
      device: d,
      reason: r.body.reason === 3n ? 0n : r.body.reason,
    });
  }
  return Object.freeze({
    propose: Object.freeze([...bound, ...unbound]),
    notRelevant: Object.freeze(notRelevant),
  });
}

/**
 * §7.1 steps 1 and 2 for one target, in their normative order. For the
 * target `I` itself both steps are vacuous. Registrations are planned on
 * the target's state as the revocations leave it, and every pair of `I`'s
 * `revoked` counts as revoked in `X` whether its propagation succeeds or
 * not (an unpropagated pair, refused by W §17.5 rule 5, or a pair that is
 * not relevant): no device whose issuer `I` has revoked is ever registered.
 */
export function planReconciliation(
  identity: LinearChain,
  target: LinearChain,
): readonly ReconcileStep[] {
  if (bytesEqual(identity.state.resourceId, target.state.resourceId)) return [];
  const R = genesisOwner(identity);
  const I = identity.state;
  const X = target.state;
  // Step 1: the relevant revocations of I, bound in X first.
  const steps: ReconcileStep[] = [...planRevocations(identity, target).propose];
  const revokedAfter = (d: PrincipalId) =>
    revocationOf(X, R, d) !== undefined || revocationOf(I, R, d) !== undefined;
  // Step 2: registrations, in I's binding order.
  for (const [hex, d] of I.devices) {
    if (!bytesEqual(d.root, R) || d.chain === null || d.leafId === null) continue;
    const D = principalId(fromHex(hex));
    if (revokedAfter(D) || d.chain.issuers.some((e) => revokedAfter(e))) continue;
    const x = X.devices.get(hex);
    if (d.kind === DEVICE_KIND.PERSONAL) {
      if (activeDevice(I, D) === undefined) continue;
      if (x?.registered && x.leafId !== null && bytesEqual(x.leafId, d.leafId)) continue;
      steps.push({ kind: "register", root: R, device: D, chain: d.chain });
    } else if (d.kind === DEVICE_KIND.SERVICE) {
      if (revocationOf(I, R, D) !== undefined) continue;
      if (!d.scope.some((s) => bytesEqual(s, X.resourceId))) continue;
      // Absent from X, or bound there with another leaf and suspended by the cascade:
      // I's chain re-certifies it (§7.1 step 2, third item; F09). Kind, mask and
      // scope are immutable (N8): a binding with others is left alone.
      if (x !== undefined) {
        if (x.leafId !== null && bytesEqual(x.leafId, d.leafId)) continue;
        if (activeDevice(X, D) !== undefined || !sameBinding(x, d)) continue;
      }
      steps.push({ kind: "register", root: R, device: D, chain: d.chain });
    }
  }
  return Object.freeze(steps);
}

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((v) => b.includes(v));

/** N8: the same kind, mask and scope. */
const sameBinding = (
  a: { kind: number; mask: readonly bigint[]; scope: readonly Uint8Array[] },
  b: { kind: number; mask: readonly bigint[]; scope: readonly Uint8Array[] },
) =>
  a.kind === b.kind &&
  sameSet(a.mask.map(String), b.mask.map(String)) &&
  sameSet(a.scope.map(toHex), b.scope.map(toHex));

/** The record of a step on the target's head, signed by the reconciler. */
export function reconcileRecord(
  target: LinearChain,
  step: ReconcileStep,
  signer: Signer,
): Uint8Array {
  const header = {
    resourceId: target.state.resourceId,
    controlSeq: target.state.seq + 1n,
    prevControlId: target.state.head,
  };
  return step.kind === "revoke"
    ? signControlRecord(
        header,
        { type: "DEVICE_REVOKE", root: step.root, device: step.device, reason: step.reason },
        signer,
      ).bytes
    : signControlRecord(
        header,
        { type: "DEVICE_GRANT", root: step.root, chain: step.chain },
        signer,
      ).bytes;
}

export interface TargetReconciliation {
  readonly resource: ResourceId;
  readonly status: "done" | "unsupported" | "unreachable" | "conflict" | "not-authorized";
  /** Each proposed step and its §9.2 phase state. */
  readonly steps: readonly {
    readonly step: ReconcileStep;
    readonly state: PhaseState | "refused";
  }[];
  /**
   * §7.1 step 1: devices whose revocation in `I` the target refused (the
   * limit of W §17.5 rule 5, or the reconciler's authority there), to
   * report to the human with the Resource. Each stays unpropagated: this
   * run registered no device through it and sealed nothing to it, and a
   * later run proposes it again. Empty when every relevant pair reached the
   * target.
   */
  readonly unpropagated?: readonly PrincipalId[];
  readonly keys?: KeyDelivery;
  readonly rotation?: RotationOutcome;
}

/**
 * §7.1: reconciles `{I} ∪ roster` from this managing installation (the
 * root, or an active personal device with `12`). Proposals the target
 * refuses are reported, not repeated as such; a second run proposes
 * nothing. When the target holds an exposing revocation since its epoch
 * opened and this installation is the rotator, it rotates (§8.4).
 */
export async function reconcileDevices(
  o: IdentityFlowOptions & {
    /** Only these targets (default: `I` and the whole roster). */
    readonly only?: readonly ResourceId[];
    /** Apply the rotation policy of §8.4 to each target (default true). */
    readonly rotate?: boolean;
  },
): Promise<{
  readonly operation: string;
  readonly targets: readonly TargetReconciliation[];
  /**
   * Step 4's unit of display data in `I`: not needed (`none`), written,
   * found written by another manager when built (`complete`, nothing sent),
   * or refused with `code`. A refused unit leaves this operation open.
   * Reconciliation has no resume: a later call is a new operation that
   * proposes the entries still missing then, and does not close this one.
   */
  readonly document: DocumentWrite;
}> {
  checkFlowProfiles(o);
  const target = await identityTarget(o);
  const me = o.installation.signer;
  const journal = new OperationJournal(o.storage);
  const ledger = new PackageLedger(o.storage);
  const operation = newOperationId("reconcile", secureRandom(8));
  await journal.begin({
    id: operation,
    kind: "reconcile",
    createdAt: o.now(),
    intent: { identity: toHex(target.resource) },
  });
  const pool = new ChannelPool(o.network);
  const out: TargetReconciliation[] = [];
  let document: DocumentWrite = { state: "none" };
  let open = false;
  try {
    const channel = await pool.get(me, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    // A rotation an earlier run committed but did not adopt is finished first (§9.1). It
    // seals nothing to a device I has revoked (§7.1 step 1).
    await resumeRotations({ ...o, pool, identityChain: I });
    const R = genesisOwner(I);
    if (!mayManageDevices(I.state, me.descriptor.principalId, R))
      return {
        operation,
        targets: [{ resource: target.resource, status: "not-authorized", steps: [] }],
        document,
      };
    const doc = o.document(target.resource, R);
    const deksI = await fetchDeks(o.storage, o.secrets, channel, I, o.installation);
    await loadIdentityDocument({ channel, chain: I, deks: deksI, doc });
    const hints = (resource: ResourceId) => {
      const ref = resourceRef(resource);
      const m = new Map<string, Set<string>>();
      for (const [key, e] of doc.devices()) {
        const epochs = e.missing_keys?.[ref];
        const d = key.startsWith("p:") ? toHex(fromBase64url(key.slice(2))) : undefined;
        if (epochs !== undefined && d !== undefined) m.set(d, new Set(epochs.map(String)));
      }
      return m;
    };
    const targets = [
      { resource: target.resource, url: target.url },
      ...[...doc.roster()]
        .filter(([, e]) => e.archived !== true)
        .map(([ref, e]) => ({ resource: resourceId(fromBase64url(ref)), url: e.coordinator }))
        .filter((t) => !bytesEqual(t.resource, target.resource)),
    ].filter((t) => o.only === undefined || o.only.some((r) => bytesEqual(r, t.resource)));

    for (const t of targets) {
      try {
        const c = await pool.get(me, t.url);
        if (!c.extensions.includes(IDENTITY_EXTENSION)) {
          out.push({ resource: t.resource, status: "unsupported", steps: [] });
          continue;
        }
        out.push(
          await reconcileTarget(o, c, journal, ledger, operation, I, t.resource, hints(t.resource)),
        );
      } catch (e) {
        if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
          out.push({ resource: t.resource, status: "unreachable", steps: [] });
        else if (e instanceof IdentityConflict)
          out.push({ resource: t.resource, status: "conflict", steps: [] });
        else throw e;
      }
    }

    // Step 4: display data for the leaf-bound personal and service devices of I without a valid
    // entry (labels default to the fingerprint), and the flag of a retired entry.
    if (!nothingToWrite(displayPlan(I, doc, R)) && doc.initialized()) {
      // Built on the current state of I: a rotation of I by this run, or by
      // anyone, makes an earlier unit stale (W §19.1), and it is written again.
      document = await runUnitPhase(channel, journal, operation, {
        id: "display",
        resource: target.resource,
        rebuildOn: ["STALE_DATA_EPOCH"],
        build: async () => {
          const now = await syncChain(o.storage, channel, target.resource);
          const deks = await fetchDeks(o.storage, o.secrets, channel, now, o.installation);
          const fresh = o.document(target.resource, R);
          const loaded = await loadIdentityDocument({ channel, chain: now, deks, doc: fresh });
          // Another manager may have written the entries since the first read (§7.1).
          const plan = displayPlan(now, fresh, R);
          if (nothingToWrite(plan)) return null;
          return sealIdentityUnit({
            storage: o.storage,
            chain: now,
            deks,
            signer: me,
            doc: fresh,
            latest: loaded.latest,
            intents: plan.intents,
            retire: plan.retire,
          });
        },
      });
    }
    open =
      document.state === "refused" ||
      out.some(
        (t) =>
          t.status === "unreachable" ||
          t.status === "conflict" ||
          t.rotation?.status === "unreachable" ||
          t.rotation?.status === "awaiting-key-holder",
      );
    await journal.setStatus(operation, open ? "open" : "done");
  } catch (e) {
    if (e instanceof IdentityConflict)
      out.push({ resource: target.resource, status: "conflict", steps: [] });
    else if (e instanceof IdentityUnavailable)
      out.push({ resource: target.resource, status: "unreachable", steps: [] });
    else throw e;
  } finally {
    pool.closeAll();
  }
  return { operation, targets: Object.freeze(out), document };
}

/** §7.1 step 4's writes in `I`'s document: new entries, and the retired entries to flag. */
export interface DisplayPlan {
  readonly intents: readonly IdentityIntent[];
  /** Retired entries (PrincipalRefs) whose `revoked` is set to `true`, and nothing else of them. */
  readonly retire: readonly string[];
}

/**
 * §7.1 step 4: the display data reconciliation writes in `I`'s document,
 * from `I`'s Control state and the valid device entries (§4). For every
 * device of `R` of kind 0 or 1 bound in `I` as the leaf of an accepted
 * chain (an intermediate-only binding issues and does not act in `I`):
 * when it is not revoked in `I` and has no valid entry, an entry labelled
 * with its fingerprint (§5.2); when it is revoked in `I` and some value of
 * its entry's `revoked` (a retired entry) is not `true`, or the field is
 * absent, that flag alone. `revokedValues` gives every concurrent value
 * of the flag (IdentityDocumentPort.retirement); without it the entry's
 * one shown value is read. No entry is created for a revoked device,
 * nothing is written for a pairing device, nothing is relabelled or
 * deleted, and a second run on the same states plans nothing.
 */
export function planDisplayData(
  identity: ControlState,
  entries: ReadonlyMap<string, DeviceEntryValue>,
  root: PrincipalId,
  revokedValues?: (key: string) => readonly unknown[],
): DisplayPlan {
  const intents: IdentityIntent[] = [];
  const retire: string[] = [];
  for (const [hex, d] of identity.devices) {
    if (!bytesEqual(d.root, root) || d.chain === null) continue;
    if (d.kind !== DEVICE_KIND.PERSONAL && d.kind !== DEVICE_KIND.SERVICE) continue;
    const D = principalId(fromHex(hex));
    const key = principalRefOf(D);
    if (revocationOf(identity, root, D) !== undefined) {
      if (retiredFlagMissing(entries, key, revokedValues)) retire.push(key);
      continue;
    }
    if (entries.has(key)) continue;
    intents.push({
      intent: "device.put",
      key,
      entry: {
        label: deviceFingerprint(D),
        kind: d.kind === DEVICE_KIND.SERVICE ? 1 : 0,
      },
    });
  }
  return Object.freeze({ intents: Object.freeze(intents), retire: Object.freeze(retire) });
}

const displayPlan = (
  I: LinearChain,
  doc: Pick<IdentityDocumentPort, "devices" | "retirement">,
  R: PrincipalId,
): DisplayPlan =>
  planDisplayData(
    I.state,
    doc.devices(),
    R,
    doc.retirement === undefined ? undefined : (key) => doc.retirement?.revokedValues(key) ?? [],
  );

const nothingToWrite = (p: DisplayPlan) => p.intents.length === 0 && p.retire.length === 0;

/**
 * §7.1 step 3: the devices of `R` reconciliation seals the target's keys
 * to: every reader of the target whose root is `R` (pairing devices of `I`
 * included, in `I`), except a device revoked in `I` and a device whose
 * current chain in the target passes through a device revoked in `I` (an
 * unpropagated pair of step 1, which the target still counts as active).
 */
export function keyRecipients(
  identity: LinearChain,
  target: LinearChain,
): readonly PrincipalDescriptor[] {
  const R = genesisOwner(identity);
  return Object.freeze(
    readersAt(target.state).filter(
      (r) =>
        bytesEqual(actsFor(target.state, r.principalId), R) &&
        !revokedByIdentity(identity, target.state, r.principalId),
    ),
  );
}

async function reconcileTarget(
  o: IdentityFlowOptions & { readonly rotate?: boolean },
  channel: IdentityChannel,
  journal: OperationJournal,
  ledger: PackageLedger,
  operation: string,
  I: LinearChain,
  X: ResourceId,
  resend: ReadonlyMap<string, ReadonlySet<string>>,
): Promise<TargetReconciliation> {
  const me = o.installation.signer;
  const R = genesisOwner(I);
  let chain = await syncChain(o.storage, channel, X);
  const steps: { step: ReconcileStep; state: PhaseState | "refused" }[] = [];
  const manages = mayManageDevices(chain.state, me.descriptor.principalId, R);
  if (manages)
    for (const step of planReconciliation(I, chain)) {
      const id = `${step.kind}:${toHex(X)}:${toHex(step.device)}`;
      const outcome = await runControlPhase(o.storage, channel, journal, operation, {
        id,
        kind: step.kind,
        resource: X,
        classify: (c, isOwn) =>
          step.kind === "revoke"
            ? classifyRevoke(c.state, step.root, step.device)
            : classifyRegister(c, { root: step.root, chain: step.chain, isOwnRecord: isOwn }),
        build: (c) => reconcileRecord(c, step, me),
      });
      steps.push({ step, state: outcome.state });
      chain = outcome.chain;
    }
  // §7.1 step 1: a refused revocation is reported and stays unpropagated.
  const unpropagated = steps
    .filter((s) => s.step.kind === "revoke" && s.state === "refused")
    .map((s) => s.step.device);
  // Step 3: every reader of the target whose root is R (pairing devices of I included), by the
  // ledger, except the devices I has revoked and those whose chain passes through one.
  const deks = await fetchDeks(o.storage, o.secrets, channel, chain, o.installation);
  const recipients = keyRecipients(I, chain);
  const keys = await deliverKeys({ channel, ledger, chain, sender: me, recipients, deks, resend });
  const rotation =
    o.rotate === false
      ? undefined
      : // §7.1 step 1: the new epoch is sealed to no device I has revoked, nor through one.
        await rotateIfExposed({ ...o, channel, operation, resource: X, identityChain: I });
  return {
    resource: X,
    status: manages ? "done" : "not-authorized",
    steps: Object.freeze(steps),
    ...(unpropagated.length === 0 ? {} : { unpropagated: Object.freeze(unpropagated) }),
    keys,
    ...(rotation === undefined ? {} : { rotation }),
  };
}
