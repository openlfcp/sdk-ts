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
  DEVICE_KIND,
  deviceFingerprint,
  revocationOf,
  type Signer,
  signControlRecord,
} from "@openlfcp/wire";
import {
  deliverKeys,
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  type KeyDelivery,
  loadIdentityDocument,
  readersAt,
  runControlPhase,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { mayManageDevices } from "./devices.js";
import { type IdentityIntent, principalRefOf, resourceRef } from "./document.js";
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
import { type RotationOutcome, resumeRotations } from "./rotation.js";

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
 * §7.1 steps 1 and 2 for one target, in their normative order. For the
 * target `I` itself both steps are vacuous. Registrations are planned on
 * the target's state as the revocations leave it (a device whose issuer
 * `I` revoked is never registered before the cascade reaches the target).
 */
export function planReconciliation(
  identity: LinearChain,
  target: LinearChain,
): readonly ReconcileStep[] {
  if (bytesEqual(identity.state.resourceId, target.state.resourceId)) return [];
  const R = genesisOwner(identity);
  const I = identity.state;
  const X = target.state;
  const steps: ReconcileStep[] = [];
  // Step 1: every revoked pair of I not revoked in X, in I's chain order.
  const revokedInX = (d: PrincipalId) => revocationOf(X, R, d) !== undefined;
  const revokedNow = new Set<string>();
  for (const r of identity.records) {
    if (r.body.type !== "DEVICE_REVOKE" || !bytesEqual(r.body.root, R)) continue;
    const d = r.body.device;
    if (revokedInX(d) || revokedNow.has(toHex(d))) continue;
    revokedNow.add(toHex(d));
    steps.push({
      kind: "revoke",
      root: R,
      device: d,
      reason: r.body.reason === 3n ? 0n : r.body.reason,
    });
  }
  const revokedAfter = (d: PrincipalId) => revokedInX(d) || revokedNow.has(toHex(d));
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
): Promise<{ readonly operation: string; readonly targets: readonly TargetReconciliation[] }> {
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
  let open = false;
  try {
    // A rotation an earlier run committed but did not adopt is finished first (§9.1).
    await resumeRotations({ ...o, pool });
    const channel = await pool.get(me, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    const R = genesisOwner(I);
    if (!mayManageDevices(I.state, me.descriptor.principalId, R))
      return {
        operation,
        targets: [{ resource: target.resource, status: "not-authorized", steps: [] }],
      };
    const doc = o.document(target.resource, R);
    const deksI = await fetchDeks(o.storage, o.secrets, channel, I, o.installation);
    const load = await loadIdentityDocument({ channel, chain: I, deks: deksI, doc });
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

    // Step 4: display data for devices in I's chain without a valid entry (labels default to the fingerprint).
    const intents: IdentityIntent[] = [];
    for (const [hex, d] of I.state.devices) {
      if (!bytesEqual(d.root, R) || d.chain === null || d.kind === DEVICE_KIND.PAIRING) continue;
      const key = principalRefOf(principalId(fromHex(hex)));
      if (doc.devices().has(key)) continue;
      intents.push({
        intent: "device.put",
        key,
        entry: {
          label: deviceFingerprint(principalId(fromHex(hex))),
          kind: d.kind === DEVICE_KIND.SERVICE ? 1 : 0,
        },
      });
    }
    if (intents.length > 0 && doc.initialized())
      await runUnitPhase(channel, journal, operation, {
        id: "display",
        resource: target.resource,
        build: () =>
          sealIdentityUnit({
            storage: o.storage,
            chain: I,
            deks: deksI,
            signer: me,
            doc,
            latest: load.latest,
            intents,
          }),
      });
    open = out.some(
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
  return { operation, targets: Object.freeze(out) };
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
  // Step 3: every reader of the target whose root is R (pairing devices of I included), by the ledger.
  const deks = await fetchDeks(o.storage, o.secrets, channel, chain, o.installation);
  const recipients = readersAt(chain.state).filter((r) =>
    bytesEqual(actsFor(chain.state, r.principalId), R),
  );
  const keys = await deliverKeys({ channel, ledger, chain, sender: me, recipients, deks, resend });
  const rotation =
    o.rotate === false
      ? undefined
      : await rotateIfExposed({ ...o, channel, operation, resource: X });
  return {
    resource: X,
    status: manages ? "done" : "not-authorized",
    steps: Object.freeze(steps),
    keys,
    ...(rotation === undefined ? {} : { rotation }),
  };
}
