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
  type ControlState,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import {
  genesisOwner,
  heldDeks,
  IdentityConflict,
  loadIdentityDocument,
  runControlPhase,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import { type FlowOptions, mayManageDevices } from "./devices.js";
import { principalRefOf } from "./document.js";
import { newOperationId, OperationJournal, phaseOf } from "./journal.js";
import {
  ChannelPool,
  IDENTITY_EXTENSION,
  type IdentityChannel,
  IdentityRefused,
  IdentityUnavailable,
} from "./network.js";
import { classifyRevoke, type LinearChain } from "./phases.js";
import { type IdentityFlowOptions, identityTarget } from "./resource.js";
import {
  exposingRevocationsSince,
  type RotationOutcome,
  rotateAfter,
  rotatorTest,
} from "./rotation.js";

/**
 * Revoking a device (IDENTITY-PROFILE-01 §8, decision I4) and the
 * automatic rotation policy (§8.4).
 */

/** What revoking `device` does to one Resource, computed on the post-state (§8.1). */
export interface ResourcePreview {
  readonly resource: ResourceId;
  readonly status:
    | "ok"
    | "already-revoked"
    | "not-authorized"
    | "unreachable"
    | "unsupported"
    | "conflict";
  /** Devices active before and suspended after, by the cascade (W §17.5). */
  readonly suspended: readonly PrincipalId[];
  /** Whether the revocation removes a reader (W §17.5). */
  readonly exposing: boolean;
  /** Whether this installation rotates afterwards (§8.1); else the Resource awaits rotation. */
  readonly rotator: boolean;
}

export interface RevocationPreview {
  readonly device: PrincipalId;
  /** The revoker's own chain passes through the device: re-certify first (§8.1). */
  readonly selfDependent: boolean;
  readonly resources: readonly ResourcePreview[];
}

const toKeep = (state: ControlState, root: PrincipalId) =>
  [...state.devices.entries()]
    .filter(([, d]) => bytesEqual(d.root, root))
    .map(([hex]) => principalId(fromHex(hex)))
    .filter((p) => activeDevice(state, p) !== undefined);

/** The DEVICE_REVOKE on the chain's head, if this installation may issue it there. */
function revokeOn(
  chain: LinearChain,
  o: FlowOptions,
  root: PrincipalId,
  device: PrincipalId,
  reason: bigint,
): { bytes: Uint8Array; after: LinearChain } | undefined {
  const signed = signControlRecord(
    {
      resourceId: chain.state.resourceId,
      controlSeq: chain.state.seq + 1n,
      prevControlId: chain.state.head,
    },
    { type: "DEVICE_REVOKE", root, device, reason },
    o.installation.signer,
  );
  const after = validateControlChain([...chain.records.map((r) => r.signed.bytes), signed.bytes]);
  return after.kind === "linear" ? { bytes: signed.bytes, after } : undefined;
}

function previewOn(
  chain: LinearChain,
  o: FlowOptions,
  root: PrincipalId,
  device: PrincipalId,
  reason: bigint,
): ResourcePreview {
  const R = chain.state.resourceId;
  const empty = { suspended: [], exposing: false, rotator: false };
  if (chain.state.revoked.has(`${toHex(root)}:${toHex(device)}`))
    return { resource: R, status: "already-revoked", ...empty };
  const sim = revokeOn(chain, o, root, device, reason);
  if (sim === undefined) return { resource: R, status: "not-authorized", ...empty };
  const before = new Set(toKeep(chain.state, root).map(toHex));
  const after = new Set(toKeep(sim.after.state, root).map(toHex));
  const suspended = [...before]
    .filter((p) => !after.has(p) && p !== toHex(device))
    .map((p) => principalId(fromHex(p)));
  const exposing = exposingRevocationsSince(sim.after).some((e) => e.seq === sim.after.state.seq);
  return {
    resource: R,
    status: "ok",
    suspended,
    exposing,
    rotator: rotatorTest(sim.after.state, o.installation.signer.descriptor.principalId).rotator,
  };
}

/** Roster targets of the Identity Resource (not archived), I excluded. */
async function rosterTargets(
  o: IdentityFlowOptions,
  channel: IdentityChannel,
  chain: LinearChain,
): Promise<{ resource: ResourceId; url: string }[]> {
  const doc = o.document(chain.state.resourceId, genesisOwner(chain));
  await loadIdentityDocument({ channel, chain, deks: await heldDeks(o.secrets, chain), doc });
  return [...doc.roster()]
    .filter(([, e]) => e.archived !== true)
    .map(([ref, e]) => ({ resource: resourceId(fromBase64url(ref)), url: e.coordinator }))
    .filter((t) => !bytesEqual(t.resource, chain.state.resourceId));
}

/**
 * §8.1: the post-state of revoking `device` in `I` and every reachable
 * roster Resource: suspended devices, exposure, whether this installation
 * stays active and who rotates.
 */
export async function previewRevocation(
  o: IdentityFlowOptions & { readonly device: PrincipalId; readonly reason?: bigint },
): Promise<RevocationPreview> {
  const target = await identityTarget(o);
  const pool = new ChannelPool(o.network);
  const me = o.installation.signer.descriptor.principalId;
  const reason = o.reason ?? 1n;
  try {
    const channel = await pool.get(o.installation.signer, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    const R = genesisOwner(I);
    const mine = activeDevice(I.state, me);
    const selfDependent =
      !bytesEqual(me, o.device) &&
      mine !== undefined &&
      mine.issuers.some((e) => bytesEqual(e, o.device));
    const resources: ResourcePreview[] = [previewOn(I, o, R, o.device, reason)];
    for (const t of await rosterTargets(o, channel, I)) {
      const empty = { suspended: [], exposing: false, rotator: false };
      try {
        const c = await pool.get(o.installation.signer, t.url);
        if (!c.extensions.includes(IDENTITY_EXTENSION)) {
          resources.push({ resource: t.resource, status: "unsupported", ...empty });
          continue;
        }
        resources.push(
          previewOn(await syncChain(o.storage, c, t.resource), o, R, o.device, reason),
        );
      } catch (e) {
        if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
          resources.push({ resource: t.resource, status: "unreachable", ...empty });
        else if (e instanceof IdentityConflict)
          resources.push({ resource: t.resource, status: "conflict", ...empty });
        else throw e;
      }
    }
    return { device: o.device, selfDependent, resources };
  } finally {
    pool.closeAll();
  }
}

/** One Resource's part of a revocation. */
export interface RevocationResult {
  readonly resource: ResourceId;
  readonly revoke:
    | "revoked"
    | "complete"
    | "superseded"
    | "not-authorized"
    | "refused"
    | "unreachable"
    | "unsupported"
    | "conflict";
  readonly rotation?: RotationOutcome;
}

export type RevokeDeviceResult =
  | {
      readonly kind: "revoked";
      readonly operation: string;
      readonly results: readonly RevocationResult[];
    }
  /** The revoker's chain passes through the device: obtain a fresh chain first (§8.1). */
  | { readonly kind: "self-dependent" }
  /** Only the root or a managing device revokes devices (§8). */
  | { readonly kind: "not-authorized" }
  /** The pair was consumed by a pairing approval (§9.2 Revoke: superseded). */
  | { readonly kind: "superseded"; readonly operation: string }
  /** Revocation needs the Identity Resource's coordinator: an offline "Remove device…" is refused (§8.5). */
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string }
  | { readonly kind: "conflict" };

class NotAuthorized extends Error {}

/**
 * §8.2–§8.5: `DEVICE_REVOKE {R, D, r}` in `I`, then in every roster
 * Resource where this installation may act, each followed by the rotation
 * when the revocation is exposing there and this installation is the
 * rotator (else `awaiting-rotation`). A self-retiring device (`D` is this
 * installation, reason 0) commits the revocations only. Every phase is
 * journaled and classified by §9.2: a revocation by another hand with
 * another reason is `complete` and the rotation test still runs.
 */
export async function revokeDevice(
  o: IdentityFlowOptions & {
    readonly device: PrincipalId;
    /** 0 retired, 1 lost, 2 compromised. */
    readonly reason: 0n | 1n | 2n;
    /** Resume this operation. */
    readonly operation?: string;
  },
): Promise<RevokeDeviceResult> {
  const target = await identityTarget(o);
  const me = o.installation.signer.descriptor.principalId;
  const selfRetire = bytesEqual(me, o.device);
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  const operation = o.operation ?? newOperationId("revoke-device", secureRandom(8));
  try {
    const channel = await pool.get(o.installation.signer, target.url);
    const I = await syncChain(o.storage, channel, target.resource);
    const R = genesisOwner(I);
    if (!selfRetire && !mayManageDevices(I.state, me, R)) return { kind: "not-authorized" };
    const mine = activeDevice(I.state, me);
    if (!selfRetire && mine !== undefined && mine.issuers.some((e) => bytesEqual(e, o.device)))
      return { kind: "self-dependent" };
    if ((await journal.get(operation)) === undefined)
      await journal.begin({
        id: operation,
        kind: "revoke-device",
        createdAt: o.now(),
        intent: {
          identity: toHex(target.resource),
          device: toHex(o.device),
          root: toHex(R),
          reason: String(o.reason),
        },
      });
    const results: RevocationResult[] = [];
    const one = async (c: IdentityChannel, X: ResourceId): Promise<RevocationResult> => {
      let outcome: Awaited<ReturnType<typeof runControlPhase>>;
      try {
        outcome = await runControlPhase(o.storage, c, journal, operation, {
          id: `revoke:${toHex(X)}`,
          kind: "revoke",
          resource: X,
          classify: (chain) => classifyRevoke(chain.state, R, o.device),
          build: (chain) => {
            const sim = revokeOn(chain, o, R, o.device, o.reason);
            if (sim === undefined) throw new NotAuthorized();
            return sim.bytes;
          },
        });
      } catch (e) {
        if (e instanceof NotAuthorized) return { resource: X, revoke: "not-authorized" };
        throw e;
      }
      if (outcome.state === "superseded") return { resource: X, revoke: "superseded" };
      if (outcome.state === "refused") return { resource: X, revoke: "refused" };
      const revoke = outcome.state === "committed-own" ? "revoked" : "complete";
      if (selfRetire && o.reason === 0n) return { resource: X, revoke };
      let rotation: RotationOutcome;
      try {
        rotation = await rotateIfExposed({ ...o, channel: c, operation, resource: X });
      } catch (e) {
        // The revocation stands; the rotation resumes from the journal (§9.1).
        if (!(e instanceof IdentityUnavailable)) throw e;
        rotation = { resource: X, status: "unreachable" };
      }
      return { resource: X, revoke, rotation };
    };
    // The roster is read before I's revocation: a self-retiring device cannot read I after it.
    const roster = await rosterTargets(o, channel, I);
    const first = await one(channel, target.resource);
    results.push(first);
    if (first.revoke === "superseded") {
      await journal.setStatus(operation, "superseded");
      return { kind: "superseded", operation };
    }
    // §8.2: display only.
    if (!selfRetire && (first.revoke === "revoked" || first.revoke === "complete"))
      await markRevoked(o, channel, journal, operation, target.resource, o.device);
    for (const t of roster) {
      try {
        const c = await pool.get(o.installation.signer, t.url);
        if (!c.extensions.includes(IDENTITY_EXTENSION)) {
          results.push({ resource: t.resource, revoke: "unsupported" });
          continue;
        }
        results.push(await one(c, t.resource));
      } catch (e) {
        if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
          results.push({ resource: t.resource, revoke: "unreachable" });
        else if (e instanceof IdentityConflict)
          results.push({ resource: t.resource, revoke: "conflict" });
        else throw e;
      }
    }
    const open = results.some(
      (r) =>
        r.revoke === "unreachable" ||
        r.revoke === "conflict" ||
        r.rotation?.status === "awaiting-key-holder" ||
        r.rotation?.status === "unreachable",
    );
    await journal.setStatus(operation, open ? "open" : "done");
    return { kind: "revoked", operation, results: Object.freeze(results) };
  } catch (e) {
    if (e instanceof IdentityUnavailable)
      return { kind: "unavailable", operation, reason: e.message };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }
}

async function markRevoked(
  o: IdentityFlowOptions,
  channel: IdentityChannel,
  journal: OperationJournal,
  operation: string,
  I: ResourceId,
  device: PrincipalId,
): Promise<void> {
  const chain = await syncChain(o.storage, channel, I);
  const doc = o.document(I, genesisOwner(chain));
  const deks = await heldDeks(o.secrets, chain);
  const load = await loadIdentityDocument({ channel, chain, deks, doc });
  const key = principalRefOf(device);
  const entry = doc.devices().get(key);
  if (entry === undefined || entry.revoked === true) return;
  try {
    await runUnitPhase(channel, journal, operation, {
      id: "display",
      resource: I,
      build: () =>
        sealIdentityUnit({
          storage: o.storage,
          chain,
          deks,
          signer: o.installation.signer,
          doc,
          latest: load.latest,
          intents: [{ intent: "device.put", key, entry: { ...entry, revoked: true } }],
        }),
    });
  } catch (e) {
    // Display data only (§4 rule 5): a refused or impossible write is not an error of the revocation.
    if (e instanceof IdentityUnavailable) throw e;
  }
}

/**
 * §8.4 rotation policy: when the Resource holds an exposing revocation
 * committed after its current epoch opened and this installation is the
 * rotator, rotate once (covering every such revocation) and seal the new
 * DEK to every reader; otherwise `awaiting-rotation`, or `not-needed` when
 * nothing exposing happened since the last rotation.
 */
export async function rotateIfExposed(
  o: FlowOptions & {
    readonly channel: IdentityChannel;
    readonly operation: string;
    readonly resource: ResourceId;
  },
): Promise<RotationOutcome> {
  // A rotation this operation already started resumes from its journaled phase: its
  // KEY_EPOCH may be committed while its DEK still waits in the pending slot (§9.1).
  const started = phaseOf(
    await new OperationJournal(o.storage).load(o.operation),
    `rotate:${toHex(o.resource)}`,
  );
  const at = started?.facts?.revokedAt;
  if (at !== undefined && started?.state !== "awaiting-rotation")
    return rotateAfter({ ...o, revokedAt: BigInt(at) });
  const chain = await syncChain(o.storage, o.channel, o.resource);
  const exposing = exposingRevocationsSince(chain);
  const last = exposing.at(-1);
  if (last === undefined) return { resource: o.resource, status: "not-needed" };
  return rotateAfter({ ...o, revokedAt: last.seq });
}
