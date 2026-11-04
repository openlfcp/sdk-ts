import {
  bytesEqual,
  dataEpoch,
  fromHex,
  generateResourceId,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { dekCommitment, generateResourceDEK, type InvitationSecret } from "@openlfcp/crypto";
import {
  ABILITY,
  activeDevice,
  type CertificateChain,
  DEVICE_ABILITY,
  DEVICE_KIND,
  hasAbility,
  invitationPrincipal,
  type PrincipalDescriptor,
  parseInviteUri,
  type Signer,
  signControlRecord,
  validateControlChain,
  verifyInvitationSecret,
} from "@openlfcp/wire";
import type { InvitationLink } from "../invite.js";
import {
  deliverKeys,
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  type KeyDelivery,
  loadIdentityDocument,
  runControlPhase,
  runUnitPhase,
  sealIdentityUnit,
  storeDek,
  syncChain,
} from "./context.js";
import { type RegistrationResult, registerDevice } from "./devices.js";
import { type RosterEntryValue, resourceRef } from "./document.js";
import {
  type JournalOperation,
  newOperationId,
  OperationJournal,
  PackageLedger,
  phaseOf,
} from "./journal.js";
import { ChannelPool, IdentityRefused, IdentityUnavailable } from "./network.js";
import { classifyRegister, type LinearChain } from "./phases.js";
import { type IdentityFlowOptions, identityTarget } from "./resource.js";

/**
 * Invitations accepted by a device and Resources created from a device
 * (IDENTITY-PROFILE-01 §7.2, §7.3). Inviting is unchanged; a device that
 * accepts claims for its root, registers itself, keys the root and (as a
 * managing device) its siblings, and adds the Resource to the roster, as
 * one durable operation, so no accepted or created Resource is ever
 * unreachable for the human's other installations.
 */

/** The root's descriptor: `I`'s Genesis owner (§7.2). */
function rootDescriptor(I: LinearChain): PrincipalDescriptor {
  const g = I.records[0];
  if (g?.body.type !== "GENESIS") throw new Error("the Identity Resource's chain has no Genesis");
  return g.body.owner;
}

/** This installation's chain in `I`, when it is an active personal device of the root. */
function myChain(I: LinearChain, me: PrincipalId): CertificateChain | undefined {
  const d = activeDevice(I.state, me);
  return d !== undefined && d.kind === DEVICE_KIND.PERSONAL && d.chain !== null
    ? d.chain
    : undefined;
}

/** The other active personal devices of the root in `I`, with their chains (§7.2 step 3, §7.3). */
function siblings(I: LinearChain, me: PrincipalId): CertificateChain[] {
  const R = genesisOwner(I);
  const out: CertificateChain[] = [];
  for (const [hex, d] of I.state.devices) {
    const p = principalId(fromHex(hex));
    if (bytesEqual(p, me) || d.kind !== DEVICE_KIND.PERSONAL || d.chain === null) continue;
    if (!bytesEqual(d.root, R) || activeDevice(I.state, p) === undefined) continue;
    out.push(d.chain);
  }
  return out;
}

export interface DeviceResourceResult {
  /** Packages to the root (§7.2 step 2, §7.3). */
  readonly rootKeys: KeyDelivery;
  /** The root's other devices registered here by this managing device; empty without `12`. */
  readonly siblings: readonly RegistrationResult[];
  /** The roster entry was written in `I`. */
  readonly roster: boolean;
}

/**
 * The common tail of §7.2 steps 2–4 and §7.3: seals every epoch held of
 * `X` to the root, registers and keys the root's other active personal
 * devices when this installation manages devices, and adds `X` to the
 * roster of `I`. Each part is idempotent (ledger, §9.2 classification,
 * journaled unit), so a resumed operation repeats nothing.
 */
async function keyAndList(
  o: IdentityFlowOptions,
  pool: ChannelPool,
  journal: OperationJournal,
  operation: string,
  I: LinearChain,
  iUrl: string,
  X: ResourceId,
  url: string,
  entry: RosterEntryValue,
): Promise<DeviceResourceResult> {
  const me = o.installation.signer;
  const R = rootDescriptor(I);
  const channel = await pool.get(me, url);
  const chainX = await syncChain(o.storage, channel, X);
  const deks = await fetchDeks(o.storage, o.secrets, channel, chainX, o.installation);
  const rootKeys = bytesEqual(R.principalId, me.descriptor.principalId)
    ? { sent: [], complete: 0, skipped: [] }
    : await deliverKeys({
        channel,
        ledger: new PackageLedger(o.storage),
        chain: chainX,
        sender: me,
        recipients: [R],
        deks,
      });
  const mine = activeDevice(I.state, me.descriptor.principalId);
  const manages =
    bytesEqual(R.principalId, me.descriptor.principalId) ||
    mine?.mask.includes(DEVICE_ABILITY.DEVICE_MANAGE);
  const others: RegistrationResult[] = [];
  if (manages)
    for (const chain of siblings(I, me.descriptor.principalId)) {
      const r = await registerDevice({ ...o, chain, targets: [{ resource: X, url }] });
      others.push(...r.results);
    }
  // §7.2 step 4, §7.3: the roster entry, so the human's other installations reach X.
  const iChannel = await pool.get(me, iUrl);
  const openI = async () => {
    const chainI = await syncChain(o.storage, iChannel, I.state.resourceId);
    const doc = o.document(I.state.resourceId, genesisOwner(chainI));
    const deksI = await fetchDeks(o.storage, o.secrets, iChannel, chainI, o.installation);
    const load = await loadIdentityDocument({ channel: iChannel, chain: chainI, deks: deksI, doc });
    return { chainI, doc, deksI, load };
  };
  let roster = (await openI()).doc.roster().has(resourceRef(X));
  if (!roster) {
    const r = await runUnitPhase(iChannel, journal, operation, {
      id: "roster",
      resource: I.state.resourceId,
      // A unit refused after a rotation of I is written again in the new epoch (W §19.1).
      rebuildOn: ["STALE_DATA_EPOCH"],
      build: async () => {
        const { chainI, doc, deksI, load } = await openI();
        return sealIdentityUnit({
          storage: o.storage,
          chain: chainI,
          deks: deksI,
          signer: me,
          doc,
          latest: load.latest,
          intents: [{ intent: "roster.put", key: resourceRef(X), entry }],
        });
      },
    });
    roster = r.state === "committed-own";
  }
  return { rootKeys, siblings: Object.freeze(others), roster };
}

/** §7.2: the claim of an invitation for the root, signed by the Invitation Principal (W §18.1 rule 5). */
export const claimForRootRecord = (
  chain: LinearChain,
  invitee: Signer,
  invitationGrantId: Uint8Array,
  root: PrincipalDescriptor,
  abilities: readonly bigint[],
): Uint8Array =>
  signControlRecord(
    {
      resourceId: chain.state.resourceId,
      controlSeq: chain.state.seq + 1n,
      prevControlId: chain.state.head,
    },
    {
      type: "CAPABILITY_CLAIM",
      invitationGrantId: invitationGrantId as never,
      claimant: root,
      abilities,
    },
    invitee,
  ).bytes;

/** §7.2 step 1: the device's own first registration (W §17.4 rule 6). */
export const selfRegistrationRecord = (
  chain: LinearChain,
  device: Signer,
  certificates: CertificateChain,
): Uint8Array =>
  signControlRecord(
    {
      resourceId: chain.state.resourceId,
      controlSeq: chain.state.seq + 1n,
      prevControlId: chain.state.head,
    },
    { type: "DEVICE_GRANT", root: certificates.root, chain: certificates },
    device,
  ).bytes;

/**
 * The Resource is joined or created and keyed, but its roster entry could
 * not be written: the operation stays open; resume it with `operation`
 * (§7.2 step 4, §7.3).
 */
export interface IncompleteDeviceResource extends DeviceResourceResult {
  readonly kind: "incomplete";
  readonly operation: string;
  readonly resource: ResourceId;
}

export type DeviceAcceptResult =
  | IncompleteDeviceResource
  | ({
      readonly kind: "claimed";
      readonly operation: string;
      readonly resource: ResourceId;
      /** The claim record: the root's grant (§18.1). */
      readonly grantId: Uint8Array;
    } & DeviceResourceResult)
  /**
   * This device cannot write the roster (`holds(D_B, 2)` in `I` is false,
   * e.g. a Read device): the invitation stays unclaimed; complete it on an
   * installation that can write `I` (§7.2).
   */
  | { readonly kind: "needs-writer" }
  /** The coordinator refused the claim (e.g. the invitation is used up). */
  | { readonly kind: "refused"; readonly operation: string; readonly code: string }
  /** The link has no secret, or its secret is not the grant's subject (W §18.2). */
  | { readonly kind: "invalid-invitation"; readonly reason: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string };

/**
 * §7.2: accepts an invitation on a device `D_B` of root `R`. The claim
 * names `R` (claimant = `R`'s descriptor, known from `I`'s Genesis) and is
 * signed by the Invitation Principal; then, as one durable operation, the
 * device registers itself (W §17.4 rule 6), seals every epoch it holds to
 * `R`, registers and keys `R`'s other devices when it has `12`, and adds
 * the Resource to the roster. When the installation is the root itself,
 * the claim names it as today and only the last two steps remain.
 */
export async function acceptInvitationAsDevice(
  o: IdentityFlowOptions & {
    readonly link: string | InvitationLink;
    /** The coordinator to use (default: the link's first endpoint). */
    readonly url?: string;
    readonly name?: string;
    /** Resume this operation. */
    readonly operation?: string;
  },
): Promise<DeviceAcceptResult> {
  const invitation = parseInviteUri(typeof o.link === "string" ? o.link : o.link.reveal());
  const secret = invitation.secret;
  if (secret === undefined)
    return { kind: "invalid-invitation", reason: "the link has no #secret= fragment" };
  const X = invitation.resourceId;
  const url = o.url ?? (invitation.endpoints[0] as string);
  const me = o.installation.signer;
  const target = await identityTarget(o);
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  let operation = o.operation;
  try {
    const iChannel = await pool.get(me, target.url);
    const I = await syncChain(o.storage, iChannel, target.resource);
    const R = rootDescriptor(I);
    const isRoot = bytesEqual(R.principalId, me.descriptor.principalId);
    const chainB = isRoot ? undefined : myChain(I, me.descriptor.principalId);
    // §7.2: no claim unless this device can write the roster entry in I.
    if (
      !isRoot &&
      (chainB === undefined || !hasAbility(I.state, me.descriptor.principalId, ABILITY.DATA_WRITE))
    )
      return { kind: "needs-writer" };

    // The Invitation Principal opens X, verifies its secret and opens its package (W §73).
    const invitee: Signer = { key: secret.signingKey, descriptor: invitationPrincipal(secret) };
    const ch = await pool.get(invitee, url);
    let chainX = await syncChain(o.storage, ch, X);
    const claimSigner = verifyInvitationSecretOn(chainX, invitation.grantId, secret);
    if (typeof claimSigner === "string") return { kind: "invalid-invitation", reason: claimSigner };
    await fetchDeks(o.storage, o.secrets, ch, chainX, {
      signer: invitee,
      agreement: secret.agreementKey,
    });
    const grant = chainX.state.grants.get(toHex(invitation.grantId));
    if (grant === undefined)
      return { kind: "invalid-invitation", reason: "the grant is not on the chain" };
    const delegable = grant.delegable.includes(ABILITY.INVITE_CLAIM);
    const abilities = grant.abilities.filter((a) => a !== ABILITY.INVITE_CLAIM || delegable);

    if (operation === undefined || (await journal.get(operation)) === undefined) {
      operation = operation ?? newOperationId("accept-invitation", secureRandom(8));
      await journal.begin({
        id: operation,
        kind: "accept-invitation",
        createdAt: o.now(),
        intent: {
          resource: toHex(X),
          url,
          grant: toHex(invitation.grantId),
          root: toHex(R.principalId),
        },
      });
    }
    const op = operation;
    // The claim, for R (W §18.1 rule 5): a claim already on the chain for R is this operation's or complete.
    const claim = await runControlPhase(o.storage, ch, journal, op, {
      id: "claim",
      kind: "claim",
      resource: X,
      classify: (chain, isOwn) => {
        const done = chain.records.find(
          (r) =>
            r.body.type === "CAPABILITY_CLAIM" &&
            bytesEqual(r.body.invitationGrantId, invitation.grantId) &&
            bytesEqual(r.body.claimant.principalId, R.principalId),
        );
        if (done === undefined) return "pending";
        return isOwn(toHex(done.signed.id)) ? "committed-own" : "complete";
      },
      build: (chain) => claimForRootRecord(chain, claimSigner, invitation.grantId, R, abilities),
    });
    if (claim.state === "refused") {
      await journal.setStatus(op, "abandoned");
      return { kind: "refused", operation: op, code: claim.code ?? "refused" };
    }
    chainX = claim.chain;
    const grantId = chainX.records.find(
      (r) =>
        r.body.type === "CAPABILITY_CLAIM" &&
        bytesEqual(r.body.invitationGrantId, invitation.grantId),
    )?.signed.id as Uint8Array;

    // Step 1: self-registration (W §17.4 rule 6), proposed through the Invitation Principal's session.
    if (chainB !== undefined) {
      const reg = await runControlPhase(o.storage, ch, journal, op, {
        id: `register:${toHex(X)}`,
        kind: "register",
        resource: X,
        classify: (chain, isOwn) =>
          classifyRegister(chain, { root: R.principalId, chain: chainB, isOwnRecord: isOwn }),
        build: (chain) => selfRegistrationRecord(chain, me, chainB),
      });
      if (reg.state === "refused" || reg.state === "superseded")
        return { kind: "refused", operation: op, code: reg.code ?? reg.state };
    }

    // Steps 2–4.
    const rest = await keyAndList(o, pool, journal, op, I, target.url, X, url, {
      profile: chainX.state.dataProfile,
      endpoints: [...invitation.endpoints],
      coordinator: chainX.state.route.coordinatorUrl,
      ...(o.name === undefined ? {} : { name: o.name }),
    });
    // The roster entry is the point of §7.2: without it the operation stays open.
    if (!rest.roster) return { kind: "incomplete", operation: op, resource: X, ...rest };
    await journal.setStatus(op, "done");
    return { kind: "claimed", operation: op, resource: X, grantId, ...rest };
  } catch (e) {
    if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
      return {
        kind: "unavailable",
        ...(operation === undefined ? {} : { operation }),
        reason: e.message,
      };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }
}

function verifyInvitationSecretOn(
  chain: LinearChain,
  grantId: Uint8Array,
  secret: InvitationSecret,
): Signer | string {
  try {
    return verifyInvitationSecret(chain.state, grantId as never, secret);
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

export type DeviceCreateResult =
  | IncompleteDeviceResource
  | ({
      readonly kind: "created";
      readonly operation: string;
      readonly resource: ResourceId;
      readonly chain: LinearChain;
    } & DeviceResourceResult)
  /** Only a personal device with `13` creates Resources for its root (§7.3). */
  | { readonly kind: "not-owner-acting" }
  | { readonly kind: "refused"; readonly operation: string; readonly code: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string };

/**
 * §7.3: a personal device with `13` creates a Resource owned by its root:
 * Genesis field 1 = the root's descriptor, field 5 = the device's chain,
 * signed by the device (W §15), hosted by the device's session; then the
 * epoch-0 DEK sealed to the root, the root's other devices registered and
 * keyed when the device has `12`, and the roster entry — so the root opens
 * the Resource even if the creating device goes offline right after.
 */
export async function createResourceAsDevice(
  o: IdentityFlowOptions & {
    readonly dataProfile: string;
    /** Route and coordinator of the new Resource. */
    readonly url: string;
    readonly name?: string;
    /** Resume this operation. */
    readonly operation?: string;
  },
): Promise<DeviceCreateResult> {
  const me = o.installation.signer;
  const target = await identityTarget(o);
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  let operation = o.operation;
  try {
    const iChannel = await pool.get(me, target.url);
    const I = await syncChain(o.storage, iChannel, target.resource);
    const R = rootDescriptor(I);
    let op: JournalOperation;
    if (operation === undefined || (await journal.get(operation)) === undefined) {
      const chain = myChain(I, me.descriptor.principalId);
      if (chain === undefined || !chain.leaf.payload.mask.includes(DEVICE_ABILITY.OWNER_ACT))
        return { kind: "not-owner-acting" };
      const X = generateResourceId();
      const dek = generateResourceDEK();
      const genesis = signControlRecord(
        { resourceId: X, controlSeq: 0n, prevControlId: null },
        {
          type: "GENESIS",
          dataProfile: o.dataProfile,
          owner: R,
          dekCommitment: dekCommitment(X, dataEpoch(0n), dek),
          endpoints: [{ url: o.url, priority: 0n }],
          coordinatorUrl: o.url,
          deviceChain: chain,
        },
        me,
      );
      const start = validateControlChain([genesis.bytes]);
      if (start.kind !== "linear")
        throw new Error(
          `the Genesis does not validate: ${start.kind === "invalid" ? start.error.message : start.kind}`,
        );
      // The DEK first, then the journal that names the Genesis (§9.1).
      await storeDek(o.storage, o.secrets, start, dataEpoch(0n), dek);
      operation = operation ?? newOperationId("create-resource", secureRandom(8));
      op = await journal.begin({
        id: operation,
        kind: "create-resource",
        createdAt: o.now(),
        intent: {
          resource: toHex(X),
          url: o.url,
          profile: o.dataProfile,
          ...(o.name === undefined ? {} : { name: o.name }),
        },
        phases: [
          {
            id: "host",
            kind: "host",
            resource: toHex(X),
            state: "pending",
            bytes: toHex(genesis.bytes),
          },
        ],
      });
    } else op = await journal.load(operation);
    const X = resourceId(fromHex(op.intent.resource as string));
    const url = op.intent.url as string;
    const host = phaseOf(op, "host");
    if (host !== undefined && host.state !== "committed-own") {
      const answer = await (await pool.get(me, url)).host(fromHex(host.bytes as string));
      if (answer.kind === "nack") {
        await journal.putPhase(op.id, { ...host, state: "refused", code: answer.code });
        await journal.setStatus(op.id, "abandoned");
        return { kind: "refused", operation: op.id, code: answer.code };
      }
      await journal.putPhase(op.id, { ...host, state: "committed-own" });
    }
    const rest = await keyAndList(o, pool, journal, op.id, I, target.url, X, url, {
      profile: op.intent.profile as string,
      endpoints: [url],
      coordinator: url,
      ...(op.intent.name === undefined ? {} : { name: op.intent.name as string }),
    });
    const chain = await syncChain(o.storage, await pool.get(me, url), X);
    if (!rest.roster) return { kind: "incomplete", operation: op.id, resource: X, ...rest };
    await journal.setStatus(op.id, "done");
    return { kind: "created", operation: op.id, resource: X, chain, ...rest };
  } catch (e) {
    if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
      return {
        kind: "unavailable",
        ...(operation === undefined ? {} : { operation }),
        reason: e.message,
      };
    if (e instanceof IdentityConflict) return { kind: "conflict" };
    throw e;
  } finally {
    pool.closeAll();
  }
}
