import {
  bytesEqual,
  fromBase64url,
  fromHex,
  type Hash32,
  hash32,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { InvitationSecret } from "@openlfcp/crypto";
import {
  activeDevice,
  assemblePairingUri,
  type CertificateChain,
  certificateChain,
  DEVICE_KIND,
  type DeviceCertificatePayload,
  type DeviceKind,
  decodeInviteSecret,
  decodePrincipalDescriptor,
  deviceCertificatePayloadDigest,
  deviceFingerprint,
  encodePrincipalDescriptor as encodeDescriptor,
  encodeInviteSecret,
  InMemorySeenUnits,
  invitationPrincipal,
  parseDeviceCertificate,
  receiveDataUnit,
  type Signer,
  signControlRecord,
} from "@openlfcp/wire";
import { loadControlChain } from "../storage.js";
import {
  deliverKeys,
  genesisOwner,
  heldDeks,
  IdentityConflict,
  type IdentityDocumentLoad,
  loadIdentityDocument,
  type PhaseOutcome,
  runControlPhase,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import {
  checkIssuance,
  type FlowOptions,
  leafPayload,
  MASK_PRESETS,
  type MaskPreset,
  mayManageDevices,
  type RegistrationResult,
  registerDevice,
  signChain,
} from "./devices.js";
import {
  type IdentityDocumentPort,
  identityPlaintextCodec,
  type PairingRequestValue,
  principalOfRef,
  principalRefOf,
} from "./document.js";
import {
  type JournalOperation,
  newOperationId,
  OperationJournal,
  PackageLedger,
  pairingSecretRef,
  phaseOf,
} from "./journal.js";
import { ChannelPool, type IdentityChannel, IdentityUnavailable } from "./network.js";
import { classifyCancel, classifyConsume, classifyRegister, type LinearChain } from "./phases.js";
import { type IdentityDocumentFactory, localIdentityResource } from "./resource.js";

/**
 * Pairing a new installation, the managing side `A` (IDENTITY-PROFILE-01
 * §5.3 steps 1, 4–7, 9 and 10): a pairing device `J` registered in the
 * Identity Resource for one session, the request it carries validated and
 * checked against the complete future certificate chain, then the two
 * phases: consume `J` with the approved payload's digest, sign and register
 * exactly that payload. Every phase is journaled and classified by §9.2, so
 * a crash or a lost answer resumes without signing anything else; a
 * pairing session yields at most one approved payload.
 */

/** A bearer link (§5.2): its text is revealed on demand and never logged. */
export class PairingLinkText {
  readonly #uri: string;
  constructor(uri: string) {
    this.#uri = uri;
  }
  /** The lfcp://pair URI with its #secret= fragment. Show it to the human; never log it. */
  reveal(): string {
    return this.#uri;
  }
  toJSON(): string {
    return "[redacted]";
  }
  toString(): string {
    return "[redacted]";
  }
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[redacted]";
  }
}

export interface IdentityFlowOptions extends FlowOptions {
  /** The Identity Resource; default: the one recorded locally, at its chain's coordinator. */
  readonly identity?: { readonly resource: ResourceId; readonly url: string };
  readonly document: IdentityDocumentFactory;
}

/** The Identity Resource of this installation and its coordinator. */
export async function identityTarget(
  o: Pick<IdentityFlowOptions, "identity" | "storage">,
): Promise<{ readonly resource: ResourceId; readonly url: string }> {
  if (o.identity !== undefined) return o.identity;
  const resource = await localIdentityResource(o.storage);
  if (resource === undefined) throw new Error("this installation has no Identity Resource");
  const chain = await loadControlChain(o.storage, resource);
  if (chain?.kind !== "linear") throw new Error("the Identity Resource's chain is not stored");
  return { resource, url: chain.state.route.coordinatorUrl };
}

export type PairingSessionResult =
  | {
      readonly kind: "created";
      readonly session: string;
      readonly pairingDevice: PrincipalId;
      readonly link: PairingLinkText;
    }
  /** §5.3 step 1: the root already has 32 live devices in I; revoke one first. */
  | { readonly kind: "limit"; readonly reason: string }
  /** A lacks the root's unit 1 or a DEK of I: no link (§5.3 step 1). */
  | { readonly kind: "missing-material"; readonly missing: readonly string[] }
  /** This installation is not the root or an active managing device of it. */
  | { readonly kind: "not-authorized"; readonly reason: string }
  | { readonly kind: "refused"; readonly code: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly session?: string; readonly reason: string };

const PAIRING_MASK = [1n, 2n] as const;

/** Wraps a flow body: transport failures and forks become results, the journal stays. */
async function guarded<T>(
  pool: ChannelPool,
  body: () => Promise<T>,
  unavailable: (reason: string) => T,
  conflict: () => T,
): Promise<T> {
  try {
    return await body();
  } catch (e) {
    if (e instanceof IdentityUnavailable) return unavailable(e.message);
    if (e instanceof IdentityConflict) return conflict();
    throw e;
  } finally {
    pool.closeAll();
  }
}

/**
 * §5.3 step 1: creates a pairing device `J` (kind 2, mask {1, 2}, scope
 * [I]), registers it in `I`, seals to it the DEK of every epoch of `I`, and
 * returns the link. Before anything is committed `A` must hold, verified,
 * the root's unit 1 and the DEK of every epoch of `I` (otherwise no link),
 * and the DEVICE_GRANT must fit the root's 32 live devices (W §17.4 rule 8).
 */
export async function createPairingSession(
  o: IdentityFlowOptions & { readonly endpoints?: readonly string[] },
): Promise<PairingSessionResult> {
  const target = await identityTarget(o);
  const pool = new ChannelPool(o.network);
  const me = o.installation.signer;
  return guarded(
    pool,
    async (): Promise<PairingSessionResult> => {
      const channel = await pool.get(me, target.url);
      const chain = await syncChain(o.storage, channel, target.resource);
      const R = genesisOwner(chain);
      if (!mayManageDevices(chain.state, me.descriptor.principalId, R))
        return {
          kind: "not-authorized",
          reason: "only the root or an active managing device creates a pairing session",
        };
      const missing = await missingMaterial(o, channel, chain);
      if (missing.length > 0) return { kind: "missing-material", missing };
      // J's keys go to the SecretStore before the journal row names J (§9.8).
      const secret = InvitationSecret.generate();
      const J = invitationPrincipal(secret);
      const leaf = leafPayload(R, J, DEVICE_KIND.PAIRING, PAIRING_MASK, [target.resource]);
      const feasible = checkIssuance({ chain, issuer: me, leaf });
      if (!feasible.feasible)
        return /rule 8/.test(feasible.reason)
          ? { kind: "limit", reason: feasible.reason }
          : { kind: "not-authorized", reason: feasible.reason };
      const bytes = encodeInviteSecret(secret);
      try {
        await o.secrets.put(pairingSecretRef(J.principalId), bytes);
      } finally {
        bytes.fill(0);
      }
      const chainJ = signChain(chain.state, me, leaf);
      const session = newOperationId("pairing-session", secureRandom(8));
      await new OperationJournal(o.storage).begin({
        id: session,
        kind: "pairing-session",
        createdAt: o.now(),
        intent: {
          identity: toHex(target.resource),
          url: target.url,
          endpoints: [...(o.endpoints ?? [target.url])],
          pairingDevice: toHex(J.principalId),
          root: toHex(R),
          certificates: chainJ.certificates.map((c) => toHex(c.signed.bytes)),
        },
      });
      return finishSession(o, pool, session);
    },
    (reason) => ({ kind: "unavailable", reason }),
    () => ({ kind: "conflict" }),
  );
}

/**
 * §5.3 step 1 after a crash before the link was shown: completes the
 * registration of `J` and its packages from the journal, then returns the
 * link again.
 */
export async function resumePairingSession(
  o: IdentityFlowOptions,
  session: string,
): Promise<PairingSessionResult> {
  const pool = new ChannelPool(o.network);
  return guarded(
    pool,
    () => finishSession(o, pool, session),
    (reason) => ({ kind: "unavailable", session, reason }),
    () => ({ kind: "conflict" }),
  );
}

async function missingMaterial(
  o: FlowOptions,
  channel: IdentityChannel,
  chain: LinearChain,
): Promise<string[]> {
  const missing: string[] = [];
  const deks = await heldDeks(o.secrets, chain);
  for (const e of chain.state.epochs.values())
    if (!deks.has(String(e.epoch))) missing.push(`the DEK of epoch ${e.epoch}`);
  // The carrier of the initial change (§2.2), verified, and retrievable for B.
  const R = genesisOwner(chain);
  const [unit] = await channel.dataUnits(chain.state.resourceId, [
    { actor: R, start: 1n, end: 1n },
  ]);
  const opened =
    unit === undefined
      ? undefined
      : await receiveDataUnit(chain, unit, {
          seen: new InMemorySeenUnits(),
          dek: (epoch) => deks.get(String(epoch)),
          profile: identityPlaintextCodec,
        });
  if (opened?.kind !== "accepted") missing.push("the root's Data Unit with actor sequence 1");
  return missing;
}

async function finishSession(
  o: IdentityFlowOptions,
  pool: ChannelPool,
  session: string,
): Promise<PairingSessionResult> {
  const journal = new OperationJournal(o.storage);
  const op = await journal.load(session);
  const I = resourceId(fromHex(op.intent.identity as string));
  const R = principalId(fromHex(op.intent.root as string));
  const J = principalId(fromHex(op.intent.pairingDevice as string));
  const chainJ = certificateChain(
    (op.intent.certificates as string[]).map((c) => parseDeviceCertificate(fromHex(c))),
    R,
  );
  const me = o.installation.signer;
  const channel = await pool.get(me, op.intent.url as string);
  const grant = await runControlPhase(o.storage, channel, journal, session, {
    id: "grant",
    kind: "register",
    resource: I,
    classify: (chain, isOwn) =>
      classifyRegister(chain, { root: R, chain: chainJ, isOwnRecord: isOwn }),
    build: (chain) =>
      signControlRecord(
        { resourceId: I, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
        { type: "DEVICE_GRANT", root: R, chain: chainJ },
        me,
      ).bytes,
  });
  if (grant.state === "refused" || grant.state === "superseded") {
    await journal.setStatus(session, "abandoned");
    if (grant.state === "refused" && grant.code === "AUTHORIZATION_FAILED")
      return { kind: "limit", reason: "the coordinator refused the pairing device (W §17.4)" };
    return { kind: "refused", code: grant.code ?? grant.state };
  }
  // Every epoch of I to J (same root, W §25.2), before the link is shown.
  const deks = await heldDeks(o.secrets, grant.chain);
  const delivery = await deliverKeys({
    channel,
    ledger: new PackageLedger(o.storage),
    chain: grant.chain,
    sender: me,
    recipients: [grant.chain.state.principals.get(toHex(J)) ?? chainJ.leaf.payload.device],
    deks,
  });
  if (delivery.skipped.length > 0)
    throw new IdentityUnavailable(
      `the packages to the pairing device were not all accepted: ${delivery.skipped.map((s) => s.reason).join("; ")}`,
    );
  const bytes = await o.secrets.get(pairingSecretRef(J));
  if (bytes === undefined) throw new Error("the pairing device's secret is not in the SecretStore");
  let secret: InvitationSecret;
  try {
    secret = decodeInviteSecret(bytes);
  } finally {
    bytes.fill(0);
  }
  const link = assemblePairingUri({
    identityResourceId: I,
    endpoints: op.intent.endpoints as string[],
    pairingDevice: J,
    secret,
  });
  return { kind: "created", session, pairingDevice: J, link: new PairingLinkText(link) };
}

/** A pairing request `A` may show (§5.3 step 4). */
export interface PairingReview {
  readonly session: string;
  /** `requests[k]`: the PrincipalRef of `D_B`. */
  readonly requestKey: string;
  readonly device: PrincipalId;
  /** base64url of the exact descriptor bytes. */
  readonly descriptor: string;
  readonly label: string;
  readonly platform?: string;
  readonly kind: 0 | 1;
  /** The requested scope (kind 1), the Identity Resource already removed. */
  readonly requestedScope: readonly ResourceId[];
  /** §5.2 device fingerprint of `D_B`, for the human to compare with B's screen. */
  readonly fingerprint: string;
  /** Each preset of §5.4 for the request's kind, and whether the future chain passes (§5.3 step 4). */
  readonly presets: readonly {
    readonly preset: MaskPreset;
    readonly offered: boolean;
    readonly reason?: string;
  }[];
  /** The confirmed tuple: when the entry changes, the confirmation is asked again. */
  readonly tuple: string;
}

const tupleOf = (key: string, entry: PairingRequestValue) =>
  JSON.stringify([
    key,
    entry.descriptor,
    entry.pairing,
    entry.label,
    entry.kind,
    entry.scope ?? [],
    entry.platform ?? null,
  ]);

async function readSession(o: IdentityFlowOptions, session: string) {
  const op = await new OperationJournal(o.storage).load(session);
  return {
    op,
    I: resourceId(fromHex(op.intent.identity as string)),
    R: principalId(fromHex(op.intent.root as string)),
    J: principalId(fromHex(op.intent.pairingDevice as string)),
    url: op.intent.url as string,
  };
}

async function openIdentity(
  o: IdentityFlowOptions,
  channel: IdentityChannel,
  I: ResourceId,
): Promise<{ chain: LinearChain; doc: IdentityDocumentPort; load: IdentityDocumentLoad }> {
  const chain = await syncChain(o.storage, channel, I);
  const doc = o.document(I, genesisOwner(chain));
  const load = await loadIdentityDocument({
    channel,
    chain,
    deks: await heldDeks(o.secrets, chain),
    doc,
  });
  return { chain, doc, load };
}

function presetsFor(
  chain: LinearChain,
  o: IdentityFlowOptions,
  R: PrincipalId,
  J: PrincipalId,
  device: ReturnType<typeof decodePrincipalDescriptor>,
  kind: 0 | 1,
  scope: readonly ResourceId[],
): PairingReview["presets"] {
  const names: MaskPreset[] = kind === 0 ? ["full", "edit", "read"] : ["service"];
  return names.map((preset) => {
    const p = MASK_PRESETS[preset];
    if (kind === 1 && scope.length === 0)
      return { preset, offered: false, reason: "a service scope must keep at least one Resource" };
    const f = checkIssuance({
      chain,
      issuer: o.installation.signer,
      leaf: leafPayload(R, device, p.kind as DeviceKind, p.mask, kind === 1 ? scope : []),
      pairing: J,
    });
    return f.feasible ? { preset, offered: true } : { preset, offered: false, reason: f.reason };
  });
}

function reviewOf(
  o: IdentityFlowOptions,
  session: string,
  chain: LinearChain,
  load: IdentityDocumentLoad,
  R: PrincipalId,
  J: PrincipalId,
  I: ResourceId,
  key: string,
  entry: PairingRequestValue,
): PairingReview | undefined {
  // §5.3 step 4: the entry names this session's J, J is an active pairing
  // device of R, and every change that wrote the entry was signed by J.
  if (entry.pairing !== principalRefOf(J)) return undefined;
  const j = activeDevice(chain.state, J);
  if (j === undefined || j.kind !== DEVICE_KIND.PAIRING || !bytesEqual(j.root, R)) return undefined;
  const writers = load.requestWriters.get(key);
  if (writers === undefined || [...writers].some((w) => w !== toHex(J))) return undefined;
  const device = principalOfRef(key);
  if (device === undefined) return undefined;
  let descriptor: ReturnType<typeof decodePrincipalDescriptor>;
  try {
    descriptor = decodePrincipalDescriptor(fromBase64url(entry.descriptor));
  } catch {
    return undefined;
  }
  if (!bytesEqual(descriptor.principalId, device)) return undefined;
  const requestedScope = (entry.scope ?? [])
    .map((ref) => resourceId(fromBase64url(ref)))
    // A service scope never lists the Identity Resource (§5.3 step 4).
    .filter((r) => !bytesEqual(r, I));
  return Object.freeze({
    session,
    requestKey: key,
    device,
    descriptor: entry.descriptor,
    label: entry.label,
    ...(entry.platform === undefined ? {} : { platform: entry.platform }),
    kind: entry.kind,
    requestedScope: Object.freeze(requestedScope),
    fingerprint: deviceFingerprint(device),
    presets: Object.freeze(presetsFor(chain, o, R, J, descriptor, entry.kind, requestedScope)),
    tuple: tupleOf(key, entry),
  });
}

/** §5.3 step 4: the valid requests of a session, each with the presets whose future chain passes. */
export async function pairingRequests(
  o: IdentityFlowOptions & { readonly session: string },
): Promise<readonly PairingReview[]> {
  const { I, R, J, url } = await readSession(o, o.session);
  const pool = new ChannelPool(o.network);
  try {
    const channel = await pool.get(o.installation.signer, url);
    const { chain, doc, load } = await openIdentity(o, channel, I);
    const out: PairingReview[] = [];
    for (const [key, entry] of doc.requests()) {
      const r = reviewOf(o, o.session, chain, load, R, J, I, key, entry);
      if (r !== undefined) out.push(r);
    }
    return Object.freeze(out);
  } finally {
    pool.closeAll();
  }
}

export type ApprovalResult =
  | {
      readonly kind: "approved";
      readonly operation: string;
      readonly device: PrincipalId;
      readonly chain: CertificateChain;
      /** §5.3 step 10: the Resources of the roster (or the approved scope). */
      readonly registrations: readonly RegistrationResult[];
    }
  /** The entry changed since the human confirmed it: ask again (§5.3 step 4). */
  | { readonly kind: "reconfirm"; readonly review: PairingReview | undefined }
  /** The preset's future chain does not pass on the current head (§5.3 step 4). */
  | { readonly kind: "infeasible"; readonly reason: string }
  /** The session was consumed by another approval or cancelled: nothing is signed (§9.2). */
  | { readonly kind: "superseded"; readonly operation: string }
  /** Phase 2 meets the 32-device limit: retry after a revocation; the approval stays consumed (§5.3 step 6). */
  | { readonly kind: "limit"; readonly operation: string }
  | { readonly kind: "refused"; readonly operation: string; readonly code: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string };

/**
 * §5.3 steps 4–7 and 10: approves the confirmed request with a preset
 * (and, for a service device, a scope within the requested one). The
 * complete certificate payload and its digest are journaled before
 * phase 1; phase 2 signs exactly that payload.
 */
export async function approvePairing(
  o: IdentityFlowOptions & {
    readonly review: PairingReview;
    readonly preset: MaskPreset;
    /** Service only: the approved scope, a subset of the requested one. */
    readonly scope?: readonly ResourceId[];
    /** RFC 3339 UTC for `devices[...].added_at`. */
    readonly addedAt?: string;
  },
): Promise<ApprovalResult> {
  const { I, R, J, url } = await readSession(o, o.review.session);
  const pool = new ChannelPool(o.network);
  const me = o.installation.signer;
  const prepared = await guarded(
    pool,
    async (): Promise<ApprovalResult | string> => {
      const channel = await pool.get(me, url);
      const { chain, doc, load } = await openIdentity(o, channel, I);
      const entry = doc.requests().get(o.review.requestKey);
      const review =
        entry === undefined
          ? undefined
          : reviewOf(o, o.review.session, chain, load, R, J, I, o.review.requestKey, entry);
      if (review === undefined || review.tuple !== o.review.tuple)
        return { kind: "reconfirm", review };
      const preset = MASK_PRESETS[o.preset];
      if ((preset.kind === DEVICE_KIND.SERVICE) !== (review.kind === 1))
        return { kind: "infeasible", reason: "the preset's kind is not the requested kind" };
      const scope =
        review.kind === 1
          ? (o.scope ?? review.requestedScope).filter((r) => !bytesEqual(r, I))
          : [];
      if (scope.some((r) => !review.requestedScope.some((q) => bytesEqual(q, r))))
        return { kind: "infeasible", reason: "the approved scope adds a Resource (§5.3 step 4)" };
      if (review.kind === 1 && scope.length === 0)
        return {
          kind: "infeasible",
          reason: "a service scope trimmed to nothing is not approvable",
        };
      const descriptor = decodePrincipalDescriptor(fromBase64url(review.descriptor));
      const leaf = leafPayload(R, descriptor, preset.kind as DeviceKind, preset.mask, scope);
      const f = checkIssuance({ chain, issuer: me, leaf, pairing: J });
      if (!f.feasible) return { kind: "infeasible", reason: f.reason };
      const operation = newOperationId("pairing-approval", secureRandom(8));
      await new OperationJournal(o.storage).begin({
        id: operation,
        kind: "pairing-approval",
        createdAt: o.now(),
        intent: {
          session: o.review.session,
          identity: toHex(I),
          url,
          root: toHex(R),
          pairingDevice: toHex(J),
          requestKey: review.requestKey,
          fingerprint: review.fingerprint,
          label: review.label,
          ...(review.platform === undefined ? {} : { platform: review.platform }),
          ...(o.addedAt === undefined ? {} : { addedAt: o.addedAt }),
          payload: payloadToJson(leaf),
          digest: toHex(deviceCertificatePayloadDigest(leaf)),
        },
      });
      return operation;
    },
    (reason): ApprovalResult => ({ kind: "unavailable", reason }),
    (): ApprovalResult => ({ kind: "conflict" }),
  );
  if (typeof prepared !== "string") return prepared;
  return resumeApproval(o, prepared);
}

interface PayloadJson {
  readonly root: string;
  readonly descriptor: string;
  readonly kind: number;
  readonly mask: readonly string[];
  readonly scope: readonly string[];
  readonly serial: string;
}

const payloadToJson = (p: DeviceCertificatePayload): PayloadJson => ({
  root: toHex(p.root),
  descriptor: toBase64url(encodeDescriptor(p.device)),
  kind: p.kind,
  mask: p.mask.map(String),
  scope: p.scope.map(toHex),
  serial: toHex(p.serial),
});

function payloadFromJson(j: PayloadJson): DeviceCertificatePayload {
  return Object.freeze({
    root: principalId(fromHex(j.root)),
    device: decodePrincipalDescriptor(fromBase64url(j.descriptor)),
    kind: j.kind as DeviceKind,
    mask: Object.freeze(j.mask.map(BigInt)),
    scope: Object.freeze(j.scope.map((s) => resourceId(fromHex(s)))),
    serial: fromHex(j.serial),
  });
}

class Infeasible extends Error {}

const next = (chain: LinearChain) => ({
  resourceId: chain.state.resourceId,
  controlSeq: chain.state.seq + 1n,
  prevControlId: chain.state.head,
});

/** Phase 1 (§5.3 step 5): `DEVICE_REVOKE {R, J, 3, digest}` on the chain's head. */
export const consumeRecord = (
  chain: LinearChain,
  signer: Signer,
  root: PrincipalId,
  pairing: PrincipalId,
  digest: Hash32,
): Uint8Array =>
  signControlRecord(
    next(chain),
    { type: "DEVICE_REVOKE", root, device: pairing, reason: 3n, approval: digest },
    signer,
  ).bytes;

/** Phase 2 (§5.3 step 6): `DEVICE_GRANT {R, chain_B, 2: J}` on the chain's head. */
export const approvedGrantRecord = (
  chain: LinearChain,
  signer: Signer,
  root: PrincipalId,
  device: CertificateChain,
  pairing: PrincipalId,
): Uint8Array =>
  signControlRecord(
    next(chain),
    { type: "DEVICE_GRANT", root, chain: device, pairingDevice: pairing },
    signer,
  ).bytes;

/** §5.3 step 9: `DEVICE_REVOKE {R, J, 0}` on the chain's head. */
export const cancelRecord = (
  chain: LinearChain,
  signer: Signer,
  root: PrincipalId,
  pairing: PrincipalId,
): Uint8Array =>
  signControlRecord(
    next(chain),
    { type: "DEVICE_REVOKE", root, device: pairing, reason: 0n },
    signer,
  ).bytes;

/** Resumes a journaled approval from its next phase (§9.1: "If A crashes after step 5 …"). */
export async function resumeApproval(
  o: IdentityFlowOptions,
  operation: string,
): Promise<ApprovalResult> {
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  const me = o.installation.signer;
  return guarded(
    pool,
    async (): Promise<ApprovalResult> => {
      let op: JournalOperation = await journal.load(operation);
      if (op.status === "superseded") return { kind: "superseded", operation };
      const I = resourceId(fromHex(op.intent.identity as string));
      const R = principalId(fromHex(op.intent.root as string));
      const J = principalId(fromHex(op.intent.pairingDevice as string));
      const leaf = payloadFromJson(op.intent.payload as PayloadJson);
      const digest = hash32(fromHex(op.intent.digest as string));
      if (!bytesEqual(deviceCertificatePayloadDigest(leaf), digest))
        throw new Error("the journaled payload does not match its digest");
      const channel = await pool.get(me, op.intent.url as string);

      // Phase 1: consume J with the digest (§5.3 step 5).
      let consume: PhaseOutcome;
      try {
        consume = await runControlPhase(o.storage, channel, journal, operation, {
          id: "consume",
          kind: "consume",
          resource: I,
          facts: { digest: toHex(digest) },
          classify: (chain) => classifyConsume(chain.state, R, J, digest),
          build: (chain) => {
            // The proposer re-checks its own authority on the new head (§5.3 step 5).
            const f = checkIssuance({ chain, issuer: me, leaf, pairing: J });
            if (!f.feasible) throw new Infeasible(f.reason);
            return consumeRecord(chain, me, R, J, digest);
          },
        });
      } catch (e) {
        if (!(e instanceof Infeasible)) throw e;
        await journal.setStatus(operation, "abandoned");
        return { kind: "infeasible", reason: e.message };
      }
      if (consume.state === "superseded") {
        await journal.setStatus(operation, "superseded");
        return { kind: "superseded", operation };
      }
      if (consume.state === "refused") {
        await journal.setStatus(operation, "abandoned");
        return { kind: "refused", operation, code: consume.code ?? "refused" };
      }

      // Phase 2: sign exactly the journaled payload and register (§5.3 step 6).
      const chainB = signChain(consume.chain.state, me, leaf);
      const register = await runControlPhase(o.storage, channel, journal, operation, {
        id: "register",
        kind: "register",
        resource: I,
        classify: (chain, isOwn) =>
          classifyRegister(chain, {
            root: R,
            chain: chainB,
            pairingPhase2: true,
            isOwnRecord: isOwn,
          }),
        build: (chain) => approvedGrantRecord(chain, me, R, chainB, J),
      });
      if (register.state === "superseded") {
        await journal.setStatus(operation, "superseded");
        return { kind: "superseded", operation };
      }
      if (register.state === "refused") {
        // Rule 8: the approval stays consumed; propose the same chain after a revocation.
        if (register.code === "AUTHORIZATION_FAILED") {
          const p = phaseOf(await journal.load(operation), "register");
          if (p !== undefined) await journal.putPhase(operation, { ...p, state: "pending" });
          return { kind: "limit", operation };
        }
        await journal.setStatus(operation, "abandoned");
        return { kind: "refused", operation, code: register.code ?? "refused" };
      }

      // Step 6: the device entry, and the request removed, in one change by A.
      op = await journal.load(operation);
      const key = op.intent.requestKey as string;
      const deviceEntry = {
        label: op.intent.label as string,
        kind: (leaf.kind === DEVICE_KIND.SERVICE ? 1 : 0) as 0 | 1,
        ...(op.intent.platform === undefined ? {} : { platform: op.intent.platform as string }),
        ...(op.intent.addedAt === undefined ? {} : { added_at: op.intent.addedAt as string }),
      };
      // Display data only: a refused unit is restored by reconciliation (§7.1 step 4).
      await runUnitPhase(channel, journal, operation, {
        id: "document",
        resource: I,
        build: async () => {
          const { chain, doc, load } = await openIdentity(o, channel, I);
          return sealIdentityUnit({
            storage: o.storage,
            chain,
            deks: await heldDeks(o.secrets, chain),
            signer: me,
            doc,
            latest: load.latest,
            intents: [
              { intent: "device.put", key, entry: deviceEntry },
              ...(doc.requests().has(key) ? [{ intent: "request.delete" as const, key }] : []),
            ],
          });
        },
      });

      // Step 7: every epoch of I to a personal B, each recorded (§9.5).
      const chain = await syncChain(o.storage, channel, I);
      if (leaf.kind === DEVICE_KIND.PERSONAL)
        await deliverKeys({
          channel,
          ledger: new PackageLedger(o.storage),
          chain,
          sender: me,
          recipients: [leaf.device],
          deks: await heldDeks(o.secrets, chain),
        });

      // Step 10: register B in the roster (or the approved scope).
      const { doc } = await openIdentity(o, channel, I);
      const targets = [...doc.roster()]
        .filter(([, e]) => e.archived !== true)
        .map(([ref, e]) => ({ resource: resourceId(fromBase64url(ref)), url: e.coordinator }))
        .filter(
          (t) =>
            !bytesEqual(t.resource, I) &&
            (leaf.kind === DEVICE_KIND.PERSONAL ||
              leaf.scope.some((s) => bytesEqual(s, t.resource))),
        );
      const registered = await registerDevice({ ...o, chain: chainB, targets });
      await journal.updateIntent(operation, { registration: registered.operation });
      await journal.setStatus(operation, "done");
      await journal.setStatus(op.intent.session as string, "done");
      return {
        kind: "approved",
        operation,
        device: principalId(leaf.device.principalId),
        chain: chainB,
        registrations: registered.results,
      };
    },
    (reason) => ({ kind: "unavailable", operation, reason }),
    () => ({ kind: "conflict" }),
  );
}

export type CancelResult =
  | { readonly kind: "cancelled" }
  /** The session was consumed by an approval: not cancelled (§9.2 Cancel: superseded). */
  | { readonly kind: "consumed" }
  | { readonly kind: "refused"; readonly code: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly reason: string };

/**
 * §5.3 step 9 (rejection, timeout, cancel): `DEVICE_REVOKE {R, J, 0}`.
 * With `reject`, the request entry is deleted first (step 4: a request the
 * human does not confirm is rejected).
 */
export async function cancelPairing(
  o: IdentityFlowOptions & { readonly session: string; readonly reject?: string },
): Promise<CancelResult> {
  const { I, R, J, url } = await readSession(o, o.session);
  const journal = new OperationJournal(o.storage);
  const pool = new ChannelPool(o.network);
  const me = o.installation.signer;
  return guarded(
    pool,
    async (): Promise<CancelResult> => {
      const channel = await pool.get(me, url);
      if (o.reject !== undefined) {
        const key = o.reject;
        await runUnitPhase(channel, journal, o.session, {
          id: `reject:${key}`,
          resource: I,
          build: async () => {
            const { chain, doc, load } = await openIdentity(o, channel, I);
            return sealIdentityUnit({
              storage: o.storage,
              chain,
              deks: await heldDeks(o.secrets, chain),
              signer: me,
              doc,
              latest: load.latest,
              intents: [{ intent: "request.delete", key }],
            });
          },
        });
      }
      const cancel = await runControlPhase(o.storage, channel, journal, o.session, {
        id: "cancel",
        kind: "cancel",
        resource: I,
        classify: (chain) => classifyCancel(chain.state, R, J),
        build: (chain) => cancelRecord(chain, me, R, J),
      });
      if (cancel.state === "superseded") return { kind: "consumed" };
      if (cancel.state === "refused") return { kind: "refused", code: cancel.code ?? "refused" };
      await journal.setStatus(o.session, "abandoned");
      await o.secrets.delete(pairingSecretRef(J));
      return { kind: "cancelled" };
    },
    (reason) => ({ kind: "unavailable", reason }),
    () => ({ kind: "conflict" }),
  );
}

/** Open pairing sessions of this installation, oldest first. */
export async function openPairingSessions(o: Pick<FlowOptions, "storage">) {
  return (
    await new OperationJournal(o.storage).list({ kind: "pairing-session", status: "open" })
  ).map((op) => ({
    session: op.id,
    identity: resourceId(fromHex(op.intent.identity as string)),
    pairingDevice: principalId(fromHex(op.intent.pairingDevice as string)),
  }));
}
