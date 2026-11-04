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
import {
  activeDevice,
  type CertificateChain,
  type ControlRecord,
  certificateChain,
  DEVICE_KIND,
  type DeviceCertificatePayload,
  decodeInviteSecret,
  deviceFingerprint,
  encodeInviteSecret,
  encodePrincipalDescriptor,
  invitationPrincipal,
  type PairingLink,
  pairingDeviceSigner,
  parseDeviceCertificate,
  parsePairingUri,
  revocationOf,
  type Signer,
} from "@openlfcp/wire";
import {
  fetchDeks,
  genesisOwner,
  IdentityConflict,
  type Installation,
  loadIdentityDocument,
  runUnitPhase,
  sealIdentityUnit,
  syncChain,
} from "./context.js";
import type { FlowOptions } from "./devices.js";
import { IDENTITY_PROFILE, principalRefOf, resourceRef } from "./document.js";
import { newOperationId, OperationJournal, pairingSecretRef } from "./journal.js";
import {
  ChannelPool,
  IDENTITY_EXTENSION,
  IdentityRefused,
  IdentityUnavailable,
} from "./network.js";
import type { PairingLinkText } from "./pairing.js";
import type { LinearChain } from "./phases.js";
import { type IdentityDocumentFactory, setLocalIdentityResource } from "./resource.js";

/**
 * Pairing a new installation, the new side `B` (IDENTITY-PROFILE-01 §5.3
 * steps 2, 3, 8 and 11; §6). `B` opens the Identity Resource as the
 * pairing device `J` of the link, verifies it, persists its candidates and
 * writes its request as `J`; later it learns its result from the chain
 * alone: while `J` is active the request waits; once `J` is revoked the
 * revoked-reader prefix (W §41) says whether the session was consumed
 * (reason 3, with the approval digest `d`) or cancelled. The first
 * verified certificate naming `D_B` whose payload digest is `d` decides;
 * a timeout never does.
 */

export interface RequestPairingOptions extends FlowOptions {
  readonly link: string | PairingLinkText;
  readonly label: string;
  /** 0 personal, 1 service. */
  readonly kind: 0 | 1;
  /** Service: the Resources its human chose from the roster. */
  readonly scope?: readonly ResourceId[];
  readonly platform?: string;
  /** RFC 3339 UTC for `requested_at`. */
  readonly requestedAt?: string;
  readonly document: IdentityDocumentFactory;
}

export type RequestPairingResult =
  | {
      readonly kind: "requested";
      readonly operation: string;
      readonly identity: ResourceId;
      /** §5.2: show it; the human compares it with A's screen. */
      readonly fingerprint: string;
    }
  /** The link does not parse, or its secret is not its device's (§5.2). */
  | { readonly kind: "invalid-link"; readonly reason: string }
  /** `I` is not an Identity Resource, or `J` is not an active pairing device of its owner (§5.2). */
  | { readonly kind: "not-a-session"; readonly reason: string }
  /** No DEK of `I` or no root unit 1: the document cannot be verified (§5.3 step 2). */
  | { readonly kind: "missing-material"; readonly missing: readonly string[] }
  /** The coordinator refused the request unit (e.g. ACTOR_EQUIVOCATION: another installation used the link at once). */
  | { readonly kind: "refused"; readonly operation: string; readonly code: string }
  | { readonly kind: "unavailable"; readonly operation?: string; readonly reason: string };

interface Candidate {
  readonly resource: string;
  readonly url: string;
  readonly profile: string;
  readonly name?: string;
}

/** §5.3 steps 2–3. */
export async function requestPairing(o: RequestPairingOptions): Promise<RequestPairingResult> {
  let link: PairingLink;
  let J: Signer;
  try {
    link = parsePairingUri(typeof o.link === "string" ? o.link : o.link.reveal());
    J = pairingDeviceSigner(link);
  } catch (e) {
    return { kind: "invalid-link", reason: e instanceof Error ? e.message : String(e) };
  }
  const I = link.identityResourceId;
  const url = link.endpoints[0] as string;
  const B = o.installation.signer.descriptor;
  const pool = new ChannelPool(o.network);
  const journal = new OperationJournal(o.storage);
  try {
    const channel = await pool.get(J, url);
    const chain = await syncChain(o.storage, channel, I);
    const R = genesisOwner(chain);
    if (chain.state.dataProfile !== IDENTITY_PROFILE)
      return { kind: "not-a-session", reason: "the Resource is not an Identity Resource" };
    const j = activeDevice(chain.state, J.descriptor.principalId);
    if (j === undefined || j.kind !== DEVICE_KIND.PAIRING || !bytesEqual(j.root, R))
      return {
        kind: "not-a-session",
        reason: "the link's device is not an active pairing device of the owner",
      };
    const pairing: Installation = { signer: J, agreement: link.secret.agreementKey };
    const deks = await fetchDeks(o.storage, o.secrets, channel, chain, pairing);
    const doc = o.document(I, R);
    const load = await loadIdentityDocument({ channel, chain, deks, doc });
    if (!doc.initialized())
      return {
        kind: "missing-material",
        missing: deks.size === 0 ? ["the DEKs of the Identity Resource"] : ["the root's unit 1"],
      };
    // Step 3: the candidates B may be registered in, persisted before the request.
    const chosen = new Set((o.scope ?? []).map((r) => resourceRef(r)));
    const candidates: Candidate[] = [...doc.roster()]
      .filter(([ref, e]) => e.archived !== true && ref !== resourceRef(I))
      .filter(([ref]) => o.kind === 0 || chosen.has(ref))
      .map(([ref, e]) => ({
        resource: toHex(fromBase64url(ref)),
        url: e.coordinator,
        profile: e.profile,
        ...(e.name === undefined ? {} : { name: e.name }),
      }));
    const secret = encodeInviteSecret(link.secret);
    try {
      await o.secrets.put(pairingSecretRef(J.descriptor.principalId), secret);
    } finally {
      secret.fill(0);
    }
    const operation = newOperationId("pairing-request", secureRandom(8));
    await journal.begin({
      id: operation,
      kind: "pairing-request",
      createdAt: o.now(),
      intent: {
        identity: toHex(I),
        url,
        root: toHex(R),
        pairingDevice: toHex(J.descriptor.principalId),
        device: toHex(B.principalId),
        kind: o.kind,
        label: o.label,
        candidates,
      },
    });
    const key = principalRefOf(B.principalId);
    const previous = load.latest.get(toHex(J.descriptor.principalId));
    const unit = await runUnitPhase(channel, journal, operation, {
      id: "request",
      resource: I,
      build: () =>
        sealIdentityUnit({
          storage: o.storage,
          chain,
          deks,
          signer: J,
          doc,
          latest: load.latest,
          // J may be used by another installation: the next sequence after the one it sees (§5.3).
          seq: (previous?.seq ?? 0n) + 1n,
          intents: [
            {
              intent: "request.put",
              key,
              entry: {
                descriptor: toBase64url(encodePrincipalDescriptor(B)),
                pairing: principalRefOf(J.descriptor.principalId),
                label: o.label,
                kind: o.kind,
                ...(o.kind === 1
                  ? { scope: candidates.map((c) => toBase64url(fromHex(c.resource))) }
                  : {}),
                ...(o.platform === undefined ? {} : { platform: o.platform }),
                ...(o.requestedAt === undefined ? {} : { requested_at: o.requestedAt }),
              },
            },
          ],
        }),
    });
    if (unit.state === "refused")
      return { kind: "refused", operation, code: unit.code ?? "refused" };
    return {
      kind: "requested",
      operation,
      identity: I,
      fingerprint: deviceFingerprint(B.principalId),
    };
  } catch (e) {
    if (
      e instanceof IdentityUnavailable ||
      e instanceof IdentityRefused ||
      e instanceof IdentityConflict
    )
      return { kind: "unavailable", reason: e.message };
    throw e;
  } finally {
    pool.closeAll();
  }
}

/** §6: the status of one Resource for the new device, from its own observations only. */
export type CandidateStatus =
  | "ready"
  | "waiting-for-keys"
  | "pending-registration"
  | "not-granted"
  | "unproven"
  | "unreachable"
  | "unsupported";

export interface CandidateResult {
  readonly resource: ResourceId;
  readonly status: CandidateStatus;
}

export type PairingOutcome =
  /** `J` is still active: the request waits for the managing device (§5.3 step 3). */
  | { readonly kind: "waiting" }
  /** The session was cancelled (reason 0): final (§5.3 step 8). */
  | { readonly kind: "rejected" }
  /**
   * The session was consumed. Without a certificate yet: "approved,
   * waiting for registration"; with it, each candidate's status (§6).
   */
  | {
      readonly kind: "approved";
      readonly certificate: CertificateChain | null;
      readonly candidates: readonly CandidateResult[];
      /** Certificates naming D_B with another digest: reported, never used (§5.3 step 8). */
      readonly foreignCertificates: number;
    }
  /** `J` is no longer readable and no revoked-reader proof is available yet. */
  | { readonly kind: "unknown"; readonly reason: string }
  | { readonly kind: "unavailable"; readonly reason: string };

/** The accepted DEVICE_GRANT leaves naming `device` in a chain's history, oldest first. */
function leavesOf(chain: LinearChain, device: PrincipalId): CertificateChain[] {
  return chain.records
    .filter(
      (
        r: ControlRecord,
      ): r is ControlRecord & { body: { type: "DEVICE_GRANT"; chain: CertificateChain } } =>
        r.body.type === "DEVICE_GRANT" &&
        bytesEqual(r.body.chain.leaf.payload.device.principalId, device),
    )
    .map((r) => r.body.chain);
}

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((x) => b.includes(x));

/** What a candidate's own chain proves about the device's approved certificate (§5.3 step 8). */
export interface CandidateEvidence {
  /** The certificate IDs of every accepted leaf naming the device, oldest first. */
  readonly leaves: readonly Hash32[];
  /** A leaf whose payload digest is the approval was accepted here at some point. */
  readonly proven: boolean;
  /** Registered and active here, or still pending registration. */
  readonly registration: "active" | "pending";
  /**
   * The device may use this Resource: proven, active, and its current leaf
   * has the result's kind, mask and scope (N8). A Resource where the device
   * is registered without proof is "approval not provable here".
   */
  readonly usable: boolean;
}

export function candidateEvidence(
  chain: LinearChain,
  device: PrincipalId,
  digest: Hash32,
  result: DeviceCertificatePayload,
): CandidateEvidence {
  const leaves = leavesOf(chain, device);
  const proven = leaves.some((l) => bytesEqual(l.leaf.payloadDigest, digest));
  const d = chain.state.devices.get(toHex(device));
  const active = d?.registered === true && activeDevice(chain.state, device) !== undefined;
  const same =
    d !== undefined &&
    d.kind === result.kind &&
    sameSet(d.mask.map(String), result.mask.map(String)) &&
    sameSet(d.scope.map(toHex), result.scope.map(toHex));
  return Object.freeze({
    leaves: Object.freeze(leaves.map((l) => l.leaf.id)),
    proven,
    registration: active ? "active" : "pending",
    usable: proven && active && same,
  });
}

/**
 * §5.3 steps 8 and 11: learns the session's result and the status of
 * every candidate. Resumable at any point from the persisted candidates
 * (and while `J` is active, from the link's secret in the SecretStore).
 */
export async function completePairing(
  o: FlowOptions & { readonly operation: string; readonly document?: IdentityDocumentFactory },
): Promise<PairingOutcome> {
  const journal = new OperationJournal(o.storage);
  let op = await journal.load(o.operation);
  const I = resourceId(fromHex(op.intent.identity as string));
  const R = principalId(fromHex(op.intent.root as string));
  const Jid = principalId(fromHex(op.intent.pairingDevice as string));
  const B = o.installation.signer;
  const D = B.descriptor.principalId;
  const kind = op.intent.kind as 0 | 1;
  const pool = new ChannelPool(o.network);
  try {
    // Step 8: the session's result, from J's view of I (W §41 after its revocation).
    if (op.intent.result === undefined) {
      const bytes = await o.secrets.get(pairingSecretRef(Jid));
      if (bytes === undefined) return { kind: "unknown", reason: "the pairing secret is gone" };
      let J: Signer;
      try {
        const secret = decodeInviteSecret(bytes);
        J = { key: secret.signingKey, descriptor: invitationPrincipal(secret) };
      } finally {
        bytes.fill(0);
      }
      let chain: LinearChain;
      try {
        chain = await syncChain(o.storage, await pool.get(J, op.intent.url as string), I);
      } catch (e) {
        if (e instanceof IdentityRefused)
          return {
            kind: "unknown",
            reason: "the pairing device can no longer read and no proof is served",
          };
        throw e;
      }
      const r = revocationOf(chain.state, R, Jid);
      if (r === undefined) return { kind: "waiting" };
      if (r.reason === 3n && r.approval !== null)
        op = await journal.updateIntent(o.operation, {
          result: "approved",
          digest: toHex(r.approval),
        });
      else {
        await journal.updateIntent(o.operation, { result: "rejected" });
        await journal.setStatus(o.operation, "abandoned");
        await o.secrets.delete(pairingSecretRef(Jid));
        return { kind: "rejected" };
      }
      await o.secrets.delete(pairingSecretRef(Jid));
    }
    if (op.intent.result === "rejected") return { kind: "rejected" };
    const digest = hash32(fromHex(op.intent.digest as string));
    const candidates = (op.intent.candidates as Candidate[]).map((c) => ({
      resource: resourceId(fromHex(c.resource)),
      url: c.url,
    }));
    // A personal B is registered in I itself; a service B only in its candidates.
    const places =
      kind === 0 ? [{ resource: I, url: op.intent.url as string }, ...candidates] : candidates;

    let certificate: CertificateChain | null =
      op.intent.certificate === undefined
        ? null
        : certificateChain(
            (op.intent.certificate as string[]).map((c) => parseDeviceCertificate(fromHex(c))),
            R,
          );
    let foreign = 0;
    const seen = new Map<
      string,
      { chain: LinearChain } | "unreachable" | "unsupported" | "closed"
    >();
    for (const p of places) {
      try {
        const channel = await pool.get(B, p.url);
        if (!channel.extensions.includes(IDENTITY_EXTENSION)) {
          seen.set(toHex(p.resource), "unsupported");
          continue;
        }
        const chain = await syncChain(o.storage, channel, p.resource);
        seen.set(toHex(p.resource), { chain });
        for (const leaf of leavesOf(chain, D)) {
          if (!bytesEqual(leaf.leaf.payloadDigest, digest)) {
            foreign++;
            continue;
          }
          // The first verified certificate decides (§5.3 step 8).
          if (
            certificate === null &&
            bytesEqual(leaf.root, R) &&
            bytesEqual(leaf.leaf.payload.root, R) &&
            bytesEqual(leaf.leaf.payload.device.principalId, D)
          ) {
            certificate = leaf;
            op = await journal.updateIntent(o.operation, {
              certificate: leaf.certificates.map((c) => toHex(c.signed.bytes)),
            });
            if (kind === 0) await setLocalIdentityResource(o.storage, I);
          }
        }
      } catch (e) {
        if (e instanceof IdentityUnavailable) seen.set(toHex(p.resource), "unreachable");
        else if (e instanceof IdentityRefused) seen.set(toHex(p.resource), "closed");
        else if (e instanceof IdentityConflict) seen.set(toHex(p.resource), "unreachable");
        else throw e;
      }
    }
    if (certificate === null)
      // "approved, waiting for registration": no candidate's outcome is known yet.
      return { kind: "approved", certificate: null, candidates: [], foreignCertificates: foreign };

    const result = certificate.leaf.payload;
    const out: CandidateResult[] = [];
    for (const p of places) {
      const s = seen.get(toHex(p.resource));
      const status = async (): Promise<CandidateStatus> => {
        if (
          result.kind !== DEVICE_KIND.PERSONAL &&
          !result.scope.some((r) => bytesEqual(r, p.resource))
        )
          return bytesEqual(p.resource, I) ? "pending-registration" : "not-granted";
        if (s === "unreachable" || s === undefined) return "unreachable";
        if (s === "unsupported") return "unsupported";
        if (s === "closed") return "pending-registration";
        const evidence = candidateEvidence(s.chain, D, digest, result);
        if (evidence.registration === "pending") return "pending-registration";
        if (!evidence.usable) return "unproven";
        const channel = await pool.get(B, p.url);
        const deks = await fetchDeks(o.storage, o.secrets, channel, s.chain, o.installation);
        return [...s.chain.state.epochs.keys()].every((e) => deks.has(e))
          ? "ready"
          : "waiting-for-keys";
      };
      try {
        out.push({ resource: p.resource, status: await status() });
      } catch (e) {
        if (e instanceof IdentityUnavailable || e instanceof IdentityRefused)
          out.push({ resource: p.resource, status: "unreachable" });
        else throw e;
      }
    }
    if (out.every((c) => c.status === "ready" || c.status === "not-granted"))
      await journal.setStatus(o.operation, "done");
    return {
      kind: "approved",
      certificate,
      candidates: Object.freeze(out),
      foreignCertificates: foreign,
    };
  } catch (e) {
    if (e instanceof IdentityUnavailable || e instanceof IdentityConflict)
      return { kind: "unavailable", reason: e.message };
    throw e;
  } finally {
    pool.closeAll();
  }
}
