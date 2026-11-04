import {
  bytesEqual,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { generateAgreementKeyPair, generateSigningKeyPair } from "@openlfcp/crypto";
import type { SecretStore } from "@openlfcp/storage";
import {
  activeDevice,
  authorizeDeviceGrant,
  type CertificateChain,
  type ControlState,
  certificateChain,
  checkDeviceCertificatePayload,
  DEVICE_ABILITY,
  DEVICE_KIND,
  type DeviceCertificate,
  type DeviceCertificatePayload,
  type DeviceKind,
  newDeviceCertificateSerial,
  ownerAction,
  type PrincipalDescriptor,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  signDeviceCertificate,
  validateControlChain,
} from "@openlfcp/wire";
import {
  deliverKeys,
  fetchDeks,
  IdentityConflict,
  type IdentityStorage,
  type Installation,
  type KeyDelivery,
  runControlPhase,
} from "./context.js";
import { newOperationId, OperationJournal, PackageLedger } from "./journal.js";
import {
  ChannelPool,
  IDENTITY_EXTENSION,
  type IdentityNetwork,
  IdentityRefused,
  IdentityUnavailable,
} from "./network.js";
import { classifyRegister, type LinearChain } from "./phases.js";

/** The mask presets of IDENTITY-PROFILE-01 §5.4 (decision I6). Codes 9 and 11 are never listed. */
export const MASK_PRESETS = Object.freeze({
  full: Object.freeze({
    kind: DEVICE_KIND.PERSONAL,
    mask: [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 10n, 12n, 13n],
  }),
  edit: Object.freeze({ kind: DEVICE_KIND.PERSONAL, mask: [1n, 2n, 3n] }),
  read: Object.freeze({ kind: DEVICE_KIND.PERSONAL, mask: [1n] }),
  service: Object.freeze({ kind: DEVICE_KIND.SERVICE, mask: [1n, 2n] }),
} as const);
export type MaskPreset = keyof typeof MASK_PRESETS;

/** What every identity flow needs of the installation. */
export interface FlowOptions {
  readonly installation: Installation;
  readonly storage: IdentityStorage;
  readonly secrets: SecretStore;
  readonly network: IdentityNetwork;
  readonly now: () => number;
}

const hasCode = (mask: readonly bigint[], code: bigint) => mask.includes(code);

/**
 * The certificates above a leaf that `issuer` signs for `root` in the
 * state: none when the issuer is the root, else the issuer's own current
 * chain, which must be active there (W §7.3 (c3), §17.4 rule 6).
 */
export function issuerCertificates(
  state: ControlState,
  issuer: PrincipalId,
  root: PrincipalId,
): readonly DeviceCertificate[] | undefined {
  if (bytesEqual(issuer, root)) return [];
  const d = activeDevice(state, issuer);
  if (d === undefined || d.chain === null || !bytesEqual(d.root, root)) return undefined;
  return d.chain.certificates;
}

/** A leaf payload for `device` with a fresh serial (W §7.3). */
export function leafPayload(
  root: PrincipalId,
  device: PrincipalDescriptor,
  kind: DeviceKind,
  mask: readonly bigint[],
  scope: readonly ResourceId[],
): DeviceCertificatePayload {
  return Object.freeze({
    root,
    device,
    kind,
    mask: Object.freeze([...mask].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))),
    scope: Object.freeze([...scope]),
    serial: newDeviceCertificateSerial(),
  });
}

/** An Ed25519/X25519 Principal used only to give a not-yet-signed leaf a certificate shape. */
function placeholderSigner(): Signer {
  const key = generateSigningKeyPair();
  return { key, descriptor: principalDescriptorFromKeys(key, generateAgreementKeyPair()) };
}

export type Feasibility =
  | { readonly feasible: true }
  | { readonly feasible: false; readonly reason: string };

/**
 * IDENTITY-PROFILE-01 §5.3 step 4: whether the DEVICE_GRANT that would
 * register (or bind) `leaf` through `issuer` would be accepted by the
 * Resource's current state, before anything is committed or signed for
 * the device (N9). The complete future chain is built with the leaf's
 * signature taken as given (a placeholder never leaves this function) and
 * checked with the validators' own rules: structure (kind, mask, scope,
 * c1, c5, c7), c3 and c4 against the issuer's chain, and W §17.4 rules 4
 * to 8 on the state after `consume` when a pairing session is given (its
 * device then counts as revoked, rule 8), else on the current state.
 */
export function checkIssuance(options: {
  readonly chain: LinearChain;
  readonly issuer: Signer;
  readonly leaf: DeviceCertificatePayload;
  /** The pairing device whose consume precedes the grant (§5.3 step 5). */
  readonly pairing?: PrincipalId;
}): Feasibility {
  const { chain, issuer, leaf } = options;
  const root = leaf.root;
  const no = (reason: string): Feasibility => ({ feasible: false, reason });
  const issuers = issuerCertificates(chain.state, issuer.descriptor.principalId, root);
  if (issuers === undefined) return no("the issuer is not the root or an active device of it");
  let future: CertificateChain;
  try {
    checkDeviceCertificatePayload(leaf);
    future = certificateChain([signDeviceCertificate(leaf, placeholderSigner()), ...issuers], root);
  } catch (e) {
    if (e instanceof LfcpError) return no(e.message);
    throw e;
  }
  let state = chain.state;
  if (options.pairing !== undefined) {
    const consume = signControlRecord(
      { resourceId: state.resourceId, controlSeq: state.seq + 1n, prevControlId: state.head },
      {
        type: "DEVICE_REVOKE",
        root,
        device: options.pairing,
        reason: 3n,
        approval: future.leaf.payloadDigest,
      },
      issuer,
    );
    const after = validateControlChain([
      ...chain.records.map((r) => r.signed.bytes),
      consume.bytes,
    ]);
    if (after.kind !== "linear")
      return no(
        `the session cannot be consumed by this issuer (${after.kind === "invalid" ? after.error.message : after.kind})`,
      );
    state = after.state;
  }
  const a = authorizeDeviceGrant(state, issuer.descriptor.principalId, {
    type: "DEVICE_GRANT",
    root,
    chain: future,
    ...(options.pairing === undefined ? {} : { pairingDevice: options.pairing }),
  });
  return a.allowed ? { feasible: true } : no(a.reason);
}

/** Signs `leaf` through `issuer` and returns the complete chain (§5.3 step 6). */
export function signChain(
  state: ControlState,
  issuer: Signer,
  leaf: DeviceCertificatePayload,
): CertificateChain {
  const issuers = issuerCertificates(state, issuer.descriptor.principalId, leaf.root);
  if (issuers === undefined)
    throw new LfcpError(
      "AUTHORIZATION_FAILED",
      "the issuer is not the root or an active device of it",
    );
  return certificateChain([signDeviceCertificate(leaf, issuer), ...issuers], leaf.root);
}

/**
 * Whether `actor` may propose device records for `root`'s devices in the
 * Resource (§5.3 step 10, §7.1): it is the root, an active device of the
 * root with `12`, or, when the root owns the Resource, an active device
 * with `13`.
 */
export function mayManageDevices(
  state: ControlState,
  actor: PrincipalId,
  root: PrincipalId,
): boolean {
  if (bytesEqual(actor, root)) return true;
  const d = activeDevice(state, actor);
  if (d === undefined || !bytesEqual(d.root, root)) return false;
  if (hasCode(d.mask, DEVICE_ABILITY.DEVICE_MANAGE)) return true;
  return bytesEqual(state.owner.principalId, root) && ownerAction(state, actor);
}

/** Where a device registration ended in one Resource. */
export type RegistrationStatus =
  /** The record is committed (or the effect already existed); keys follow. */
  | "registered"
  /** The leaf or an issuer is revoked there: never registered (§9.2 superseded). */
  | "superseded"
  /** The Resource refused the record (reported, not repeated, §7.1). */
  | "refused"
  /** This installation may not act there (§5.3 step 10): left to reconciliation. */
  | "not-authorized"
  /** The coordinator does not advertise identity-01 (W §37). */
  | "unsupported"
  /** The coordinator could not be reached: left to reconciliation. */
  | "unreachable"
  /** The Resource is forked (§9.7). */
  | "conflict";

export interface RegistrationResult {
  readonly resource: ResourceId;
  readonly status: RegistrationStatus;
  readonly code?: string;
  readonly keys?: KeyDelivery;
}

export interface RegisterTarget {
  readonly resource: ResourceId;
  /** The coordinator URL (the roster entry's coordinator, or the chain's route). */
  readonly url: string;
}

/**
 * Registers a device in Resources (§5.3 step 10, §7.2, §7.3, §7.1 step
 * 2): `DEVICE_GRANT {R, chain}` on each target where this installation may
 * act, then a Key Package of every epoch DEK it holds there to the device,
 * each recorded in the ledger. One journaled operation; each Resource is
 * a phase classified by §9.2 before anything is proposed, so a
 * registration that exists by another hand is `complete` and is not
 * proposed again. Resources this installation cannot reach are listed.
 */
export async function registerDevice(
  options: FlowOptions & {
    readonly chain: CertificateChain;
    readonly targets: readonly RegisterTarget[];
    /** Resume this operation instead of starting one. */
    readonly operation?: string;
  },
): Promise<{ readonly operation: string; readonly results: readonly RegistrationResult[] }> {
  const journal = new OperationJournal(options.storage);
  const ledger = new PackageLedger(options.storage);
  const device = options.chain.leaf.payload.device;
  const root = options.chain.root;
  const operation = options.operation ?? newOperationId("register-device", secureRandom(8));
  if ((await journal.get(operation)) === undefined)
    await journal.begin({
      id: operation,
      kind: "register-device",
      createdAt: options.now(),
      intent: {
        device: toHex(device.principalId),
        root: toHex(root),
        leaf: toHex(options.chain.leaf.id),
        targets: options.targets.map((t) => ({ resource: toHex(t.resource), url: t.url })),
      },
    });
  const pool = new ChannelPool(options.network);
  const results: RegistrationResult[] = [];
  const me = options.installation.signer;
  try {
    for (const t of options.targets) {
      const result = (status: RegistrationStatus, extra: Partial<RegistrationResult> = {}) =>
        results.push(Object.freeze({ resource: t.resource, status, ...extra }));
      try {
        const channel = await pool.get(me, t.url);
        if (!channel.extensions.includes(IDENTITY_EXTENSION)) {
          result("unsupported");
          continue;
        }
        const outcome = await runControlPhase(options.storage, channel, journal, operation, {
          id: `register:${toHex(t.resource)}`,
          kind: "register",
          resource: t.resource,
          classify: (chain, isOwn) => {
            const s = classifyRegister(chain, { root, chain: options.chain, isOwnRecord: isOwn });
            if (s === "pending" && !mayManageDevices(chain.state, me.descriptor.principalId, root))
              throw new NotAuthorizedHere();
            return s;
          },
          build: (chain) =>
            signControlRecord(
              {
                resourceId: t.resource,
                controlSeq: chain.state.seq + 1n,
                prevControlId: chain.state.head,
              },
              { type: "DEVICE_GRANT", root, chain: options.chain },
              me,
            ).bytes,
        });
        if (outcome.state === "superseded") {
          result("superseded");
          continue;
        }
        if (outcome.state === "refused") {
          result("refused", { code: outcome.code ?? "refused" });
          continue;
        }
        const deks = await fetchDeks(
          options.storage,
          options.secrets,
          channel,
          outcome.chain,
          options.installation,
        );
        const keys = await deliverKeys({
          channel,
          ledger,
          chain: outcome.chain,
          sender: me,
          recipients: [device],
          deks,
        });
        result("registered", { keys });
      } catch (e) {
        if (e instanceof NotAuthorizedHere) result("not-authorized");
        else if (e instanceof IdentityUnavailable) result("unreachable");
        else if (e instanceof IdentityRefused) result("not-authorized", { code: e.code });
        else if (e instanceof IdentityConflict) result("conflict");
        else throw e;
      }
    }
  } finally {
    pool.closeAll();
  }
  const open = results.some((r) => r.status === "unreachable" || r.status === "conflict");
  await journal.setStatus(operation, open ? "open" : "done");
  return Object.freeze({ operation, results: Object.freeze(results) });
}

class NotAuthorizedHere extends Error {}
