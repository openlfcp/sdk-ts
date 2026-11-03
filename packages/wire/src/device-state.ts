import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type Hash32,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { ABILITY, type Authorization, isGrantActive } from "./capability.js";
import type { ControlState } from "./chain.js";
import type { ControlRecord } from "./control.js";
import {
  type CertificateChain,
  type ChainStateChecks,
  checkChainAuthority,
  checkChainState,
  DEVICE_ABILITY,
  DEVICE_KIND,
  type DeviceCertificatePayload,
  type DeviceKind,
} from "./device.js";
import { PersistentMap, put } from "./persistent-map.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Resource-local device state and its transitions (LFCP-WIRE-01 §7.3,
 * §17.4, §17.5, §79, §80.1). Every answer is a pure function of the
 * Resource's accepted Control Chain (N3): no clock, no server table, no
 * Identity Resource, no other Resource.
 *
 * A chain without device records has no bindings, so `bound` is false for
 * every Principal and every question here reduces to §80.
 */

/** §79: a Principal's role in a Resource; assigned once, never changed. */
export type DeviceRole = "device" | "non-device";

/** §79 `Binding`: what an accepted chain fixed for a device in this Resource. */
export interface DeviceBinding {
  readonly root: PrincipalId;
  readonly kind: DeviceKind;
  /** The certificate's codes, unknown ones included; immutable, compared as a set (N8). */
  readonly mask: readonly bigint[];
  /** Immutable, compared as a set (N8). */
  readonly scope: readonly ResourceId[];
  /** Leaf of an accepted DEVICE_GRANT whose scope admits this Resource, of Genesis field 5 or of commit field 2. */
  readonly registered: boolean;
  /** The chain of the latest accepted record whose leaf this device is; null for an intermediate only. */
  readonly chain: CertificateChain | null;
  /** The certificate ID of that chain's leaf. */
  readonly leafId: Hash32 | null;
  /** Device IDs of `chain[1..]`, nearest first; empty when the root issued the leaf. */
  readonly issuers: readonly PrincipalId[];
  /** Accepted DEVICE_GRANT records whose leaf this device is (§17.4 rule 8: at most 8). */
  readonly grantsAccepted: number;
}

/** §79 `Revocation` of an exact (root, device) pair; permanent (N5). */
export interface DeviceRevocation {
  readonly root: PrincipalId;
  readonly device: PrincipalId;
  /** As received; 4 and above are kept (§17.5). */
  readonly reason: bigint;
  /** The approved certificate payload digest, exactly for reason 3. */
  readonly approval: Hash32 | null;
  /** The DEVICE_REVOKE record. */
  readonly revokedBy: ControlRecordId;
}

/** The device part of ControlState (§79). */
export interface DeviceState {
  /** Roles by Principal ID hex. */
  readonly roles: ReadonlyMap<string, DeviceRole>;
  /** Bindings by device ID hex: leaves, intermediates, suspended and revoked devices. */
  readonly devices: ReadonlyMap<string, DeviceBinding>;
  /** Revocations by `revocationKey(root, device)`. */
  readonly revoked: ReadonlyMap<string, DeviceRevocation>;
  /**
   * §17.4 rule 8, by root ID hex: the live Principals bound to the root,
   * entries of `devices` whose pair is not in `revoked`. Every binding path
   * adds (Genesis, transfer, Device Grant); a direct revocation releases.
   */
  readonly liveBound: ReadonlyMap<string, number>;
  /** §17.5 rule 5, by root ID hex: revoked pairs (R, E) with `devices[E]` absent. */
  readonly preemptive: ReadonlyMap<string, number>;
  /** By device ID hex: the roots (hex) that revoked it while it was unbound. */
  readonly preemptiveRoots: ReadonlyMap<string, ReadonlyMap<string, true>>;
}

export const EMPTY_DEVICE_STATE: DeviceState = Object.freeze({
  roles: PersistentMap.empty<DeviceRole>(),
  devices: PersistentMap.empty<DeviceBinding>(),
  revoked: PersistentMap.empty<DeviceRevocation>(),
  liveBound: PersistentMap.empty<number>(),
  preemptive: PersistentMap.empty<number>(),
  preemptiveRoots: PersistentMap.empty<ReadonlyMap<string, true>>(),
});

/** §17.4 rule 8: live Principals bound to one root in a Resource. */
export const MAX_LIVE_BOUND = 32;
/** §17.4 rule 8: accepted Device Grants per (root, leaf) pair. */
export const MAX_DEVICE_GRANTS = 8;
/** §17.5 rule 5: pre-emptive revocations of unbound Principals per root. */
export const MAX_PREEMPTIVE_REVOCATIONS = 64;

const count = (map: ReadonlyMap<string, number>, key: string) => map.get(key) ?? 0;

/** The key of `revoked` for the pair (root, device). */
export const revocationKey = (root: PrincipalId, device: PrincipalId): string =>
  `${toHex(root)}:${toHex(device)}`;

const hasCode = (mask: readonly bigint[], code: bigint) => mask.includes(code);

/** `bound(P)` (§80.1): P appeared as a device, at any level, in an accepted chain. */
export const isBound = (state: ControlState, p: PrincipalId): boolean =>
  state.devices.has(toHex(p));

/** `revoked[(root, device)]`, if any. */
export const revocationOf = (
  state: ControlState,
  root: PrincipalId,
  device: PrincipalId,
): DeviceRevocation | undefined => state.revoked.get(revocationKey(root, device));

const isOwner = (state: ControlState, p: PrincipalId): boolean =>
  bytesEqual(state.owner.principalId, p);

/**
 * `rootStanding(R)` (§17.5): R is the owner, or the subject of at least one
 * active grant that does not list `invite/claim`.
 */
export function rootStanding(state: ControlState, root: PrincipalId): boolean {
  if (isOwner(state, root)) return true;
  for (const g of state.grants.values())
    if (
      bytesEqual(g.subject, root) &&
      !g.abilities.includes(ABILITY.INVITE_CLAIM) &&
      isGrantActive(state, g.id)
    )
      return true;
  return false;
}

/**
 * `activeDevice(P)` (§17.5): registered, `(root, P)` not revoked, no
 * revoked issuer in its current chain (the cascade), and its root in good
 * standing. Undefined otherwise.
 */
export function activeDevice(state: ControlState, p: PrincipalId): DeviceBinding | undefined {
  const d = state.devices.get(toHex(p));
  if (d === undefined || !d.registered) return undefined;
  if (revocationOf(state, d.root, p) !== undefined) return undefined;
  if (d.issuers.some((e) => revocationOf(state, d.root, e) !== undefined)) return undefined;
  return rootStanding(state, d.root) ? d : undefined;
}

/** `actsFor(P)` (§80.1): the root of an active device, else P itself. */
export const actsFor = (state: ControlState, p: PrincipalId): PrincipalId =>
  activeDevice(state, p)?.root ?? p;

/**
 * `rootOf(P)` (§80.1): the root of a bound P (registered, suspended,
 * revoked or intermediate), else P itself. For attribution, never for
 * authority.
 */
export const rootOf = (state: ControlState, p: PrincipalId): PrincipalId =>
  state.devices.get(toHex(p))?.root ?? p;

/**
 * `ownerAction(P)` (§80.1): for a bound P, an active device of the owner
 * with `owner/act` in its mask; otherwise P is the owner.
 */
export function ownerAction(state: ControlState, p: PrincipalId): boolean {
  if (!isBound(state, p)) return isOwner(state, p);
  const d = activeDevice(state, p);
  return d !== undefined && isOwner(state, d.root) && hasCode(d.mask, DEVICE_ABILITY.OWNER_ACT);
}

/**
 * The descriptor a transfer offer with `kid` is verified under (§62 class
 * 4, §23.3): the kid's, when it is the owner or a device bound to the
 * owner, active or not. Any other kid, known here or not, is neither a
 * dependency nor signature-checked: the offer fails §23.3 item 1 in the
 * authority class (ownerAction), AUTHORIZATION_FAILED.
 */
export function offerSigner(
  state: ControlState,
  kid: PrincipalId,
): PrincipalDescriptor | undefined {
  if (isOwner(state, kid)) return state.owner;
  const d = state.devices.get(toHex(kid));
  return d !== undefined && isOwner(state, d.root) ? state.principals.get(toHex(kid)) : undefined;
}

/** `sameRoot(a, b)` (§25.2): the same `actsFor`, and at least one of them an active device. */
export const sameRoot = (state: ControlState, a: PrincipalId, b: PrincipalId): boolean =>
  bytesEqual(actsFor(state, a), actsFor(state, b)) &&
  (activeDevice(state, a) !== undefined || activeDevice(state, b) !== undefined);

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && new Set([...a, ...b]).size === new Set(a).size;

/** §7.3 step 4.2–4.4 against `state`, for verifyChain. */
export function deviceChainChecks(state: ControlState): ChainStateChecks {
  return {
    rootAllowed: (root) => state.roles.get(toHex(root)) !== "device",
    bindingMatches: (p: DeviceCertificatePayload) => {
      const id = toHex(p.device.principalId);
      if (state.roles.get(id) === "non-device") return false;
      const d = state.devices.get(id);
      return (
        d === undefined ||
        (bytesEqual(d.root, p.root) &&
          d.kind === p.kind &&
          sameSet(d.mask.map(String), p.mask.map(String)) &&
          sameSet(d.scope.map(toHex), p.scope.map(toHex)))
      );
    },
    isRevoked: (root, device) => revocationOf(state, root, device) !== undefined,
  };
}

// ---------------------------------------------------------------------------
// Authority (class 5 of §62), after every dependency and signature

const ALLOW: Authorization = Object.freeze({ allowed: true });
const deny = (reason: string): Authorization => Object.freeze({ allowed: false, reason });

/** (c3), (c4), (c6) then step 4.2–4.4 of verifyChain at `state`; `inScope` on success. */
function chainAuthority(
  state: ControlState,
  chain: CertificateChain,
): Authorization | { readonly allowed: true; readonly inScope: boolean } {
  const intrinsic = checkChainAuthority(chain, state.resourceId);
  if (!intrinsic.valid) return deny(intrinsic.reason);
  const s = checkChainState(chain, deviceChainChecks(state));
  if (!s.valid) return deny(s.reason);
  return { allowed: true, inScope: intrinsic.inScope };
}

/**
 * The device chain of a Genesis (field 5) or a transfer commit (field 2):
 * verifyChain step 4 at `state`, then the leaf is a personal device with
 * `owner/act` (§15, §23.3).
 */
export function authorizeOwnerChain(state: ControlState, chain: CertificateChain): Authorization {
  const a = chainAuthority(state, chain);
  if (!a.allowed) return a;
  const leaf = chain.leaf.payload;
  if (leaf.kind !== DEVICE_KIND.PERSONAL || !hasCode(leaf.mask, DEVICE_ABILITY.OWNER_ACT))
    return deny("the leaf is not a personal device with owner/act (§15, §23.3)");
  return ALLOW;
}

/** An active device of `root` with `device/manage`. */
const manages = (state: ControlState, issuer: PrincipalId, root: PrincipalId) => {
  const d = activeDevice(state, issuer);
  return (
    d !== undefined && bytesEqual(d.root, root) && hasCode(d.mask, DEVICE_ABILITY.DEVICE_MANAGE)
  );
};

type DeviceGrantBody = Extract<ControlRecord["body"], { type: "DEVICE_GRANT" }>;
type DeviceRevokeBody = Extract<ControlRecord["body"], { type: "DEVICE_REVOKE" }>;

/** §17.4 rules 4–7, in order (rules 1–3 are structure, dependencies and signatures). */
export function authorizeDeviceGrant(
  state: ControlState,
  issuer: PrincipalId,
  body: DeviceGrantBody,
): Authorization {
  const root = body.root;
  // Rule 4.
  if (!rootStanding(state, root)) return deny("the root has no standing (§17.4 rule 4)");
  // Rule 5: verifyChain step 4, then a repeated leaf certificate is not a transition.
  const a = chainAuthority(state, body.chain);
  if (!a.allowed) return a;
  const leaf = body.chain.leaf;
  const leafId = leaf.payload.device.principalId;
  const existing = state.devices.get(toHex(leafId));
  if (
    existing?.leafId !== null &&
    existing?.leafId !== undefined &&
    bytesEqual(existing.leafId, leaf.id)
  )
    return deny("the leaf certificate is already the device's current one (§17.4 rule 5)");
  // Rule 6. A personal device submits only its first registration: once
  // it has a chain it never re-certifies itself, not even with device/manage
  // or owner/act, so a device suspended by the cascade waits for the root
  // or another managing device (spec#2 7d75f7d).
  const personal = leaf.payload.kind === DEVICE_KIND.PERSONAL;
  const self = personal && bytesEqual(issuer, leafId);
  if (self && existing !== undefined && existing.chain !== null)
    return deny("a registered device never re-certifies itself (§17.4 rule 6)");
  const allowed =
    bytesEqual(issuer, root) ||
    self ||
    (personal && body.chain.issuers.some((e) => bytesEqual(e, issuer))) ||
    manages(state, issuer, root) ||
    (isOwner(state, root) && ownerAction(state, issuer));
  if (!allowed) return deny("the issuer may not bind or register this device (§17.4 rule 6)");
  // Rule 7.
  if (body.pairingDevice !== undefined) {
    const session = state.devices.get(toHex(body.pairingDevice));
    const consumed = revocationOf(state, root, body.pairingDevice);
    if (
      session === undefined ||
      session.kind !== DEVICE_KIND.PAIRING ||
      !bytesEqual(session.root, root) ||
      consumed === undefined ||
      consumed.reason !== 3n ||
      consumed.approval === null ||
      !bytesEqual(consumed.approval, leaf.payloadDigest)
    )
      return deny("no consumed pairing approval names this leaf (§17.4 rule 7)");
  }
  // Rule 8 (spec#2 bc03b0f): live bindings per root, grants per pair.
  const fresh = body.chain.certificates.filter(
    (c) => !state.devices.has(toHex(c.payload.device.principalId)),
  ).length;
  if (count(state.liveBound, toHex(root)) + fresh > MAX_LIVE_BOUND)
    return deny(
      `more than ${MAX_LIVE_BOUND} live devices would be bound to the root (§17.4 rule 8)`,
    );
  if ((existing?.grantsAccepted ?? 0) >= MAX_DEVICE_GRANTS)
    return deny(
      `the device has had ${MAX_DEVICE_GRANTS} Device Grants for its root (§17.4 rule 8)`,
    );
  return ALLOW;
}

/** §17.5 rules 3–5, in order. */
export function authorizeDeviceRevoke(
  state: ControlState,
  issuer: PrincipalId,
  body: DeviceRevokeBody,
): Authorization {
  const { root, device } = body;
  const binding = state.devices.get(toHex(device));
  // Rule 3: consistency.
  if (binding !== undefined && !bytesEqual(binding.root, root))
    return deny("the device is bound to another root (§17.5 rule 3)");
  if (state.roles.get(toHex(device)) === "non-device")
    return deny("the device is a non-device Principal here (§17.5 rule 3)");
  if (state.roles.get(toHex(root)) === "device")
    return deny("the root is bound as a device here (§17.5 rule 3)");
  if (body.reason === 3n && binding?.kind !== DEVICE_KIND.PAIRING)
    return deny("only a bound pairing device is consumed (§17.5 rule 3)");
  // Rule 4.
  const existing = revocationOf(state, root, device) !== undefined;
  const allowed =
    (bytesEqual(issuer, root) && rootStanding(state, root)) ||
    manages(state, issuer, root) ||
    ownerAction(state, issuer) ||
    (bytesEqual(issuer, device) && body.reason === 0n && binding?.registered === true && !existing);
  if (!allowed) return deny("the issuer may not revoke this device (§17.5 rule 4)");
  // Rule 5 (spec#2 bc03b0f): only a pre-emptive revocation is limited.
  if (existing) return deny("the pair is already revoked (§17.5 rule 5)");
  if (binding === undefined && count(state.preemptive, toHex(root)) >= MAX_PREEMPTIVE_REVOCATIONS)
    return deny(
      `the root has ${MAX_PREEMPTIVE_REVOCATIONS} revocations of unbound Principals (§17.5 rule 5)`,
    );
  return ALLOW;
}

// ---------------------------------------------------------------------------
// Effects (applyRecord)

/** The device part of a state, with the descriptors bindChain records. */
type BindingState = DeviceState & Pick<ControlState, "principals">;

/**
 * Binds every device of an accepted chain to its root and records the
 * leaf's chain (§17.4 rule 9, §15, §23.3). Intermediates keep their own
 * registration and current chains. `keepSameLeaf`: a transfer commit
 * leaves a leaf registered with the same certificate ID unchanged.
 * `grant`: a Device Grant, which counts towards its leaf's eight.
 */
export function bindChain(
  state: BindingState,
  chain: CertificateChain,
  inScope: boolean,
  keepSameLeaf: boolean,
  grant = false,
): BindingState {
  let { roles, devices, principals, liveBound, preemptive } = state;
  for (const c of chain.certificates) {
    const p = c.payload;
    const id = toHex(p.device.principalId);
    if (!devices.has(id)) {
      devices = put(
        devices,
        id,
        Object.freeze({
          root: p.root,
          kind: p.kind,
          mask: p.mask,
          scope: p.scope,
          registered: false,
          chain: null,
          leafId: null,
          issuers: Object.freeze([]),
          grantsAccepted: 0,
        }),
      );
      // A chain never holds a revoked pair (§7.3 step 4): the binding is live.
      liveBound = put(liveBound, toHex(p.root), count(liveBound, toHex(p.root)) + 1);
      // Its pre-emptive revocations no longer count: it is bound now.
      for (const r of state.preemptiveRoots.get(id)?.keys() ?? [])
        preemptive = put(preemptive, r, count(preemptive, r) - 1);
    }
    if (roles.get(id) !== "device") roles = put(roles, id, "device");
    if (principals.get(id) !== p.device) principals = put(principals, id, p.device);
  }
  const leafKey = toHex(chain.leaf.payload.device.principalId);
  const leaf = devices.get(leafKey) as DeviceBinding;
  const grantsAccepted = leaf.grantsAccepted + (grant ? 1 : 0);
  if (
    keepSameLeaf &&
    leaf.registered &&
    leaf.leafId !== null &&
    bytesEqual(leaf.leafId, chain.leaf.id)
  ) {
    if (grant) devices = put(devices, leafKey, Object.freeze({ ...leaf, grantsAccepted }));
  } else
    devices = put(
      devices,
      leafKey,
      Object.freeze({
        ...leaf,
        chain,
        leafId: chain.leaf.id,
        issuers: chain.issuers,
        registered: leaf.registered || inScope,
        grantsAccepted,
      }),
    );
  return { ...state, roles, devices, principals, liveBound, preemptive };
}

/** The in-scope result of an accepted DEVICE_GRANT's chain at the state it was accepted on. */
export const grantInScope = (state: ControlState, body: DeviceGrantBody): boolean => {
  const a = checkChainAuthority(body.chain, state.resourceId);
  return a.valid && a.inScope;
};

/**
 * Records the revocation of an accepted DEVICE_REVOKE (§17.5 rule 6): a
 * bound device releases its live place (§17.4 rule 8), an unbound one
 * spends one of the root's pre-emptive revocations (§17.5 rule 5).
 */
export function recordRevocation(
  state: DeviceState,
  record: ControlRecord,
  body: DeviceRevokeBody,
): Pick<DeviceState, "revoked" | "liveBound" | "preemptive" | "preemptiveRoots"> {
  const root = toHex(body.root);
  const device = toHex(body.device);
  const revoked = put(
    state.revoked,
    revocationKey(body.root, body.device),
    Object.freeze({
      root: body.root,
      device: body.device,
      reason: body.reason,
      approval: body.approval ?? null,
      revokedBy: controlRecordId(record.signed.id),
    }),
  );
  if (state.devices.has(device))
    return {
      revoked,
      liveBound: put(state.liveBound, root, count(state.liveBound, root) - 1),
      preemptive: state.preemptive,
      preemptiveRoots: state.preemptiveRoots,
    };
  return {
    revoked,
    liveBound: state.liveBound,
    preemptive: put(state.preemptive, root, count(state.preemptive, root) + 1),
    preemptiveRoots: put(
      state.preemptiveRoots,
      device,
      put(state.preemptiveRoots.get(device) ?? PersistentMap.empty<true>(), root, true),
    ),
  };
}

/** Assigns the `non-device` role (§79). */
export function nonDevice(roles: ReadonlyMap<string, DeviceRole>, p: PrincipalId) {
  return put(roles, toHex(p), "non-device");
}
