import { dataEpoch, hash32, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode, isCborMap } from "../src/cbor/index.js";
import {
  ABILITY,
  activeDevice,
  actsFor,
  canDistributeKey,
  DEVICE_KIND,
  decodeControlRecord,
  deviceCertificatePayloadDigest,
  hasAbility,
  isBound,
  ownerAction,
  revocationOf,
  rootOf,
  rootStanding,
  sameRoot,
  signObject,
  validateControlChain,
} from "../src/index.js";
import { PersistentMap } from "../src/persistent-map.js";
import { id, keys, RESOURCE } from "./identity.js";
import {
  capabilityGrant,
  chainOf,
  deviceGrant,
  devicePayload,
  Fixture,
  FULL,
  genesis,
  issue,
  personalCert,
  recordAt,
  revokeDevice,
  revokeGrant,
  transferBody,
} from "./identity-fixture.js";

// Resource-local device authority (LFCP-WIRE-01 §7.3, §15, §17.2–§17.5,
// §18.1, §23.3, §25.2, §79, §80.1). Each test ports the sdk-rs test of
// crates/lfcp/tests/identity_authority.rs named in its title (branch
// identity-authority, openlfcp/sdk-rs#3) with the same inputs and verdicts.

const { PERSONAL, SERVICE, PAIRING } = DEVICE_KIND;
const same = (a: Uint8Array, b: Uint8Array) => toHex(a) === toHex(b);
const OWNER_LEAF = /personal device with owner\/act/;
const BINDING = /binding conflicts/;
const REPEAT = /already the device's current one/;
const STANDING = /no standing/;
const REVOKE_ISSUER = /may not revoke this device/;
const IS_DEVICE = /bound as a device/;
const REVOKED = /revoked for this root/;
const APPROVAL = /no consumed pairing approval/;
const ALREADY_REVOKED = /pair is already revoked/;
const DELEGATION = /outside the issuing device's mask/;
const GRANT_ISSUER = /may not bind or register/;

function invalidGenesis(record: { bytes: Uint8Array }) {
  const r = validateControlChain([record.bytes]);
  if (r.kind !== "invalid") throw new Error(`expected a refusal, got ${r.kind}`);
  return `${r.wireCode}: ${r.error.message}`;
}

describe("Genesis by a device of the owner (§15)", () => {
  it("requires the leaf's signature and owner/act (genesis_device_requires_leaf_signature_and_owner_act)", () => {
    const certificates = chainOf([personalCert(1, 2, [13], 1, 1)]);
    // The writer refuses a Genesis/5 not issued by its leaf; sign it as Rust does, raw.
    for (const signer of [1, 8]) {
      const raw = genesisRaw(1, signer, certificates);
      expect(invalidGenesis(raw)).toMatch(/^INVALID_SIGNATURE: /);
    }
    const f = new Fixture(genesis(1, 2, certificates));
    expect(same(f.state.owner.principalId, id(1))).toBe(true);
    expect(f.state.roles.get(toHex(id(1)))).toBe("non-device");
    expect(f.state.roles.get(toHex(id(2)))).toBe("device");
    expect(ownerAction(f.state, id(2))).toBe(true);
    expect(hasAbility(f.state, id(2), 1n)).toBe(true); // owner/act overrides the mask
    // §80.1: owner/act confers 1-10 only, never invite/claim (11).
    for (const code of [9n, 11n, 12n, 13n, 99n])
      expect(hasAbility(f.state, id(2), code)).toBe(false);
    for (const [kind, mask, scope] of [
      [PERSONAL, [1], []],
      [SERVICE, [1], [RESOURCE]],
      [PAIRING, [1, 2], [RESOURCE]],
    ] as const) {
      const c = chainOf([issue(devicePayload(1, 2, kind, mask, scope, 1), 1)]);
      expect(invalidGenesis(genesis(1, 2, c))).toMatch(
        new RegExp(`^AUTHORIZATION_FAILED: .*${OWNER_LEAF.source}`),
      );
    }
  });
});

describe("bindings, roles and activity (§17.4, §17.5, §79)", () => {
  it("learns every embedded issuer and intermediate, registers only the leaf (embedded_issuers_and_all_intermediates_are_learned_but_only_leaf_registered)", () => {
    for (const signer of [1, 2, 3]) {
      const f = new Fixture();
      const certificates = chainOf([
        personalCert(1, 3, [1, 2], 2, 3),
        personalCert(1, 2, FULL, 1, 2),
      ]);
      f.push(signer, deviceGrant(certificates));
      expect(activeDevice(f.state, id(3))).toBeDefined();
      expect(activeDevice(f.state, id(2))).toBeUndefined();
      expect(f.state.devices.get(toHex(id(2)))?.registered).toBe(false);
      expect(f.state.principals.has(toHex(id(2)))).toBe(true);
      expect(same(actsFor(f.state, id(3)), id(1))).toBe(true);
      expect(same(rootOf(f.state, id(2)), id(1))).toBe(true);
      expect(same(actsFor(f.state, id(2)), id(2))).toBe(true);
      // Becoming a leaf later registers the already bound intermediate.
      f.register(1, 2, FULL);
      expect(activeDevice(f.state, id(2))).toBeDefined();
      f.replay();
    }
  });

  it("compares masks and scopes as sets and keeps them immutable (masks_scope_and_binding_equality_are_sets_and_immutable)", () => {
    const f = new Fixture();
    f.register(1, 2, [1, 2, 99]);
    f.push(2, deviceGrant(chainOf([personalCert(1, 2, [99, 2, 1], 1, 4)])));
    f.denied(1, deviceGrant(chainOf([personalCert(1, 2, [1, 2, 3, 99], 1, 5)])), BINDING);
    f.denied(1, deviceGrant(chainOf([personalCert(1, 2, [1], 1, 5)])), BINDING);
    const other = resourceId(new Uint8Array(32).fill(78));
    const service = (scope: readonly Uint8Array[], serial: number) =>
      chainOf([
        issue(
          devicePayload(
            1,
            6,
            SERVICE,
            [1],
            scope.map((s) => resourceId(s)),
            serial,
          ),
          1,
        ),
      ]);
    f.push(1, deviceGrant(service([other, RESOURCE], 1)));
    f.push(1, deviceGrant(service([RESOURCE, other], 2)));
    f.denied(1, deviceGrant(service([RESOURCE], 3)), BINDING);
    const outside = new Fixture();
    outside.push(1, deviceGrant(service([other], 1)));
    expect(isBound(outside.state, id(6))).toBe(true);
    expect(outside.state.devices.get(toHex(id(6)))?.registered).toBe(false);
    expect(hasAbility(outside.state, id(6), ABILITY.DATA_READ)).toBe(false);
    outside.denied(1, deviceGrant(service([other], 1)), REPEAT);
    f.replay();
  });

  it("derives standing from non-invitation grants and restores devices without re-registration (root_standing_uses_non_invitation_grants_and_returns_without_reregistration)", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(10, [1, 2, 11], [], undefined, 0));
    const certs = chainOf([personalCert(10, 2, [1, 2], 10, 2)]);
    expect(rootStanding(f.state, id(10))).toBe(false);
    f.denied(10, deviceGrant(certs), STANDING);
    f.push(1, capabilityGrant(10, [1, 2]));
    const standingGrant = f.head;
    f.push(2, deviceGrant(certs));
    expect(hasAbility(f.state, id(2), 2n)).toBe(true);
    f.push(1, revokeGrant(standingGrant));
    expect(activeDevice(f.state, id(2))).toBeUndefined();
    expect(hasAbility(f.state, id(2), ABILITY.DATA_READ)).toBe(false);
    f.denied(10, revokeDevice(10, 2, 2), REVOKE_ISSUER);
    f.push(1, capabilityGrant(10, [1, 2]));
    expect(hasAbility(f.state, id(2), 2n)).toBe(true);
    f.replay();
  });

  it("keeps roles exclusive for subjects, claimants and transferees, also after revocation (role_exclusivity_survives_revocation_for_subject_claimant_and_transferee)", () => {
    const f = new Fixture();
    f.register(1, 2, [1, 2]);
    f.denied(1, capabilityGrant(2, [1]), IS_DEVICE);
    f.push(1, capabilityGrant(8, [1, 11], [], undefined, 1));
    const invite = f.head;
    f.denied(
      8,
      {
        type: "CAPABILITY_CLAIM",
        invitationGrantId: invite,
        claimant: keys(2).descriptor,
        abilities: [1n],
      },
      IS_DEVICE,
    );
    f.denied(2, transferBody(f.state, 2, 1, 2), IS_DEVICE);
    f.push(1, revokeDevice(1, 2, 2));
    f.denied(1, capabilityGrant(2, [1]), IS_DEVICE);
    // A revoked grant never frees the non-device role either.
    f.push(1, capabilityGrant(3, [1]));
    f.push(1, revokeGrant(f.head));
    f.denied(1, deviceGrant(chainOf([personalCert(1, 3, [1], 1, 3)])), BINDING);
    // The same exclusion for intermediate devices.
    f.denied(
      1,
      deviceGrant(chainOf([personalCert(1, 4, [1], 3, 4), personalCert(1, 3, FULL, 1, 3)])),
      BINDING,
    );
  });

  it("suspends through the cascade, restores by re-certification, never clears a revocation (cascade_recertification_keeps_bindings_but_never_clears_a_revocation)", () => {
    const f = new Fixture();
    f.push(
      1,
      deviceGrant(chainOf([personalCert(1, 3, [1, 2], 2, 3), personalCert(1, 2, FULL, 1, 2)])),
    );
    const before = f.state;
    f.push(1, revokeDevice(1, 2, 2)); // an intermediate-only manager suspends a reader
    expect(hasAbility(before, id(3), 2n)).toBe(true);
    expect(hasAbility(f.state, id(3), 2n)).toBe(false);
    expect(same(rootOf(f.state, id(3)), id(1))).toBe(true);
    f.push(3, deviceGrant(chainOf([personalCert(1, 3, [1, 2], 1, 9)])));
    expect(activeDevice(f.state, id(3))).toBeDefined();
    expect(f.state.devices.get(toHex(id(3)))?.issuers).toEqual([]);
    f.push(1, revokeDevice(1, 3, 2));
    f.denied(1, deviceGrant(chainOf([personalCert(1, 3, [1, 2], 1, 10)])), REVOKED);
    f.replay();
  });

  it("refuses revocations in rule order: consistency, issuer, duplicate (revocation_consistency_issuer_and_duplicate_rules_run_in_order)", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(10, [1]));
    f.register(10, 2, FULL);
    f.register(10, 3, [1]);
    f.register(1, 4, [13]);
    f.push(1, capabilityGrant(7, [99]));
    const zero = hash32(new Uint8Array(32));
    f.denied(7, revokeDevice(1, 3, 2), /bound to another root/);
    f.denied(7, revokeDevice(1, 10, 2), /non-device Principal/);
    f.denied(7, revokeDevice(2, 9, 2), /root is bound as a device/);
    f.denied(7, revokeDevice(10, 3, 3, zero), /only a bound pairing device/);
    f.denied(7, revokeDevice(10, 9, 3, zero), /only a bound pairing device/);
    f.denied(7, revokeDevice(10, 3, 2), REVOKE_ISSUER);
    f.denied(3, revokeDevice(10, 3, 1), REVOKE_ISSUER); // self-retirement is reason 0 only
    f.push(2, revokeDevice(10, 3, 2)); // an active manager
    f.denied(7, revokeDevice(10, 3, 2), REVOKE_ISSUER); // the issuer before the duplicate
    f.denied(10, revokeDevice(10, 3, 2), ALREADY_REVOKED);
    f.push(4, revokeDevice(10, 2, 99)); // the owner's device expels another root's manager
    expect(revocationOf(f.state, id(10), id(2))?.reason).toBe(99n);
    f.replay();
  });

  it("lets a suspended or standingless device retire itself but not manage (suspended_or_standingless_registered_device_can_self_retire_but_cannot_manage)", () => {
    for (const loseStanding of [false, true]) {
      const f = new Fixture();
      f.push(1, capabilityGrant(10, [1, 2]));
      const membership = f.head;
      f.register(10, 2, FULL);
      const manager = f.state.devices.get(toHex(id(2)))?.chain?.leaf;
      if (manager === undefined) throw new Error("the manager has a chain");
      f.push(2, deviceGrant(chainOf([personalCert(10, 3, [1, 2], 2, 3), manager])));
      if (loseStanding) f.push(1, revokeGrant(membership));
      else f.push(10, revokeDevice(10, 2, 2));
      f.denied(3, revokeDevice(10, 3, 2), REVOKE_ISSUER);
      f.push(3, revokeDevice(10, 3, 0));
      f.replay();
    }
  });

  it("binds nothing for an unbound revocation, and another root's pair does not cascade (unbound_revocation_binds_nothing_and_other_root_pairs_do_not_cascade)", () => {
    const f = new Fixture();
    f.push(1, revokeDevice(10, 2, 2));
    expect(isBound(f.state, id(2))).toBe(false);
    expect(f.state.roles.has(toHex(id(2)))).toBe(false);
    expect(f.state.principals.has(toHex(id(2)))).toBe(false);
    f.push(1, capabilityGrant(10, [1, 2]));
    f.denied(10, deviceGrant(chainOf([personalCert(10, 2, [1], 10, 2)])), REVOKED);
    f.push(
      1,
      deviceGrant(chainOf([personalCert(1, 3, [1], 2, 3), personalCert(1, 2, FULL, 1, 2)])),
    );
    expect(hasAbility(f.state, id(3), 1n)).toBe(true);
    expect(same(rootOf(f.state, id(2)), id(1))).toBe(true);
    f.denied(10, deviceGrant(chainOf([personalCert(10, 2, FULL, 10, 9)])), BINDING);
    f.replay();
  });
});

describe("pairing consume and approval (§17.4 rule 7, §17.5 reason 3)", () => {
  it("matches the payload digest and consumes once (two_phase_pairing_matches_payload_digest_and_consumes_once)", () => {
    const f = new Fixture();
    f.register(1, 2, FULL);
    const session = issue(devicePayload(1, 5, PAIRING, [1, 2], [RESOURCE], 5), 2);
    const manager = f.state.devices.get(toHex(id(2)))?.chain?.leaf;
    if (manager === undefined) throw new Error("the manager has a chain");
    f.push(2, deviceGrant(chainOf([session, manager])));
    const candidate = devicePayload(1, 3, PERSONAL, [1, 2], [], 3);
    const approved = deviceCertificatePayloadDigest(candidate);
    // Phase 1 commits only the digest of the unsigned payload.
    f.push(2, revokeDevice(1, 5, 3, approved));
    const r = revocationOf(f.state, id(1), id(5));
    expect(r?.approval !== null && r?.approval !== undefined && same(r.approval, approved)).toBe(
      true,
    );
    f.denied(2, revokeDevice(1, 5, 3, hash32(new Uint8Array(32).fill(1))), ALREADY_REVOKED);
    f.denied(2, deviceGrant(chainOf([personalCert(1, 4, [1, 2], 2, 4), manager]), 5), APPROVAL);
    const certificate = issue(candidate, 2);
    expect(same(certificate.id, approved)).toBe(false);
    const approvedChain = chainOf([certificate, manager]);
    f.push(2, deviceGrant(approvedChain, 5));
    f.denied(2, deviceGrant(approvedChain), REPEAT);
    expect(activeDevice(f.state, id(3))).toBeDefined();
    // An exact-byte replay is the same record, not a re-registration.
    const repeated = validateControlChain([
      ...f.records,
      f.records[f.records.length - 1] as Uint8Array,
    ]);
    expect(repeated.kind === "linear" && repeated.records.length).toBe(f.records.length);
    f.replay();
  });

  it("refuses cancelled, missing and other-root approvals (cancelled_missing_and_wrong_root_pairing_approvals_are_refused)", () => {
    const f = new Fixture();
    const leaf = chainOf([personalCert(1, 3, [1, 2], 1, 3)]);
    f.denied(1, deviceGrant(leaf, 5), APPROVAL);
    f.push(
      1,
      deviceGrant(chainOf([issue(devicePayload(1, 5, PAIRING, [1, 2], [RESOURCE], 5), 1)])),
    );
    f.denied(1, deviceGrant(leaf, 5), APPROVAL);
    f.push(1, revokeDevice(1, 5, 0));
    f.denied(1, deviceGrant(leaf, 5), APPROVAL);
    f.push(1, capabilityGrant(10, [1, 2]));
    f.denied(10, deviceGrant(chainOf([personalCert(10, 4, [1], 10, 4)]), 5), APPROVAL);
  });

  it("restricts who may bind service and pairing leaves (grant_issuer_alternatives_and_service_pairing_restrictions)", () => {
    for (const kind of [SERVICE, PAIRING]) {
      const f = new Fixture();
      const manager = personalCert(1, 2, FULL, 1, 2);
      const scoped = issue(devicePayload(1, 6, kind, [1, 2], [RESOURCE], 6), 2);
      const certificates = chainOf([scoped, manager]);
      // The leaf and an unregistered intermediate self-register personal leaves only.
      for (const issuer of [2, 6]) f.denied(issuer, deviceGrant(certificates), GRANT_ISSUER);
      f.push(1, deviceGrant(chainOf([manager])));
      f.push(2, deviceGrant(certificates));
      expect(activeDevice(f.state, id(6))).toBeDefined();
      f.denied(6, deviceGrant(chainOf([personalCert(1, 7, [1], 1, 7)])), GRANT_ISSUER);
    }
    const f = new Fixture();
    f.register(1, 2, [13]); // owner-acting, not managing
    f.push(2, deviceGrant(chainOf([issue(devicePayload(1, 6, SERVICE, [1], [RESOURCE], 6), 1)])));
    f.push(1, capabilityGrant(10, [1]));
    f.denied(2, deviceGrant(chainOf([personalCert(10, 3, [1], 10, 3)])), GRANT_ISSUER);
    // Even the Resource owner cannot register a device of another root.
    f.denied(1, deviceGrant(chainOf([personalCert(10, 3, [1], 10, 3)])), GRANT_ISSUER);
  });
});

describe("grants, keys and transfers with devices (§17.2, §17.3, §25.2, §23.3, §80.1)", () => {
  it("bounds delegation by the mask and covers sibling revokes by issuer_root (delegation_mask_and_sibling_revoke_coverage_use_issuer_root)", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(10, [1, 2, 4, 5], [1, 2, 4, 5, 9, 11, 12, 13, 99]));
    const parent = f.head;
    f.register(10, 2, [1, 4, 5]);
    f.register(10, 3, [1, 5]);
    f.denied(2, capabilityGrant(7, [1, 2], [], parent), DELEGATION);
    f.denied(2, capabilityGrant(7, [1], [2], parent), DELEGATION);
    f.denied(2, capabilityGrant(7, [1, 9], [], parent), DELEGATION);
    f.push(2, capabilityGrant(7, [1, 11, 12, 13, 99], [11, 12, 13, 99], parent, 1));
    const issued = f.head;
    const g = f.state.grants.get(toHex(issued));
    expect(g !== undefined && same(g.issuer, id(2)) && same(g.issuerRoot, id(10))).toBe(true);
    f.push(3, revokeGrant(issued));
    expect(f.state.grants.get(toHex(issued))?.revokedBy).not.toBeNull();
    f.denied(3, capabilityGrant(7, [1], [], parent), /capability\/grant/);
    f.replay();
  });

  it("lets a device deliver keys within its root, to readers only (same_root_packages_require_an_active_endpoint_and_a_reading_recipient)", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(10, [1, 2]));
    f.register(10, 2, [1, 2]);
    f.register(10, 3, [1]);
    f.register(10, 4, [2]);
    const can = (s: number, r: number) => canDistributeKey(f.state, id(s), id(r), dataEpoch(0n));
    for (const [s, r] of [
      [2, 10],
      [10, 2],
      [2, 3],
      [2, 2],
    ] as const)
      expect(can(s, r).allowed).toBe(true);
    const reason = (s: number, r: number) => {
      const a = can(s, r);
      return a.allowed ? "allowed" : a.reason;
    };
    expect(reason(10, 10)).toMatch(/key\/distribute/);
    expect(reason(2, 4)).toMatch(/data\/read/);
    expect(reason(2, 1)).toMatch(/key\/distribute/);
    f.push(10, revokeDevice(10, 3, 0));
    expect(sameRoot(f.state, id(2), id(3))).toBe(false);
    expect(sameRoot(f.state, id(3), id(10))).toBe(false);
    expect(hasAbility(f.state, id(2), ABILITY.DATA_WRITE)).toBe(true);
  });

  it("accepts a transfer through a device and keeps its registration (transfer_accepts_through_device_and_preserves_existing_registration)", () => {
    const f = new Fixture();
    f.register(1, 2, [13]);
    f.push(1, capabilityGrant(10, [1]));
    const certs = chainOf([personalCert(10, 3, [13], 10, 3)]);
    f.push(3, deviceGrant(certs));
    const binding = f.state.devices.get(toHex(id(3)));
    f.push(3, transferBody(f.state, 10, 2, 3, certs));
    expect(f.state.devices.get(toHex(id(3)))).toEqual(binding);
    expect(same(f.state.owner.principalId, id(10))).toBe(true);
    expect(ownerAction(f.state, id(3))).toBe(true);
    expect(ownerAction(f.state, id(2))).toBe(false);
    expect(hasAbility(f.state, id(2), 1n)).toBe(false);
    f.replay();
  });

  it("registers, re-certifies and refuses revoked paths through transfers (transfer_registers_new_leaf_recertifies_suspended_leaf_and_refuses_revoked_paths)", () => {
    const f = new Fixture();
    f.push(3, transferBody(f.state, 10, 1, 3, chainOf([personalCert(10, 3, [13], 10, 3)])));
    expect(f.state.roles.get(toHex(id(10)))).toBe("non-device");
    expect(activeDevice(f.state, id(3))).toBeDefined();
    f.push(10, capabilityGrant(10, [1]));
    f.push(1, transferBody(f.state, 1, 3, 1));
    const manager = personalCert(10, 2, FULL, 10, 2);
    f.push(3, deviceGrant(chainOf([personalCert(10, 3, [13], 2, 9), manager])));
    f.push(1, revokeDevice(10, 2, 2));
    expect(activeDevice(f.state, id(3))).toBeUndefined();
    f.push(3, transferBody(f.state, 10, 1, 3, chainOf([personalCert(10, 3, [13], 10, 10)])));
    expect(activeDevice(f.state, id(3))).toBeDefined();
    f.push(10, revokeDevice(10, 3, 2));
    f.denied(
      3,
      transferBody(f.state, 10, 10, 3, chainOf([personalCert(10, 3, [13], 10, 11)])),
      REVOKED,
    );
    f.replay();
  });

  it("lets owner/act bypass the mask but not parent bounds; extensions need ownerAction (owner_act_bypasses_grant_mask_but_not_parent_bounds_and_extension_requires_owner_action)", () => {
    const f = new Fixture();
    f.register(1, 2, [13]);
    f.push(2, capabilityGrant(10, [1, 2, 11, 99], [], undefined, 1));
    expect(same(f.state.grants.get(toHex(f.head))?.issuerRoot ?? new Uint8Array(), id(1))).toBe(
      true,
    );
    f.push(2, { type: "EXTENSION", code: 32n, body: null });
    f.register(1, 3, [1, 2, 4, 5]);
    f.denied(3, { type: "EXTENSION", code: 32n, body: null }, /issued by the owner/);
    f.denied(3, capabilityGrant(7, [1]), /prove its authority through a parent/);
    f.push(1, capabilityGrant(1, [1], [1]));
    f.denied(2, capabilityGrant(7, [2], [], f.head), /not delegable under the parent/);
  });
});

describe("invite/claim is never held by a device (§80.1, spec#2 1cfe51b)", () => {
  it("is not conferred by mask code 11, even when the root holds an invitation", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(10, [1]));
    f.push(1, capabilityGrant(10, [1, 11], [], undefined, 1));
    f.register(10, 2, [1, 11]);
    expect(hasAbility(f.state, id(10), ABILITY.INVITE_CLAIM)).toBe(true);
    expect(hasAbility(f.state, id(2), ABILITY.INVITE_CLAIM)).toBe(false);
    expect(hasAbility(f.state, id(2), ABILITY.DATA_READ)).toBe(true);
    // The §25.2 invitation exception does not reach the device either.
    const g = new Fixture();
    g.push(1, capabilityGrant(10, [11], [], undefined, 1));
    g.push(1, capabilityGrant(10, [2]));
    g.register(10, 3, [2, 11]);
    const a = canDistributeKey(g.state, id(1), id(3), dataEpoch(0n));
    expect(a.allowed).toBe(false);
    expect(canDistributeKey(g.state, id(1), id(10), dataEpoch(0n)).allowed).toBe(true);
  });
});

describe("ordering of the classes for device records (§62)", () => {
  it("needs the Device Grant's root known to the Resource before any signature (all_dependencies_precede_outer_or_embedded_signature_failures)", () => {
    const f = new Fixture();
    // Root 10 is unknown here: MISSING_DEPENDENCY, even with a bad certificate signature.
    const r = f.propose(10, deviceGrant(chainOf([personalCert(10, 2, [1], 9, 2)])));
    expect(r.kind === "invalid" && r.wireCode).toBe("MISSING_DEPENDENCY");
    f.push(1, capabilityGrant(10, [1]));
    // Now known: the certificate signed by 9, not the root, is INVALID_SIGNATURE before standing or issuer.
    const s = f.propose(7, deviceGrant(chainOf([personalCert(10, 2, [1], 9, 2)])));
    expect(s.kind === "invalid" && s.wireCode).toBe("MISSING_DEPENDENCY"); // issuer 7 unknown first
    const t = f.propose(2, deviceGrant(chainOf([personalCert(10, 2, [1], 9, 2)])));
    expect(t.kind === "invalid" && t.wireCode).toBe("INVALID_SIGNATURE");
  });

  it("requires the leaf to sign accept and commit with field 2 (accept_and_commit_must_use_leaf_and_all_signatures_only_policies_enforce_it)", () => {
    const f = new Fixture();
    const c = chainOf([personalCert(10, 3, [13], 10, 3)]);
    for (const [commitBy, acceptBy] of [
      [10, 3],
      [3, 10],
    ] as const) {
      const r = f.propose(commitBy, transferBody(f.state, 10, 1, acceptBy, c));
      expect(r.kind === "invalid" && r.wireCode).toBe("INVALID_SIGNATURE");
    }
    // Signature checks do not depend on the authority policy.
    const bad = recordAt(f.state, 10, transferBody(f.state, 10, 1, 3, c));
    const permissive = validateControlChain([...f.records, bad.bytes], { authorize: () => true });
    expect(permissive.kind === "invalid" && permissive.wireCode).toBe("INVALID_SIGNATURE");
    const raw = genesisRaw(1, 1, chainOf([personalCert(1, 2, [13], 1, 2)]));
    const g = validateControlChain([raw.bytes], { authorize: () => true });
    expect(g.kind === "invalid" && g.wireCode).toBe("INVALID_SIGNATURE");
  });
});

/** A Genesis with field 5 re-signed by `signer` as its issuer, bypassing the writer rule (§15). */
function genesisRaw(owner: number, signer: number, chain: ReturnType<typeof chainOf>) {
  const record = decodeControlRecord(genesis(owner, 2, chain).bytes);
  const payload = decodeStrict(record.signed.payloadBytes);
  if (!isCborMap(payload)) throw new Error("not a map");
  const entries = payload.entries.map(([k, v]) => [k, k === 4 ? id(signer) : v] as const);
  return signObject(encode(cborMap(entries)), keys(signer));
}

describe("states kept for every head (review of #8, R8-1)", () => {
  it("share their maps: a reader's revocations copy no earlier entry", () => {
    const f = new Fixture();
    f.push(1, capabilityGrant(5, [1]));
    for (let i = 0; i < 24; i++) f.push(5, revokeDevice(5, 100 + i, 0));
    const states = f.states.slice(2);
    states.forEach((s, i) => {
      expect(s.revoked).toBeInstanceOf(PersistentMap);
      expect(s.revoked.size).toBe(i + 1);
      // Every later state only adds to the maps of an earlier one.
      expect(s.principals).toBe(f.states[1]?.principals);
      expect(s.devices).toBe(f.states[1]?.devices);
    });
    // A revocation copies only its path (persistent-map.test.ts).
    expect(states[0]?.revoked.size).toBe(1);
    f.replay();
  });
});
