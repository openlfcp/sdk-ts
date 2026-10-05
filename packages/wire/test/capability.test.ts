import { type ControlRecordId, dataEpoch, resourceId, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import {
  ABILITY,
  ABILITY_NAMES,
  abilitiesOf,
  authorizeControlRecord,
  type ChainResult,
  type ControlBody,
  type ControlState,
  canDistributeKey,
  hasAbility,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic chains; the published C1-C6 authority runs in the conformance runner.

const signer = (seed: number): Signer => {
  const key = importSigningKey(seq32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(seed + 100))),
  };
};
const OWNER = ALICE;
const CARLA = signer(65);
const INVITE = signer(97);
const DORA = signer(129);
const R = resourceId(seq32(200));
const {
  DATA_READ,
  DATA_WRITE,
  CAPABILITY_GRANT,
  CAPABILITY_REVOKE,
  KEY_DISTRIBUTE,
  KEY_ROTATE,
  ROUTE_UPDATE,
  OWNER_TRANSFER_OFFER,
  INVITE_CLAIM,
} = ABILITY;

interface Built {
  readonly bytes: Uint8Array;
  readonly id: ControlRecordId;
}

/** Builds a chain record by record; each record links to the previous one. */
class Chain {
  readonly records: Built[] = [];
  constructor() {
    const g = signControlRecord(
      { resourceId: R, controlSeq: 0n, prevControlId: null },
      {
        type: "GENESIS",
        dataProfile: "org.example.custom.v1",
        owner: OWNER.descriptor,
        dekCommitment: seq32(10) as never,
        endpoints: [{ url: "wss://a.example.test", priority: 0n }],
        coordinatorUrl: "wss://a.example.test",
      },
      OWNER,
    );
    this.records.push({ bytes: g.bytes, id: g.recordId });
  }
  add(body: ControlBody, by: Signer): ControlRecordId {
    const prev = this.records[this.records.length - 1] as Built;
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(this.records.length), prevControlId: prev.id },
      body,
      by,
    );
    this.records.push({ bytes: s.bytes, id: s.recordId });
    return s.recordId;
  }
  validate(): ChainResult {
    return validateControlChain(
      this.records.map((r) => r.bytes),
      { authorize: authorizeControlRecord },
    );
  }
  state(): ControlState {
    const r = this.validate();
    if (r.kind !== "linear")
      throw new Error(`not linear: ${r.kind} ${r.kind === "invalid" ? r.error.message : ""}`);
    return r.state;
  }
}

const grant = (
  to: Signer,
  abilities: bigint[],
  extra: Partial<Extract<ControlBody, { type: "CAPABILITY_GRANT" }>> = {},
): ControlBody => ({
  type: "CAPABILITY_GRANT",
  subject: to.descriptor,
  abilities,
  delegable: [],
  ...extra,
});
const revoke = (grantId: ControlRecordId): ControlBody => ({ type: "CAPABILITY_REVOKE", grantId });
const claim = (
  invitationGrantId: ControlRecordId,
  claimant: Signer,
  abilities: bigint[],
): ControlBody => ({
  type: "CAPABILITY_CLAIM",
  invitationGrantId,
  claimant: claimant.descriptor,
  abilities,
});
const id = (s: Signer) => s.descriptor.principalId;

/** The refusal of the last record, or "allowed". */
function outcome(chain: Chain): string {
  const r = chain.validate();
  if (r.kind === "linear") return "allowed";
  if (r.kind === "invalid") return `${r.problem}/${r.wireCode}: ${r.error.message}`;
  return r.kind;
}

describe("owner implicit authority (§17.1)", () => {
  const state = new Chain().state();

  it("1, 2, 3. the owner holds every standard ability, without a grant", () => {
    for (const a of [
      DATA_READ,
      DATA_WRITE,
      CAPABILITY_GRANT,
      CAPABILITY_REVOKE,
      KEY_DISTRIBUTE,
      KEY_ROTATE,
    ])
      expect(hasAbility(state, id(OWNER), a)).toBe(true);
    expect(abilitiesOf(state, id(OWNER))).toEqual(
      [...ABILITY_NAMES.keys()].filter((a) => a !== OWNER_TRANSFER_OFFER),
    );
    expect(state.grants.size).toBe(0);
  });

  it("ability 9 (owner/transfer-offer) is reserved and confers nothing, even when granted (§17.1, §23.1)", () => {
    const c = new Chain();
    c.add(grant(BRUNO, [DATA_READ, OWNER_TRANSFER_OFFER]), OWNER);
    const s = c.state();
    expect(hasAbility(s, id(OWNER), OWNER_TRANSFER_OFFER)).toBe(false);
    expect(hasAbility(s, id(BRUNO), OWNER_TRANSFER_OFFER)).toBe(false);
    expect(abilitiesOf(s, id(BRUNO))).toEqual([DATA_READ]);
  });

  it("holds no unknown ability", () => {
    expect(hasAbility(state, id(OWNER), 99n)).toBe(false);
  });
});

describe("grants (§17.2)", () => {
  it("4, 5, 6. a direct grant confers exactly its abilities", () => {
    const c = new Chain();
    c.add(grant(BRUNO, [DATA_READ, DATA_WRITE]), OWNER);
    const s = c.state();
    expect(abilitiesOf(s, id(BRUNO))).toEqual([DATA_READ, DATA_WRITE]);
    expect(hasAbility(s, id(BRUNO), CAPABILITY_GRANT)).toBe(false);
    expect(hasAbility(s, id(CARLA), DATA_READ)).toBe(false);
  });

  it("7. a delegated grant within the parent's delegable abilities is valid", () => {
    const c = new Chain();
    const parent = c.add(
      grant(BRUNO, [DATA_READ, DATA_WRITE, CAPABILITY_GRANT], { delegable: [DATA_READ] }),
      OWNER,
    );
    c.add(grant(CARLA, [DATA_READ], { parentGrantId: parent }), BRUNO);
    expect(abilitiesOf(c.state(), id(CARLA))).toEqual([DATA_READ]);
  });

  it("8. delegation cannot escalate", () => {
    const base = () => {
      const c = new Chain();
      const parent = c.add(
        grant(BRUNO, [DATA_READ, DATA_WRITE, CAPABILITY_GRANT], { delegable: [DATA_READ] }),
        OWNER,
      );
      return { c, parent };
    };
    let t = base();
    t.c.add(grant(CARLA, [DATA_WRITE], { parentGrantId: t.parent }), BRUNO);
    expect(outcome(t.c)).toMatch(/^UNAUTHORIZED\/AUTHORIZATION_FAILED: .*not delegable/);
    t = base();
    t.c.add(grant(CARLA, [DATA_READ], { parentGrantId: t.parent, delegable: [DATA_WRITE] }), BRUNO);
    expect(outcome(t.c)).toMatch(/delegable ability is not delegable/);
    t = base();
    t.c.add(grant(CARLA, [DATA_READ]), BRUNO); // no parent
    expect(outcome(t.c)).toMatch(/must prove its authority through a parent grant/);
    t = base();
    t.c.add(grant(CARLA, [DATA_READ], { parentGrantId: t.parent }), CARLA); // not the parent's subject
    expect(outcome(t.c)).toMatch(/UNAUTHORIZED|UNRESOLVED_ISSUER/);
  });

  it("requires capability/grant from a delegating non-owner (§17.2)", () => {
    const c = new Chain();
    const parent = c.add(grant(BRUNO, [DATA_READ], { delegable: [DATA_READ] }), OWNER);
    c.add(grant(CARLA, [DATA_READ], { parentGrantId: parent }), BRUNO);
    expect(outcome(c)).toMatch(/does not hold capability\/grant/);
  });

  it("keeps unknown ability codes but confers nothing for them (§17.1)", () => {
    const c = new Chain();
    c.add(grant(BRUNO, [99n]), OWNER);
    const s = c.state();
    expect(abilitiesOf(s, id(BRUNO))).toEqual([]);
    expect(hasAbility(s, id(BRUNO), 99n)).toBe(false);
  });
});

describe("revocation (§17.3)", () => {
  it("9. a revoked parent deactivates every grant delegated from it (§17.2)", () => {
    const c = new Chain();
    const parent = c.add(
      grant(BRUNO, [DATA_READ, CAPABILITY_GRANT], { delegable: [DATA_READ] }),
      OWNER,
    );
    c.add(grant(CARLA, [DATA_READ], { parentGrantId: parent }), BRUNO);
    expect(hasAbility(c.state(), id(CARLA), DATA_READ)).toBe(true);
    c.add(revoke(parent), OWNER);
    const s = c.state();
    expect(hasAbility(s, id(BRUNO), DATA_READ)).toBe(false);
    expect(hasAbility(s, id(CARLA), DATA_READ)).toBe(false);
  });

  it("10. the owner may revoke any grant", () => {
    const c = new Chain();
    const g = c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(revoke(g), OWNER);
    expect(hasAbility(c.state(), id(BRUNO), DATA_WRITE)).toBe(false);
  });

  it("11. rejects an unauthorized revoke", () => {
    let c = new Chain();
    const g = c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(grant(CARLA, [DATA_READ]), OWNER);
    c.add(revoke(g), CARLA); // no capability/revoke
    expect(outcome(c)).toMatch(/does not hold capability\/revoke/);

    c = new Chain();
    const g2 = c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(grant(CARLA, [CAPABILITY_REVOKE]), OWNER);
    c.add(revoke(g2), CARLA); // holds capability/revoke, but it does not cover the owner's grant
    expect(outcome(c)).toMatch(/does not cover the grant/);

    c = new Chain();
    c.add(revoke(seq32(3) as ControlRecordId), OWNER);
    expect(outcome(c)).toMatch(/does not exist/);
  });

  it("lets a revoker revoke a grant it issued; an already revoked grant is AUTHORIZATION_FAILED (§17.3)", () => {
    const c = new Chain();
    const parent = c.add(
      grant(BRUNO, [DATA_READ, CAPABILITY_GRANT, CAPABILITY_REVOKE], { delegable: [DATA_READ] }),
      OWNER,
    );
    const child = c.add(grant(CARLA, [DATA_READ], { parentGrantId: parent }), BRUNO);
    c.add(revoke(child), BRUNO);
    expect(hasAbility(c.state(), id(CARLA), DATA_READ)).toBe(false);
    c.add(revoke(child), OWNER);
    expect(outcome(c)).toMatch(/^UNAUTHORIZED\/AUTHORIZATION_FAILED: .*already revoked/);
  });

  it("checks authority before already-revoked (§17.3 order)", () => {
    const c = new Chain();
    const g = c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(grant(CARLA, [DATA_READ]), OWNER);
    c.add(revoke(g), OWNER);
    c.add(revoke(g), CARLA); // already revoked, and CARLA has no capability/revoke
    expect(outcome(c)).toMatch(
      /^UNAUTHORIZED\/AUTHORIZATION_FAILED: .*does not hold capability\/revoke/,
    );
  });

  it("covers grants delegated from one the revoker issued, not grants it received (§17.3)", () => {
    // OWNER -> BRUNO (P) -> CARLA (C, by BRUNO) -> DORA (D, by CARLA).
    const build = () => {
      const c = new Chain();
      const p = c.add(
        grant(BRUNO, [DATA_READ, CAPABILITY_GRANT, CAPABILITY_REVOKE], {
          delegable: [DATA_READ, CAPABILITY_GRANT],
        }),
        OWNER,
      );
      const ch = c.add(
        grant(CARLA, [DATA_READ, CAPABILITY_GRANT], { parentGrantId: p, delegable: [DATA_READ] }),
        BRUNO,
      );
      const d = c.add(grant(DORA, [DATA_READ], { parentGrantId: ch }), CARLA);
      return { c, p, ch, d };
    };
    let t = build();
    t.c.add(revoke(t.d), BRUNO); // D descends from C, which BRUNO issued
    expect(outcome(t.c)).toBe("allowed");
    expect(hasAbility(t.c.state(), id(DORA), DATA_READ)).toBe(false);
    expect(hasAbility(t.c.state(), id(CARLA), DATA_READ)).toBe(true);
    t = build();
    t.c.add(revoke(t.p), BRUNO); // P is the grant BRUNO received
    expect(outcome(t.c)).toMatch(/does not cover the grant/);
  });
});

describe("invitations and claims (§18, §18.1)", () => {
  const invited = (
    limit?: bigint,
    extra: Partial<Extract<ControlBody, { type: "CAPABILITY_GRANT" }>> = {},
  ) => {
    const c = new Chain();
    const inv = c.add(
      grant(
        INVITE,
        [DATA_READ, DATA_WRITE, INVITE_CLAIM],
        limit === undefined ? extra : { claimLimit: limit, ...extra },
      ),
      OWNER,
    );
    return { c, inv };
  };

  it("12. an invitation grant gives the Invitation Principal invite/claim", () => {
    const { c } = invited(1n);
    expect(abilitiesOf(c.state(), id(INVITE))).toEqual([DATA_READ, DATA_WRITE, INVITE_CLAIM]);
  });

  it("13, 16. a valid claim creates the claimant's grant and consumes a claim", () => {
    const { c, inv } = invited(1n);
    const claimId = c.add(claim(inv, DORA, [DATA_READ, DATA_WRITE]), INVITE);
    const s = c.state();
    expect(abilitiesOf(s, id(DORA))).toEqual([DATA_READ, DATA_WRITE]);
    expect(s.grants.get(toHex(inv))?.claimsUsed).toBe(1n);
    expect(s.grants.get(toHex(claimId))).toMatchObject({
      source: "claim",
      delegable: [],
      parentGrantId: null,
    });
  });

  it("14. rejects a claim for more than the invitation transfers", () => {
    let t = invited(1n);
    t.c.add(claim(t.inv, DORA, [DATA_READ, KEY_ROTATE]), INVITE);
    expect(outcome(t.c)).toMatch(/beyond the invitation grant/);
    t = invited(1n);
    t.c.add(claim(t.inv, DORA, [DATA_READ, INVITE_CLAIM]), INVITE); // invite/claim not delegated
    expect(outcome(t.c)).toMatch(/beyond the invitation grant/);
    t = invited(1n, { delegable: [INVITE_CLAIM] });
    t.c.add(claim(t.inv, DORA, [INVITE_CLAIM]), INVITE); // explicitly delegated
    expect(outcome(t.c)).toBe("allowed");
    t = invited(1n);
    t.c.add(claim(t.inv, DORA, [DATA_READ, 99n]), INVITE); // unknown codes request nothing
    expect(outcome(t.c)).toBe("allowed");
  });

  it("15. rejects a claim not issued by the Invitation Principal", () => {
    const { c, inv } = invited(1n);
    c.add(claim(inv, DORA, [DATA_READ]), OWNER);
    expect(outcome(c)).toMatch(/not the Invitation Principal/);
  });

  it("16. tracks claim_limit in chain order", () => {
    let t = invited(1n);
    t.c.add(claim(t.inv, DORA, [DATA_READ]), INVITE);
    t.c.add(claim(t.inv, CARLA, [DATA_READ]), INVITE);
    expect(outcome(t.c)).toMatch(/no claims left/);
    t = invited(2n);
    t.c.add(claim(t.inv, DORA, [DATA_READ]), INVITE);
    t.c.add(claim(t.inv, CARLA, [DATA_READ]), INVITE);
    expect(t.c.state().grants.get(toHex(t.inv))?.claimsUsed).toBe(2n);
    t = invited(undefined); // §18: no claim_limit, not claimable
    t.c.add(claim(t.inv, DORA, [DATA_READ]), INVITE);
    expect(outcome(t.c)).toMatch(/not claimable/);
  });

  it("an invitation whose claims are used up confers no invite/claim; its other abilities stay (§18.1, §25.2)", () => {
    const { c, inv } = invited(1n);
    const before = c.state();
    expect(hasAbility(before, id(INVITE), INVITE_CLAIM)).toBe(true);
    c.add(claim(inv, DORA, [DATA_READ]), INVITE);
    const s = c.state();
    expect(abilitiesOf(s, id(INVITE))).toEqual([DATA_READ, DATA_WRITE]);
    // An invite-only grant (no data/read) no longer qualifies its subject for Key Packages.
    const k = new Chain();
    const only = k.add(grant(INVITE, [DATA_WRITE, INVITE_CLAIM], { claimLimit: 1n }), OWNER);
    expect(canDistributeKey(k.state(), id(OWNER), id(INVITE), dataEpoch(0n))).toEqual({
      allowed: true,
    });
    k.add(claim(only, DORA, [DATA_WRITE]), INVITE);
    expect(canDistributeKey(k.state(), id(OWNER), id(INVITE), dataEpoch(0n))).toMatchObject({
      allowed: false,
    });
  });

  it("rejects a claim against a revoked invitation, and keeps an earlier claim when it is revoked", () => {
    let t = invited(2n);
    t.c.add(revoke(t.inv), OWNER);
    t.c.add(claim(t.inv, DORA, [DATA_READ]), INVITE);
    expect(outcome(t.c)).toMatch(/UNAUTHORIZED|UNRESOLVED_ISSUER/);
    t = invited(1n);
    t.c.add(claim(t.inv, DORA, [DATA_READ]), INVITE);
    t.c.add(revoke(t.inv), OWNER);
    expect(hasAbility(t.c.state(), id(DORA), DATA_READ)).toBe(true); // §18.1: a claim grant has no parent
  });
});

describe("evaluation at a Control Head", () => {
  it("17, 18. evaluates at an older head; a later revocation does not change it", () => {
    const c = new Chain();
    const g = c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    const revoked = c.add(revoke(g), OWNER);
    const r = c.validate();
    if (r.kind !== "linear") throw new Error(r.kind);
    const atGrant = r.stateAt(g);
    expect(atGrant && hasAbility(atGrant, id(BRUNO), DATA_WRITE)).toBe(true);
    expect(hasAbility(r.state, id(BRUNO), DATA_WRITE)).toBe(false);
    expect(toHex(r.state.head)).toBe(toHex(revoked));
    // The same head gives the same state object (cache by immutable head ID).
    expect(r.stateAt(g)).toBe(atGrant);
    expect(r.stateAt(seq32(7))).toBeUndefined();
  });
});

describe("key rotation, routes and Key Packages", () => {
  it("requires key/rotate for a Key Epoch record (§19)", () => {
    const c = new Chain();
    c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(
      {
        type: "KEY_EPOCH",
        epoch: dataEpoch(1n),
        dekCommitment: seq32(11) as never,
        finalFrontier: [],
        reason: 0n,
      },
      BRUNO,
    );
    expect(outcome(c)).toMatch(/does not hold key\/rotate/);
  });

  it("requires route/update and an increasing route version (§20), and applies the route", () => {
    const route = (v: bigint): ControlBody => ({
      type: "ROUTE_UPDATE",
      routeVersion: v,
      endpoints: [{ url: "wss://b.example.test", priority: 0n }],
      coordinatorUrl: "wss://b.example.test",
    });
    let c = new Chain();
    c.add(grant(BRUNO, [ROUTE_UPDATE]), OWNER);
    c.add(route(1n), BRUNO);
    expect(c.state()).toMatchObject({
      routeVersion: 1n,
      route: { coordinatorUrl: "wss://b.example.test" },
    });
    c.add(route(1n), BRUNO);
    expect(outcome(c)).toMatch(/does not increase/);
    c = new Chain();
    c.add(grant(BRUNO, [DATA_WRITE]), OWNER);
    c.add(route(1n), BRUNO);
    expect(outcome(c)).toMatch(/does not hold route\/update/);
  });

  it("canDistributeKey: key/distribute for the sender, data/read or an invite grant for the recipient (§25.2)", () => {
    const c = new Chain();
    c.add(grant(BRUNO, [DATA_READ]), OWNER);
    c.add(grant(INVITE, [INVITE_CLAIM], { claimLimit: 1n }), OWNER);
    const s = c.state();
    const e = dataEpoch(0n);
    expect(canDistributeKey(s, id(OWNER), id(BRUNO), e)).toEqual({ allowed: true });
    expect(canDistributeKey(s, id(OWNER), id(INVITE), e)).toEqual({ allowed: true });
    expect(canDistributeKey(s, id(BRUNO), id(OWNER), e)).toMatchObject({ allowed: false });
    expect(canDistributeKey(s, id(OWNER), id(CARLA), e)).toMatchObject({ allowed: false });
  });
});
