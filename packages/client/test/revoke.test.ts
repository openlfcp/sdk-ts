import {
  type ControlRecordId,
  dataEpoch,
  type PrincipalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  ABILITY,
  type ControlBody,
  decodeControlRecord,
  hasAbility,
  KEY_EPOCH_REASON,
  parseKeyPackage,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { planRevocation } from "../src/index.js";

// LFCP-02-060: planning a member's removal on the validated chain: the
// revocations of every grant the revoker may revoke, the epoch rotation
// and the Key Packages of the new DEK to the remaining readers.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const party = (seed: number): { signer: Signer; agreement: AgreementKeyPair } => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const OWNER = party(1);
const BOB = party(41);
const CAROL = party(51);
const DAVE = party(61);
const ERIN = party(71);
const R = resourceId(bytes32(230));
const DEK0 = importResourceDEK(bytes32(90));
const pid = (p: { signer: Signer }): PrincipalId => p.signer.descriptor.principalId;

/** A chain built record by record, each by its own signer. */
function chain() {
  const records: Uint8Array[] = [];
  let head: ControlRecordId | null = null;
  const add = (body: ControlBody, by = OWNER) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
      body,
      by.signer,
    );
    records.push(s.bytes);
    head = s.recordId;
    return s.recordId;
  };
  add({
    type: "GENESIS",
    dataProfile: "org.example.text.v1",
    owner: OWNER.signer.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
    coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
  });
  const grant = (
    who: { signer: Signer },
    abilities: bigint[],
    by = OWNER,
    extra: { delegable?: bigint[]; parentGrantId?: ControlRecordId } = {},
  ) =>
    add(
      {
        type: "CAPABILITY_GRANT",
        subject: who.signer.descriptor,
        abilities,
        delegable: extra.delegable ?? [],
        ...(extra.parentGrantId === undefined ? {} : { parentGrantId: extra.parentGrantId }),
      },
      by,
    );
  const view = () => {
    const v = validateControlChain(records);
    if (v.kind !== "linear") throw new Error(v.kind);
    return v;
  };
  return { add, grant, view, records };
}

const READ = ABILITY.DATA_READ;
const WRITE = ABILITY.DATA_WRITE;

describe("planRevocation (LFCP-02-060)", () => {
  it("revokes the member, rotates the epoch and keys only the remaining readers", async () => {
    const c = chain();
    const bob = c.grant(BOB, [READ, WRITE]);
    c.grant(CAROL, [READ]);
    const plan = await planRevocation({
      view: c.view(),
      revoker: OWNER.signer,
      subject: pid(BOB),
      frontier: [],
    });
    expect(plan.revoked.map(toHex)).toEqual([toHex(bob)]);
    expect(plan.records).toHaveLength(2);
    expect(plan.rotation?.epoch).toBe(1n);
    expect(plan.recipients.map(toHex)).toEqual([toHex(pid(CAROL))]);
    expect(plan.remainingPaths).toEqual([]);
    // The records extend the chain: BOB no longer reads, the epoch is 1, member revoked.
    const after = validateControlChain([...c.records, ...plan.records.map((r) => r.bytes)]);
    if (after.kind !== "linear") throw new Error(after.kind);
    expect(hasAbility(after.state, pid(BOB), READ)).toBe(false);
    expect(after.state.epoch.epoch).toBe(1n);
    expect(after.state.epoch.dekCommitment).toEqual(
      dekCommitment(R, dataEpoch(1n), plan.rotation?.dek as never),
    );
    const kp = parseKeyPackage(plan.keyPackages[0] as Uint8Array);
    expect(toHex(kp.payload.recipient)).toBe(toHex(pid(CAROL)));
    expect(kp.payload.dataEpoch).toBe(1n);
    const epoch = decodeControlRecord(plan.records[1]?.bytes as Uint8Array).body;
    expect(epoch).toMatchObject({ type: "KEY_EPOCH", reason: KEY_EPOCH_REASON.MEMBER_REVOKED });
  });

  it("deactivates grants delegated from a revoked one, and keys no one through them", async () => {
    const c = chain();
    const bob = c.grant(BOB, [READ, WRITE, ABILITY.CAPABILITY_GRANT], OWNER, {
      delegable: [READ],
    });
    const erin = c.grant(ERIN, [READ], BOB, { parentGrantId: bob });
    c.grant(CAROL, [READ]);
    const plan = await planRevocation({
      view: c.view(),
      revoker: OWNER.signer,
      subject: pid(BOB),
      frontier: [],
    });
    expect(plan.deactivated.map(toHex)).toEqual([toHex(erin)]);
    expect(plan.recipients.map(toHex)).toEqual([toHex(pid(CAROL))]);
  });

  it("reports a path the revoker may not revoke, and does not rotate while the member still reads", async () => {
    const c = chain();
    c.grant(
      DAVE,
      [READ, ABILITY.CAPABILITY_GRANT, ABILITY.CAPABILITY_REVOKE, ABILITY.KEY_ROTATE],
      OWNER,
      {
        delegable: [READ],
      },
    );
    const fromOwner = c.grant(CAROL, [READ]);
    const daveGrant = [...c.view().state.grants.values()].find(
      (g) => toHex(g.subject) === toHex(pid(DAVE)),
    )?.id as ControlRecordId;
    const fromDave = c.grant(CAROL, [READ], DAVE, { parentGrantId: daveGrant });
    const plan = await planRevocation({
      view: c.view(),
      revoker: DAVE.signer,
      subject: pid(CAROL),
      frontier: [],
    });
    expect(plan.revoked.map(toHex)).toEqual([toHex(fromDave)]);
    expect(plan.remainingPaths).toMatchObject([{ abilities: ["data/read"] }]);
    expect(toHex(plan.remainingPaths[0]?.grantId as ControlRecordId)).toBe(toHex(fromOwner));
    expect(plan.rotation).toBeNull();
    expect(plan.keyPackages).toEqual([]);
  });

  it("refuses the owner, a non-member, and a revoker without authority", async () => {
    const c = chain();
    c.grant(BOB, [READ, WRITE]);
    c.grant(CAROL, [READ]);
    const plan = (revoker: { signer: Signer }, subject: { signer: Signer }) =>
      planRevocation({
        view: c.view(),
        revoker: revoker.signer,
        subject: pid(subject),
        frontier: [],
      });
    await expect(plan(OWNER, OWNER)).rejects.toMatchObject({ reason: "would-remove-owner" });
    await expect(plan(OWNER, DAVE)).rejects.toMatchObject({ reason: "not-member" });
    await expect(plan(BOB, CAROL)).rejects.toMatchObject({ reason: "not-authorized" });
  });

  it("revokes without rotating on request", async () => {
    const c = chain();
    c.grant(BOB, [READ]);
    const plan = await planRevocation({
      view: c.view(),
      revoker: OWNER.signer,
      subject: pid(BOB),
      frontier: [],
      rotate: false,
    });
    expect(plan.records).toHaveLength(1);
    expect(plan.rotation).toBeNull();
  });
});
