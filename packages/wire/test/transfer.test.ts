import {
  type ControlRecordId,
  controlRecordId,
  dataEpoch,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  ABILITY_NAMES,
  abilitiesOf,
  type ChainResult,
  type ControlBody,
  encodePrincipalDescriptor,
  objectId,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  signObject,
  validateControlChain,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// §23 ownership transfer, verified and applied (LFCP-021, user decision A).
// Synthetic keys; the published C4 transfer runs in the conformance runner.

const signer = (seed: number): Signer => {
  const key = importSigningKey(seq32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(seed + 100))),
  };
};
const CARLA = signer(65);
const DORA = signer(129); // never granted anything before the transfer
const R = resourceId(seq32(200));
const OTHER_R = resourceId(seq32(201));

interface Built {
  readonly bytes: Uint8Array;
  readonly id: ControlRecordId;
}

/** G (owner ALICE) <- grant BRUNO <- grant CARLA; the transfer commit comes next, at seq 3. */
function base(): Built[] {
  const records: Built[] = [];
  const add = (body: ControlBody, by: Signer) => {
    const prev = records[records.length - 1];
    const s = signControlRecord(
      {
        resourceId: R,
        controlSeq: BigInt(records.length),
        prevControlId: prev === undefined ? null : prev.id,
      },
      body,
      by,
    );
    records.push({ bytes: s.bytes, id: s.recordId });
  };
  add(
    {
      type: "GENESIS",
      dataProfile: "org.example.custom.v1",
      owner: ALICE.descriptor,
      dekCommitment: seq32(10) as never,
      endpoints: [{ url: "wss://a.example.test", priority: 0n }],
      coordinatorUrl: "wss://a.example.test",
    },
    ALICE,
  );
  add(
    { type: "CAPABILITY_GRANT", subject: BRUNO.descriptor, abilities: [1n, 2n], delegable: [] },
    ALICE,
  );
  add(
    { type: "CAPABILITY_GRANT", subject: CARLA.descriptor, abilities: [1n], delegable: [] },
    ALICE,
  );
  return records;
}

interface TransferOptions {
  offerBy?: Signer;
  head?: Uint8Array;
  expectedSeq?: bigint;
  newOwner?: Signer;
  offerResource?: Uint8Array;
  acceptBy?: Signer;
  acceptNames?: Signer;
  acceptOfferId?: Uint8Array;
  commitBy?: Signer;
}

/** Appends an offer/accept/commit at seq 3; options break one rule at a time. */
function transfer(o: TransferOptions = {}): Uint8Array[] {
  const records = base();
  const head = (records[2] as Built).id;
  const newOwner = o.newOwner ?? DORA;
  const offer = signObject(
    encode(
      cborMap([
        [0, o.offerResource ?? R],
        [1, o.head ?? head],
        [2, o.expectedSeq ?? 3n],
        [3, decodeStrict(encodePrincipalDescriptor(newOwner.descriptor))],
        [4, seq32(7).subarray(0, 16)],
      ]),
    ),
    o.offerBy ?? ALICE,
  );
  const accept = signObject(
    encode(
      cborMap([
        [0, R],
        [1, o.acceptOfferId ?? objectId(offer.bytes)],
        [2, (o.acceptNames ?? newOwner).descriptor.principalId],
      ]),
    ),
    o.acceptBy ?? newOwner,
  );
  const commit = signControlRecord(
    { resourceId: R, controlSeq: 3n, prevControlId: head },
    { type: "OWNER_TRANSFER_COMMIT", offer: offer.bytes, accept: accept.bytes },
    o.commitBy ?? newOwner,
  );
  return [...records.map((r) => r.bytes), commit.bytes];
}

const refusal = (r: ChainResult): string =>
  r.kind === "invalid" ? `${r.problem}/${r.wireCode}: ${r.error.message}` : r.kind;

describe("ownership transfer (§23.3)", () => {
  it("a valid transfer makes the accepting Principal the owner, even one never granted before", () => {
    const r = validateControlChain(transfer());
    if (r.kind !== "linear") throw new Error(refusal(r));
    expect(toHex(r.state.owner.principalId)).toBe(toHex(DORA.descriptor.principalId));
    expect(abilitiesOf(r.state, DORA.descriptor.principalId)).toEqual([...ABILITY_NAMES.keys()]);
    // The previous owner keeps no implicit authority (it holds no grant).
    expect(abilitiesOf(r.state, ALICE.descriptor.principalId)).toEqual([]);
    expect(r.unappliedRecords).toEqual([]);
  });

  it("the new owner can then act as owner (key rotation)", () => {
    const chain = transfer();
    const commitId = controlRecordId(objectId(chain[3] as Uint8Array));
    const rotate = signControlRecord(
      { resourceId: R, controlSeq: 4n, prevControlId: commitId },
      {
        type: "KEY_EPOCH",
        epoch: dataEpoch(1n),
        dekCommitment: seq32(11) as never,
        finalFrontier: [],
        reason: 3n,
      },
      DORA,
    );
    expect(validateControlChain([...chain, rotate.bytes]).kind).toBe("linear");
  });

  it.each([
    [
      "an offer signed by a non-owner",
      { offerBy: BRUNO },
      /not signed by the current owner .*rule 1/,
    ],
    ["a stale offer head", { head: seq32(3) }, /current Control Head .*rule 2/],
    [
      "an accept naming someone else",
      { acceptNames: CARLA },
      /not by the Principal the offer names .*rule 3/,
    ],
    [
      "an accept signed by someone else",
      { acceptBy: CARLA },
      /accept is not signed by the new owner .*rule 4/,
    ],
    [
      "a commit issued by someone other than the acceptor",
      { commitBy: CARLA },
      /commit is not issued by the new owner .*rule 5/,
    ],
    ["a wrong expected sequence", { expectedSeq: 4n }, /expected Control Sequence .*rule 6/],
    ["an accept for another offer", { acceptOfferId: seq32(9) }, /does not name this offer/],
    ["an offer for another Resource", { offerResource: OTHER_R }, /another Resource/],
  ] as [string, TransferOptions, RegExp][])(
    "refuses %s (AUTHORIZATION_FAILED)",
    (_n, options, why) => {
      const r = validateControlChain(transfer(options));
      expect(refusal(r)).toMatch(/^UNAUTHORIZED\/AUTHORIZATION_FAILED: /);
      expect(refusal(r)).toMatch(why);
    },
  );
});
