import { dataEpoch, principalId, resourceId, toHex } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  type ChainResult,
  type ControlBody,
  keyPackageHpkeAad,
  keyPackageHpkeInfo,
  parseKeyPackage,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  signObject,
  validateControlChain,
  verifyKeyPackage,
} from "../src/index.js";
import { ALICE, BRUNO, seq32 } from "./synthetic.js";

// Synthetic values; the published KP0, KPI and KPC run in the conformance runner.

const signer = (seed: number): Signer => {
  const key = importSigningKey(seq32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(seq32(seed + 100))),
  };
};
const CARLA = signer(65);
const INVITE = signer(97);
const R = resourceId(seq32(200));

describe("HPKE info and AAD (§25.1)", () => {
  it('info is exactly ["LFCP-KEY-v1", resource_id, data_epoch, recipient]', () => {
    const info = keyPackageHpkeInfo(R, dataEpoch(3n), principalId(seq32(5)));
    expect(toHex(info)).toBe(toHex(encode(["LFCP-KEY-v1", R, 3, seq32(5)])));
    expect(decodeStrict(info)).toEqual(["LFCP-KEY-v1", R, 3, seq32(5)]);
  });

  it("AAD is exactly [resource_id, data_epoch, control_head]", () => {
    const aad = keyPackageHpkeAad(R, dataEpoch(0n), seq32(9));
    expect(toHex(aad)).toBe(`835820${toHex(R)}005820${toHex(seq32(9))}`);
  });
});

// G <- grant BRUNO (data/read, key/distribute) <- invite grant (invite/claim only) <- grant CARLA (data/write only)
const records: { bytes: Uint8Array; id: Uint8Array }[] = [];
function add(body: ControlBody, by: Signer) {
  const prev = records[records.length - 1];
  const s = signControlRecord(
    {
      resourceId: R,
      controlSeq: BigInt(records.length),
      prevControlId: prev === undefined ? null : (prev.id as never),
    },
    body,
    by,
  );
  records.push({ bytes: s.bytes, id: s.recordId });
}
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
  { type: "CAPABILITY_GRANT", subject: BRUNO.descriptor, abilities: [1n, 6n], delegable: [] },
  ALICE,
);
add(
  {
    type: "CAPABILITY_GRANT",
    subject: INVITE.descriptor,
    abilities: [11n],
    delegable: [],
    claimLimit: 1n,
  },
  ALICE,
);
add({ type: "CAPABILITY_GRANT", subject: CARLA.descriptor, abilities: [2n], delegable: [] }, ALICE);
const view = validateControlChain(records.map((r) => r.bytes)) as Extract<
  ChainResult,
  { kind: "linear" }
>;
const HEAD = (records[3] as { id: Uint8Array }).id;

/** A Key Package object (the HPKE fields are placeholders: verification does not open it). */
function keyPackage(
  sender: Signer,
  recipient: Signer,
  over: { epoch?: number; head?: Uint8Array; by?: Signer } = {},
) {
  const payload = encode(
    cborMap([
      [0, R],
      [1, over.epoch ?? 0],
      [2, recipient.descriptor.principalId],
      [3, over.head ?? HEAD],
      [4, sender.descriptor.principalId],
      [5, seq32(1)],
      [6, seq32(2)],
    ]),
  );
  return parseKeyPackage(signObject(payload, over.by ?? sender).bytes);
}

describe("verifyKeyPackage (§25.2)", () => {
  it("12, 15. accepts an owner or key/distribute sender to a data/read recipient, signed by the sender", () => {
    expect(view.kind).toBe("linear");
    expect(verifyKeyPackage(view, keyPackage(ALICE, BRUNO)).kind).toBe("authorized");
    expect(verifyKeyPackage(view, keyPackage(BRUNO, BRUNO)).kind).toBe("authorized");
  });

  it("14. accepts an Invitation Principal recipient through its active invite grant", () => {
    expect(verifyKeyPackage(view, keyPackage(ALICE, INVITE)).kind).toBe("authorized");
  });

  it("11. refuses a sender without key/distribute", () => {
    expect(verifyKeyPackage(view, keyPackage(CARLA, BRUNO))).toMatchObject({
      kind: "rejected",
      reason: "UNAUTHORIZED",
      wireCode: "AUTHORIZATION_FAILED",
    });
  });

  it("13. refuses a recipient without data/read or an invite grant", () => {
    expect(verifyKeyPackage(view, keyPackage(ALICE, CARLA))).toMatchObject({
      reason: "UNAUTHORIZED",
    });
  });

  it("refuses a package not signed by its sender (kid = sender)", () => {
    expect(verifyKeyPackage(view, keyPackage(ALICE, BRUNO, { by: BRUNO }))).toMatchObject({
      reason: "SIGNATURE",
      wireCode: "INVALID_SIGNATURE",
    });
  });

  it("refuses unknown heads and epochs not known at the head (MISSING_DEPENDENCY)", () => {
    expect(verifyKeyPackage(view, keyPackage(ALICE, BRUNO, { head: seq32(4) }))).toMatchObject({
      reason: "UNKNOWN_CONTROL_HEAD",
      wireCode: "MISSING_DEPENDENCY",
    });
    expect(verifyKeyPackage(view, keyPackage(ALICE, BRUNO, { epoch: 1 }))).toMatchObject({
      reason: "UNKNOWN_EPOCH",
    });
  });

  it("evaluates authority at the package's head, not the latest one", () => {
    const atGenesis = keyPackage(ALICE, BRUNO, { head: (records[0] as { id: Uint8Array }).id });
    expect(verifyKeyPackage(view, atGenesis)).toMatchObject({ reason: "UNAUTHORIZED" }); // BRUNO had no grant yet
  });
});
