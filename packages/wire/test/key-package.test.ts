import { dataEpoch, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  type ChainResult,
  type ControlBody,
  keyPackageHpkeAad,
  keyPackageHpkeInfo,
  parseKeyPackage,
  principalDescriptorFromKeys,
  receiveKeyPackage,
  type Signer,
  sealKeyPackage,
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
const DEK0 = importResourceDEK(seq32(90));
/** The X25519 key pairs of the synthetic Principals (see synthetic.ts and signer above). */
const agreement = { ALICE: importAgreementKey(seq32(101)), BRUNO: importAgreementKey(seq32(133)) };

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
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
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

describe("sealKeyPackage / receiveKeyPackage (§25, §25.2)", () => {
  const BRUNO_KEYS = { descriptor: BRUNO.descriptor, agreement: agreement.BRUNO };
  const seal = (
    over: { recipient?: typeof BRUNO.descriptor; dek?: typeof DEK0; signer?: Signer } = {},
  ) =>
    sealKeyPackage({
      resourceId: R,
      epoch: dataEpoch(0n),
      controlHead: HEAD,
      recipient: over.recipient ?? BRUNO.descriptor,
      dek: over.dek ?? DEK0,
      signer: over.signer ?? ALICE,
    });

  it("2, 5, 9, 15, 16. the recipient opens the epoch DEK; the package ID is SHA-256 of its exact bytes", async () => {
    const pkg = await seal();
    const parsed = parseKeyPackage(pkg.bytes);
    expect(toHex(parsed.signed.id)).toBe(toHex(pkg.packageId));
    const r = await receiveKeyPackage(view, pkg.bytes, BRUNO_KEYS);
    if (r.kind !== "opened") throw new Error(JSON.stringify(r));
    expect(toHex(exportSecretKeyBytes(r.dek))).toBe(toHex(exportSecretKeyBytes(DEK0)));
  });

  it("refuses keys of another Principal (recipient binding, no key trying)", async () => {
    const pkg = await seal();
    const r = await receiveKeyPackage(view, pkg.bytes, {
      descriptor: ALICE.descriptor,
      agreement: agreement.ALICE,
    });
    expect(r).toMatchObject({ kind: "ignored", code: "KEY_PACKAGE_RECIPIENT_MISMATCH" });
    // A descriptor and a key pair that do not belong together are refused too.
    const mixed = await receiveKeyPackage(view, pkg.bytes, {
      descriptor: BRUNO.descriptor,
      agreement: agreement.ALICE,
    });
    expect(mixed).toMatchObject({ kind: "ignored", code: "KEY_PACKAGE_RECIPIENT_MISMATCH" });
  });

  it("6. ignores a package that does not open for its named recipient (client-local)", async () => {
    // Names BRUNO but is sealed to ALICE's X25519 key.
    const pkg = await seal({
      recipient: { ...BRUNO.descriptor, x25519PublicKey: agreement.ALICE.publicKey },
    });
    expect(await receiveKeyPackage(view, pkg.bytes, BRUNO_KEYS)).toMatchObject({
      kind: "ignored",
      code: "KEY_PACKAGE_OPEN_FAILED",
    });
  });

  it("10. ignores a DEK that does not match the epoch commitment (client-local)", async () => {
    const pkg = await seal({ dek: importResourceDEK(seq32(91)) });
    expect(await receiveKeyPackage(view, pkg.bytes, BRUNO_KEYS)).toMatchObject({
      kind: "ignored",
      code: "DEK_COMMITMENT_MISMATCH",
    });
  });

  it("7. a tampered ciphertext breaks the sender's signature", async () => {
    const pkg = await seal();
    const tampered = Uint8Array.from(pkg.bytes);
    tampered[tampered.length - 70] = (tampered[tampered.length - 70] as number) ^ 1;
    const r = await receiveKeyPackage(view, tampered, BRUNO_KEYS);
    expect(r).toMatchObject({
      kind: "rejected",
      reason: "SIGNATURE",
      wireCode: "INVALID_SIGNATURE",
    });
  });

  it("11. a package from a sender without key/distribute is rejected before opening", async () => {
    const pkg = await seal({ signer: CARLA });
    expect(await receiveKeyPackage(view, pkg.bytes, BRUNO_KEYS)).toMatchObject({
      kind: "rejected",
      reason: "UNAUTHORIZED",
      wireCode: "AUTHORIZATION_FAILED",
    });
  });
});
