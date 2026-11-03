import { controlRecordId, type Hash32, hash32, type PrincipalId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { type CborValue, cborMap, decodeStrict, encode, isCborMap } from "../src/cbor/index.js";
import {
  type CertificateChain,
  type ControlBody,
  certificateChainToCbor,
  controlBodyFromCbor,
  controlBodyToCbor,
  DEVICE_KIND,
  decodeControlRecord,
  isMvpSupported,
  parseDeviceCertificate,
  principalDescriptorToCbor,
  proposeControlTransition,
  signControlRecord,
  validateControlChain,
  verifyGenesis,
} from "../src/index.js";
import {
  brokenSignature,
  cert,
  chain,
  field,
  id,
  keys,
  payload,
  personal,
  RESOURCE,
  ROOT,
  replace,
  signed,
  wireOf,
} from "./identity.js";

// Control bodies 9 and 10, Genesis field 5 and commit field 2 (LFCP-WIRE-01
// §14, §15, §17.4, §17.5, §23.3): structure, before any authority. Mirrors sdk-rs
// crates/lfcp/tests/identity_wire_codecs.rs (test names in the titles).

const fill = (n: number, length = 32) => new Uint8Array(length).fill(n);
const PREV = fill(8);

/** A record envelope {0..5} signed by `signer`, without the writer rules (Rust raw_record). */
function rawRecord(
  type: number,
  body: CborValue,
  o: { seq?: number; prev?: Uint8Array | null; issuer?: number; signer?: number } = {},
): Uint8Array {
  const signer = o.signer ?? 1;
  return signed(
    cborMap([
      [0, RESOURCE],
      [1, o.seq ?? 1],
      [2, o.prev === undefined ? PREV : o.prev],
      [3, type],
      [4, id(o.issuer ?? signer)],
      [5, body],
    ]),
    signer,
  );
}

/** The record with its signature replaced by 64 zero bytes. */
function zeroSignature(bytes: Uint8Array): Uint8Array {
  return encode(replace(decodeStrict(bytes), 3, new Uint8Array(64)));
}

const grant = (c: CertificateChain, pairingDevice?: PrincipalId): ControlBody => ({
  type: "DEVICE_GRANT",
  root: id(1),
  chain: c,
  ...(pairingDevice !== undefined ? { pairingDevice } : {}),
});
const revoke = (reason: bigint, approval?: Hash32): ControlBody => ({
  type: "DEVICE_REVOKE",
  root: id(1),
  device: id(2),
  reason,
  ...(approval !== undefined ? { approval } : {}),
});
const genesis = (deviceChain?: CertificateChain): ControlBody => ({
  type: "GENESIS",
  dataProfile: "org.openlfcp.identity.v1",
  owner: ROOT.descriptor,
  dekCommitment: hash32(fill(0)),
  endpoints: [{ url: "wss://example.test/", priority: 0n }],
  coordinatorUrl: "wss://example.test/",
  ...(deviceChain !== undefined ? { deviceChain } : {}),
});
const OFFER = signed(
  cborMap([
    [0, RESOURCE],
    [1, PREV],
    [2, 1],
    [3, principalDescriptorToCbor(ROOT.descriptor)],
    [4, fill(9, 16)],
  ]),
  8,
);
const ACCEPT = signed(
  cborMap([
    [0, RESOURCE],
    [1, sha256(OFFER)],
    [2, id(1)],
  ]),
  2,
);
const commit = (deviceChain?: CertificateChain): ControlBody => ({
  type: "OWNER_TRANSFER_COMMIT",
  offer: OFFER,
  accept: ACCEPT,
  ...(deviceChain !== undefined ? { deviceChain } : {}),
});
const HEADER = { resourceId: RESOURCE, controlSeq: 1n, prevControlId: controlRecordId(PREV) };
const LEAF_CHAIN = () => chain([cert(personal(2, [13]), 1)]);
const typeOf = (b: ControlBody) =>
  ({ GENESIS: 0, OWNER_TRANSFER_COMMIT: 6, DEVICE_GRANT: 9, DEVICE_REVOKE: 10 })[
    b.type as "GENESIS"
  ];

describe("DEVICE_GRANT and DEVICE_REVOKE bodies (§17.4, §17.5)", () => {
  it("round-trips a grant, keeps the map closed and refuses field 2 for a pairing leaf (device_grant_round_trip_approval_rules_and_closed_map)", () => {
    for (const pairingDevice of [undefined, id(9)]) {
      const body = grant(chain([cert(personal(2, [1]), 1)]), pairingDevice);
      const record = signControlRecord(HEADER, body, ROOT);
      const parsed = decodeControlRecord(record.bytes);
      expect(parsed.body).toEqual(body);
      expect(parsed.mvpSupported).toBe(true);
      expect(toHex(encode(controlBodyToCbor(parsed.body)))).toBe(
        toHex(encode(controlBodyToCbor(body))),
      );
    }
    const value = controlBodyToCbor(grant(chain([cert(personal(2, [1]), 1)])));
    for (const malformed of [
      field(value, 0),
      field(value, 1),
      field(value, 2, fill(0, 31)),
      field(value, 3, null),
      field(value, 1, []),
      // The chain's certificates name root 1, not [9; 32] (c1).
      field(value, 0, fill(9)),
    ])
      expect(wireOf(() => decodeControlRecord(rawRecord(9, malformed)))).toBe("MALFORMED_MESSAGE");
    const pairing = chain([cert(payload(2, DEVICE_KIND.PAIRING, [1], [RESOURCE]), 1)]);
    expect(wireOf(() => controlBodyToCbor(grant(pairing, id(9))))).toBe("MALFORMED_MESSAGE");
    const bad = field(controlBodyToCbor(grant(pairing)), 2, id(9));
    expect(wireOf(() => controlBodyFromCbor(9n, bad))).toBe("MALFORMED_MESSAGE");
  });

  it("ties field 4 to reason 3, reserves field 3 and keeps unknown reasons (device_revoke_reason_approval_reserved_field_and_unknown_type)", () => {
    for (const reason of [0n, 1n, 2n, 3n, 4n, 2n ** 64n - 1n]) {
      const body = revoke(reason, reason === 3n ? hash32(fill(9)) : undefined);
      expect(decodeControlRecord(signControlRecord(HEADER, body, ROOT).bytes).body).toEqual(body);
      const value = controlBodyToCbor(body);
      for (const key of [0, 1, 2])
        expect(wireOf(() => controlBodyFromCbor(10n, field(value, key)))).toBe("MALFORMED_MESSAGE");
      for (const v of [null, [], 0])
        expect(wireOf(() => controlBodyFromCbor(10n, field(value, 3, v)))).toBe(
          "MALFORMED_MESSAGE",
        );
      const wrongApproval = reason === 3n ? field(value, 4) : field(value, 4, fill(0));
      expect(wireOf(() => controlBodyFromCbor(10n, wrongApproval))).toBe("MALFORMED_MESSAGE");
      expect(wireOf(() => controlBodyFromCbor(10n, field(value, 1, id(1))))).toBe(
        "MALFORMED_MESSAGE",
      );
      // The writer applies the same rules.
      expect(
        wireOf(() =>
          controlBodyToCbor(revoke(reason, reason === 3n ? undefined : hash32(fill(9)))),
        ),
      ).toBe("MALFORMED_MESSAGE");
    }
    expect(wireOf(() => controlBodyFromCbor(11n, cborMap([])))).toBe("INVALID_CONTROL_CHAIN");
    expect(wireOf(() => decodeControlRecord(rawRecord(11, null)))).toBe("INVALID_CONTROL_CHAIN");
    expect(isMvpSupported("DEVICE_GRANT")).toBe(true);
    expect(isMvpSupported("DEVICE_REVOKE")).toBe(true);
  });
});

describe("Genesis field 5 and transfer commit field 2 (§15, §23.3)", () => {
  it("are optional, keep their exact bytes and leave the legacy shape unchanged (genesis_and_commit_optional_chains_preserve_bytes_and_legacy_shape)", () => {
    for (const c of [undefined, LEAF_CHAIN()]) {
      for (const [body, key] of [
        [genesis(c), 5],
        [commit(c), 2],
      ] as const) {
        const signer = body.type === "GENESIS" && c !== undefined ? keys(2) : ROOT;
        const header =
          body.type === "GENESIS"
            ? { resourceId: RESOURCE, controlSeq: 0n, prevControlId: null }
            : HEADER;
        const parsed = decodeControlRecord(signControlRecord(header, body, signer).bytes);
        expect(parsed.body).toEqual(body);
        const value = controlBodyToCbor(body);
        expect(isCborMap(value) && value.entries.some(([k]) => k === key)).toBe(c !== undefined);
        for (const bad of [null, [], [new Uint8Array(0)]])
          expect(
            wireOf(() => controlBodyFromCbor(BigInt(typeOf(body)), field(value, key, bad))),
          ).toBe("MALFORMED_MESSAGE");
      }
    }
    // §15: with field 5 the leaf signs the Genesis, never the owner.
    expect(
      wireOf(() =>
        signControlRecord(
          { resourceId: RESOURCE, controlSeq: 0n, prevControlId: null },
          genesis(LEAF_CHAIN()),
          ROOT,
        ),
      ),
    ).toBe("MALFORMED_MESSAGE");
  });

  it("roots the chain at the Genesis owner or the offer's new owner (embedded_chain_root_must_match_genesis_owner_or_transfer_new_owner)", () => {
    const foreign = chain([cert(payload(2, DEVICE_KIND.PERSONAL, [13], [], id(8)), 8)], id(8));
    for (const [body, key] of [
      [genesis(), 5],
      [commit(), 2],
    ] as const) {
      const withForeign = { ...body, deviceChain: foreign } as ControlBody;
      expect(wireOf(() => controlBodyToCbor(withForeign))).toBe("MALFORMED_MESSAGE");
      const value = field(controlBodyToCbor(body), key, certificateChainToCbor(foreign));
      expect(wireOf(() => controlBodyFromCbor(BigInt(typeOf(body)), value))).toBe(
        "MALFORMED_MESSAGE",
      );
      expect(
        wireOf(() =>
          decodeControlRecord(
            rawRecord(typeOf(body), value, body.type === "GENESIS" ? { seq: 0, prev: null } : {}),
          ),
        ),
      ).toBe("MALFORMED_MESSAGE");
    }
  });

  it("parses the embedded offer and accept before the outer signature matters (embedded_transfer_structure_precedes_outer_signature_with_or_without_chain)", () => {
    for (const c of [undefined, LEAF_CHAIN()]) {
      for (const key of [0, 1]) {
        const bad = field(controlBodyToCbor(commit(c)), key, signed(null, 1));
        expect(wireOf(() => decodeControlRecord(zeroSignature(rawRecord(6, bad))))).toBe(
          "MALFORMED_MESSAGE",
        );
      }
    }
    // The writer refuses a commit whose offer is not a transfer object.
    expect(
      wireOf(() => controlBodyToCbor({ ...commit(), offer: signed(null, 1) } as ControlBody)),
    ).toBe("MALFORMED_MESSAGE");
  });
});

describe("verifyGenesis with field 5 (§15)", () => {
  const at0 = { seq: 0, prev: null };
  const verdict = (body: ControlBody, signer: number) => {
    const v = verifyGenesis(
      decodeControlRecord(rawRecord(0, controlBodyToCbor(body), { ...at0, signer })),
    );
    return v.valid ? "valid" : v.reason;
  };
  it("requires the leaf as signer and verifies the chain up to the owner", () => {
    expect(verdict(genesis(LEAF_CHAIN()), 2)).toBe("valid");
    expect(verdict(genesis(LEAF_CHAIN()), 1)).toBe("ISSUER_NOT_OWNER"); // the owner is not the leaf
    expect(verdict(genesis(LEAF_CHAIN()), 9)).toBe("ISSUER_NOT_OWNER");
    expect(verdict(genesis(), 1)).toBe("valid");
    const broken = chain([parseDeviceCertificate(brokenSignature(cert(personal(2, [13]), 1)))]);
    expect(verdict(genesis(broken), 2)).toBe("BAD_SIGNATURE");
    expect(verdict(genesis(chain([cert(personal(2, [13]), 3)])), 2)).toBe("KID_MISMATCH");
  });
  it("refuses a leaf that cannot act as owner, after the signatures", () => {
    for (const leaf of [
      personal(2, [1]),
      payload(2, DEVICE_KIND.SERVICE, [1], [RESOURCE]),
      payload(2, DEVICE_KIND.PAIRING, [1, 2], [RESOURCE]),
    ])
      expect(verdict(genesis(chain([cert(leaf, 1)])), 2)).toBe("DEVICE_CHAIN_UNAUTHORIZED");
    // (c4) inside the chain is authority too.
    const escalating = chain([cert(personal(3, [13, 2]), 2), cert(personal(2, [1, 2, 12]), 1)]);
    expect(verdict(genesis(escalating), 3)).toBe("DEVICE_CHAIN_UNAUTHORIZED");
  });
});

describe("structure before placement (§62)", () => {
  const G = signControlRecord(
    { resourceId: RESOURCE, controlSeq: 0n, prevControlId: null },
    genesis(),
    ROOT,
  );

  it("refuses a malformed legacy transfer before placement and dependencies (malformed_legacy_transfer_precedes_placement_and_dependency_errors)", () => {
    for (const embedded of [0, 1]) {
      const malformed = field(controlBodyToCbor(commit()), embedded, signed(null, 1));
      for (const [signer, badPlacement] of [
        [1, true],
        [9, false],
        [9, true],
      ] as const) {
        const bytes = rawRecord(
          6,
          malformed,
          badPlacement ? { seq: 42, prev: PREV, signer } : { seq: 1, prev: G.recordId, signer },
        );
        const r = validateControlChain([G.bytes, bytes]);
        expect(r.kind === "invalid" && [r.index, r.problem, r.wireCode]).toEqual([
          1,
          "MALFORMED",
          "MALFORMED_MESSAGE",
        ]);
      }
    }
  });

  it("reads baseline.12's unknown_core_type_C1 shape as MALFORMED_MESSAGE, and type 31 as an unknown core type (mvp-0.4-baseline.1 value-changes)", () => {
    const capabilityGrant = cborMap([
      [0, principalDescriptorToCbor(keys(2).descriptor)],
      [1, [1, 2, 3]],
      [2, []],
    ]);
    for (const [type, problem, wireCode] of [
      [9, "MALFORMED", "MALFORMED_MESSAGE"],
      [31, "UNSUPPORTED_TYPE", "INVALID_CONTROL_CHAIN"],
    ] as const) {
      const r = validateControlChain([
        G.bytes,
        rawRecord(type, capabilityGrant, { seq: 1, prev: G.recordId }),
      ]);
      expect(r.kind === "invalid" && [r.problem, r.wireCode]).toEqual([problem, wireCode]);
    }
  });
});
