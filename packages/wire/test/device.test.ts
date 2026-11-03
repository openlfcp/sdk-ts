import { bytesEqual, LfcpError, type PrincipalId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { type CborValue, cborMap, decodeStrict, encode } from "../src/cbor/index.js";
import {
  type ChainStateChecks,
  certificateChainFromCbor,
  certificateChainToCbor,
  checkChainAuthority,
  checkDeviceCertificatePayload,
  DEVICE_CERT_LABEL,
  DEVICE_KIND,
  type DeviceCertificatePayload,
  derivePrincipalId,
  deviceCertificatePayloadDigest,
  deviceCertificatePayloadToCbor,
  EMPTY_CHAIN_STATE,
  encodeDeviceCertificatePayload,
  parseDeviceCertificate,
  preflightIssuance,
  principalDescriptor,
  principalDescriptorToCbor,
  signDeviceCertificate,
  verifyChain,
  verifyChainSignatures,
} from "../src/index.js";
import {
  brokenSignature,
  cert,
  chain,
  deepChain,
  field,
  id,
  keys,
  payload,
  personal,
  RESOURCE,
  ROOT,
  replace,
  rid,
  signed,
  wireOf,
} from "./identity.js";

// LFCP-WIRE-01 §7.3 (IDENTITY-01). Each test mirrors the sdk-rs test of
// crates/lfcp/tests/identity_wire_codecs.rs named in its title, with the
// same inputs and the same wire codes.

const { PERSONAL, SERVICE, PAIRING } = DEVICE_KIND;
const verify = (c: ReturnType<typeof chain>, state: ChainStateChecks = EMPTY_CHAIN_STATE) =>
  verifyChain(c, id(1), ROOT.descriptor, RESOURCE, state);
const ruleOf = (r: { valid: boolean; rule?: string; wireCode?: string }) =>
  r.valid ? "VALID" : `${r.wireCode} ${r.rule}`;
const asPayload = (p: DeviceCertificatePayload) => deviceCertificatePayloadToCbor(p);

describe("Device Certificate codec (§7.3 rules 1–7)", () => {
  it("round-trips every kind with exact bytes, the certificate ID and the payload digest (certificates_round_trip_all_kinds_and_exact_digests)", () => {
    for (const p of [
      personal(2, [13, 12, 2, 1, 9, 11, 2n ** 64n - 1n]),
      payload(2, SERVICE, [1, 2], [RESOURCE]),
      payload(2, PAIRING, [2, 1], [RESOURCE]),
    ]) {
      const digest = deviceCertificatePayloadDigest(p);
      const c = cert(p, 1);
      const parsed = parseDeviceCertificate(c.signed.bytes);
      expect(parsed.payload).toEqual(c.payload);
      // Mask order and unknown codes are kept as received (rule 4).
      expect(parsed.payload.mask).toEqual(p.mask);
      expect(bytesEqual(c.id, sha256(c.signed.bytes))).toBe(true);
      expect(bytesEqual(c.payloadDigest, digest)).toBe(true);
      expect(bytesEqual(c.id, digest)).toBe(false);
      expect(bytesEqual(c.signed.payloadBytes, encodeDeviceCertificatePayload(p))).toBe(true);
      const ch = chain([c]);
      const again = certificateChainFromCbor(
        decodeStrict(encode(certificateChainToCbor(ch))),
        id(1),
      );
      expect(again.certificates.map((x) => toHex(x.signed.bytes))).toEqual([toHex(c.signed.bytes)]);
      const v = verify(ch);
      expect(v.valid && v.inScope).toBe(true);
      // The serial makes two issuances distinct (rule 6).
      const serial = Uint8Array.from(p.serial);
      serial[0] = (serial[0] as number) ^ 1;
      expect(bytesEqual(cert({ ...p, serial }, 1).id, c.id)).toBe(false);
    }
  });

  it("is a closed, typed seven-element array (payload_shapes_and_every_field_are_closed_and_typed)", () => {
    const good = asPayload(personal(2, [1, 2]));
    const descriptor = principalDescriptorToCbor(keys(2).descriptor);
    const smallOrder = field(
      field(descriptor, 1, new Uint8Array(32)),
      0,
      derivePrincipalId(new Uint8Array(32), keys(2).descriptor.x25519PublicKey),
    );
    const cases: CborValue[] = [
      field(descriptor, 0), // a map, not an array
      [],
      replace(good, 0, "LFCP-DEVICE-CERT-v2"),
      [...(good as CborValue[]), null],
      (good as CborValue[]).slice(0, 6),
      replace(good, 0, new TextEncoder().encode(DEVICE_CERT_LABEL)),
      replace(good, 1, new Uint8Array(31)),
      replace(good, 1, 1),
      replace(good, 2, []),
      replace(good, 3, 3),
      replace(good, 3, -1),
      replace(good, 3, "0"),
      replace(good, 4, null),
      replace(good, 5, null),
      replace(good, 6, new Uint8Array(15)),
      replace(good, 6, new Uint8Array(17)),
      replace(good, 6, "0123456789abcdef"),
      replace(good, 2, field(descriptor, 3, null)),
      replace(good, 2, field(descriptor, 1)),
      replace(good, 2, field(descriptor, 0, new Uint8Array(32))),
      // A small-order Ed25519 key with a correctly recomputed ID (§7).
      replace(good, 2, smallOrder),
      // Rule 2: the device is its own root.
      replace(good, 1, keys(2).descriptor.principalId),
    ];
    for (const [i, value] of cases.entries())
      expect([i, wireOf(() => parseDeviceCertificate(signed(value, 1)))]).toEqual([
        i,
        "MALFORMED_MESSAGE",
      ]);
  });

  it("applies the kind, mask and scope rules and limits to readers and writers (kind_mask_scope_rules_and_limits_apply_to_readers_and_writers)", () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => rid(i));
    const cases = [
      personal(2, []),
      personal(2, [1, 1]),
      personal(2, [12]),
      personal(2, [1, 12]),
      personal(2, [2, 12]),
      payload(2, PERSONAL, [1], [RESOURCE]),
      payload(2, SERVICE, [1], []),
      payload(2, SERVICE, [1, 2, 12], [RESOURCE]),
      payload(2, SERVICE, [13], [RESOURCE]),
      payload(2, PAIRING, [1], []),
      payload(2, PAIRING, [1], [RESOURCE, rid(9)]),
      payload(2, PAIRING, [1, 2, 12], [RESOURCE]),
      payload(2, PAIRING, [3], [RESOURCE]),
      payload(2, SERVICE, [1], [RESOURCE, RESOURCE]),
      personal(
        2,
        Array.from({ length: 33 }, (_, i) => 100 + i),
      ),
      payload(2, SERVICE, [1], many(65)),
    ];
    for (const p of cases) {
      expect(wireOf(() => checkDeviceCertificatePayload(p))).toBe("MALFORMED_MESSAGE");
      expect(wireOf(() => signDeviceCertificate(p, ROOT))).toBe("MALFORMED_MESSAGE");
      expect(wireOf(() => parseDeviceCertificate(signed(asPayload(p), 1)))).toBe(
        "MALFORMED_MESSAGE",
      );
    }
    const max = payload(
      2,
      SERVICE,
      Array.from({ length: 32 }, (_, i) => 100 + i),
      many(64),
    );
    const c = cert(max, 1);
    expect(parseDeviceCertificate(c.signed.bytes).payload).toEqual(c.payload);
    for (const [index, item] of [
      [4, "1"],
      [4, -1],
      [5, new Uint8Array(31).fill(1)],
      [5, 0],
    ] as const)
      expect(
        wireOf(() =>
          parseDeviceCertificate(signed(replace(asPayload(personal(2, [1])), index, [item]), 1)),
        ),
      ).toBe("MALFORMED_MESSAGE");
  });

  it("requires the canonical COSE shape and canonical nested bytes (canonical_nested_bytes_and_cose_shape_are_required)", () => {
    const c = cert(personal(2, [1]), 1);
    const object = decodeStrict(c.signed.bytes) as CborValue[];
    const protectedValue = decodeStrict(c.signed.protectedBytes);
    const longArray = Uint8Array.from([0x98, 7, ...c.signed.payloadBytes.subarray(1)]);
    const longMap = Uint8Array.from([0xb8, 2, ...c.signed.protectedBytes.subarray(1)]);
    const cases: Uint8Array[] = [
      Uint8Array.from([0xd2, ...c.signed.bytes]),
      Uint8Array.from([...c.signed.bytes, 0]),
      ...(
        [
          [0, longMap],
          [2, longArray],
          [0, encode(field(protectedValue, 1, -7))],
          [0, encode(field(protectedValue, 4, new Uint8Array(31)))],
          [0, encode(field(protectedValue, 5, null))],
          [1, cborMap([[1, null]])],
          [2, null],
          [3, new Uint8Array(63)],
        ] as [number, CborValue][]
      ).map(([i, part]) => encode(replace(object, i, part))),
    ];
    for (const bytes of cases)
      expect(wireOf(() => parseDeviceCertificate(bytes))).toBe("MALFORMED_MESSAGE");
  });
});

describe("writer-side payload checks match the reader (§7.3, IDENTITY-PROFILE-01 §5.3)", () => {
  it("refuses in check, digest and preflight what signing would refuse", () => {
    const x = keys(2).descriptor.x25519PublicKey;
    const smallOrder = principalDescriptor(new Uint8Array(32), x); // self-consistent ID
    const cases: DeviceCertificatePayload[] = [
      personal(2, [-1n]),
      personal(2, [2n ** 64n]),
      { ...personal(2, [13]), device: smallOrder },
      { ...personal(2, [13]), device: { ...keys(2).descriptor, principalId: id(3) } },
      { ...personal(2, [1]), serial: new Uint8Array(15) },
      { ...personal(2, [1]), root: new Uint8Array(31) as never },
    ];
    for (const p of cases) {
      expect(wireOf(() => checkDeviceCertificatePayload(p))).toBe("MALFORMED_MESSAGE");
      expect(wireOf(() => deviceCertificatePayloadDigest(p))).toBe("MALFORMED_MESSAGE");
      expect(ruleOf(preflightIssuance(p, [], ROOT.descriptor, RESOURCE))).toBe(
        "MALFORMED_MESSAGE structure",
      );
      expect(wireOf(() => signDeviceCertificate(p, ROOT))).toBe("MALFORMED_MESSAGE");
    }
  });

  it("signs, encodes and parses back whatever preflight accepts", () => {
    for (const p of [
      personal(5, [1, 2, 12]),
      personal(5, [13, 2n ** 64n - 1n]),
      payload(5, SERVICE, [1], [RESOURCE]),
      payload(5, PAIRING, [1, 2], [RESOURCE]),
    ]) {
      expect(preflightIssuance(p, [], ROOT.descriptor, RESOURCE).valid).toBe(true);
      const c = signDeviceCertificate(p, ROOT);
      expect(parseDeviceCertificate(c.signed.bytes).payload).toEqual(c.payload);
      expect(bytesEqual(c.payloadDigest, deviceCertificatePayloadDigest(p))).toBe(true);
    }
  });
});

describe("certificate chain structure (§7.3 (c1), (c5), (c7))", () => {
  it("bounds the length, keeps one root and caps managing depth (chain_structure_root_uniqueness_and_depth_boundaries)", () => {
    expect(wireOf(() => chain([]))).toBe("MALFORMED_MESSAGE");
    expect(wireOf(() => certificateChainFromCbor([], id(1)))).toBe("MALFORMED_MESSAGE");
    expect(wireOf(() => certificateChainFromCbor([null], id(1)))).toBe("MALFORMED_MESSAGE");
    expect(wireOf(() => certificateChainFromCbor(null, id(1)))).toBe("MALFORMED_MESSAGE");
    const tooDeep = [...deepChain(false), cert(personal(6, [1]), 1)];
    expect(wireOf(() => chain(tooDeep))).toBe("MALFORMED_MESSAGE");
    // Five entries are refused before any certificate is parsed.
    expect(
      wireOf(() =>
        certificateChainFromCbor(
          [1, 2, 3, 4, 5].map(() => new Uint8Array()),
          id(1),
        ),
      ),
    ).toBe("MALFORMED_MESSAGE");
    expect(wireOf(() => chain(deepChain(true)))).toBe("MALFORMED_MESSAGE"); // (c7)
    const one = cert(personal(2, [1, 2, 12]), 1);
    expect(wireOf(() => chain([one, one]))).toBe("MALFORMED_MESSAGE"); // (c5)
    const foreign = cert(payload(2, PERSONAL, [1], [], id(9)), 9);
    expect(wireOf(() => chain([foreign]))).toBe("MALFORMED_MESSAGE"); // (c1)
    const v = verify(chain(deepChain(false)));
    expect(v.valid).toBe(true);
    if (v.valid) {
      expect(v.inScope).toBe(true);
      expect(v.issuers.map(toHex)).toEqual([4, 3, 2].map((n) => toHex(id(n))));
      expect(v.bindings.length).toBe(4);
      expect(bytesEqual(v.leafId, v.chain.leaf.id)).toBe(true);
    }
    // A managing leaf at depth three is allowed.
    expect(verify(chain(deepChain(true).slice(1))).valid).toBe(true);
  });
});

describe("verifyChain (§7.3, §62 class order)", () => {
  it("checks kids, signatures, the dependency and c3/c4/c6 (signatures_kids_dependencies_and_all_intrinsic_authority_errors)", () => {
    const valid = chain(deepChain(false));
    expect(ruleOf(verifyChain(valid, id(1), undefined, RESOURCE, EMPTY_CHAIN_STATE))).toBe(
      "MISSING_DEPENDENCY root-descriptor",
    );
    // A root descriptor for another Principal fails (c2) at the signature class, as in sdk-rs.
    expect(ruleOf(verifyChainSignatures(valid, keys(9).descriptor))).toBe(
      "INVALID_SIGNATURE c2-kid",
    );
    expect(ruleOf(verifyChain(valid, id(1), keys(9).descriptor, RESOURCE, EMPTY_CHAIN_STATE))).toBe(
      "INVALID_SIGNATURE c2-kid",
    );
    expect(ruleOf(preflightIssuance(personal(5, [1]), [], keys(9).descriptor, RESOURCE))).toBe(
      "INVALID_SIGNATURE c2-kid",
    );
    for (const index of valid.certificates.keys()) {
      const certs = [...valid.certificates];
      certs[index] = parseDeviceCertificate(brokenSignature(certs[index] as never));
      expect(ruleOf(verify(chain(certs)))).toBe("INVALID_SIGNATURE c2-signature");
    }
    const wrongLeafKid = chain([cert(personal(3, [1]), 1), cert(personal(2, [1, 2, 12]), 1)]);
    expect(ruleOf(verify(wrongLeafKid))).toBe("INVALID_SIGNATURE c2-kid");
    const wrongRootKid = chain([cert(personal(2, [1]), 3)]);
    expect(ruleOf(verify(wrongRootKid))).toBe("INVALID_SIGNATURE c2-kid");
    for (const issuer of [
      personal(2, [1, 2]),
      payload(2, SERVICE, [1], [RESOURCE]),
      payload(2, PAIRING, [1], [RESOURCE]),
    ])
      expect(ruleOf(verify(chain([cert(personal(3, [1]), 2), cert(issuer, 1)])))).toBe(
        "AUTHORIZATION_FAILED c3",
      );
    for (const extra of [13, 9, 11, 2n ** 64n - 1n])
      expect(
        ruleOf(verify(chain([cert(personal(3, [1, extra]), 2), cert(personal(2, [1, 2, 12]), 1)]))),
      ).toBe("AUTHORIZATION_FAILED c4");
    expect(ruleOf(verify(chain([cert(payload(2, PAIRING, [1], [rid(0)]), 1)])))).toBe(
      "AUTHORIZATION_FAILED c6",
    );
    // An out-of-scope service leaf is valid but not in scope (bound, never registered).
    const service = verify(chain([cert(payload(2, SERVICE, [1], [rid(0)]), 1)]));
    expect(service.valid && service.inScope).toBe(false);
    expect(service.valid).toBe(true);
  });

  it("reports classes globally, not per certificate (error_classes_are_global_not_per_certificate)", () => {
    // A bad leaf signature never hides a malformed later certificate.
    const first = brokenSignature(cert(personal(3, [13]), 2));
    const malformed = signed(asPayload(personal(2, [])), 1);
    expect(wireOf(() => certificateChainFromCbor([first, malformed], id(1)))).toBe(
      "MALFORMED_MESSAGE",
    );
    // The missing dependency precedes bad signatures and authority.
    const c = chain([parseDeviceCertificate(first), cert(personal(2, [1]), 1)]);
    expect(ruleOf(verifyChain(c, id(1), undefined, RESOURCE, EMPTY_CHAIN_STATE))).toBe(
      "MISSING_DEPENDENCY root-descriptor",
    );
    // A later signature failure precedes the c3/c4 failures of an earlier link.
    const later = chain([
      cert(personal(3, [13]), 2),
      parseDeviceCertificate(brokenSignature(cert(personal(2, [1]), 1))),
    ]);
    expect(ruleOf(verify(later))).toBe("INVALID_SIGNATURE c2-signature");
    // (c1) against the requested root precedes the missing dependency.
    expect(ruleOf(verifyChain(later, id(8), undefined, RESOURCE, EMPTY_CHAIN_STATE))).toBe(
      "MALFORMED_MESSAGE c1-root",
    );
    // Within authority, c3 wins over c4 and c6.
    const both = chain([cert(payload(3, PAIRING, [1], [rid(0)]), 2), cert(personal(2, [2]), 1)]);
    expect(ruleOf(checkChainAuthority(both, RESOURCE))).toBe("AUTHORIZATION_FAILED c3");
  });

  it("asks the state predicates after every signature and intrinsic rule, in spec order (state_predicates_follow_all_signatures_and_intrinsic_rules_in_spec_order)", () => {
    const c = chain(deepChain(false));
    const state = (o: { rootDenied?: boolean; binding?: PrincipalId; revoked?: PrincipalId }) => {
      const calls: string[] = [];
      const checks: ChainStateChecks = {
        rootAllowed: (root) => {
          expect(bytesEqual(root, id(1))).toBe(true);
          calls.push("root");
          return o.rootDenied !== true;
        },
        bindingMatches: (p) => {
          calls.push("binding");
          return !(o.binding !== undefined && bytesEqual(p.device.principalId, o.binding));
        },
        isRevoked: (root, device) => {
          expect(bytesEqual(root, id(1))).toBe(true);
          calls.push("revoked");
          return o.revoked !== undefined && bytesEqual(device, o.revoked);
        },
      };
      return { calls, checks };
    };
    const ok = state({});
    expect(verify(c, ok.checks).valid).toBe(true);
    expect(ok.calls).toEqual(["root", ...Array(4).fill("binding"), ...Array(4).fill("revoked")]);
    const root = state({ rootDenied: true });
    expect(ruleOf(verify(c, root.checks))).toBe("AUTHORIZATION_FAILED root-role");
    expect(root.calls.length).toBe(1);
    // A later binding conflict beats an earlier leaf revocation.
    const binding = state({ binding: id(2), revoked: id(5) });
    expect(ruleOf(verify(c, binding.checks))).toBe("AUTHORIZATION_FAILED binding");
    expect(binding.calls.length).toBe(5);
    // Every position, intermediates included, is checked for revocation.
    for (const n of [2, 3, 4, 5])
      expect(ruleOf(verify(c, state({ revoked: id(n) }).checks))).toBe(
        "AUTHORIZATION_FAILED revoked",
      );
    const none = state({});
    // The leaf alone: its kid (device 4) is not the root, and its signature is broken.
    const broken = chain([parseDeviceCertificate(brokenSignature(c.leaf))]);
    expect(ruleOf(verify(broken, none.checks))).toBe("INVALID_SIGNATURE c2-kid");
    const notManaging = chain([cert(personal(3, [1]), 2), cert(personal(2, [1]), 1)]);
    expect(ruleOf(verify(notManaging, none.checks))).toBe("AUTHORIZATION_FAILED c3");
    expect(none.calls).toEqual([]);
  });
});

describe("preflightIssuance (§7.3, N9: before a pairing session is consumed)", () => {
  it("refuses managing depth four and an empty service scope before anything is signed (unsigned_preflight_rejects_n07_before_consume_or_leaf_signature)", () => {
    const issuers = deepChain(true).slice(1);
    const run = (leaf: DeviceCertificatePayload, from = issuers, root = true) =>
      ruleOf(preflightIssuance(leaf, from, root ? ROOT.descriptor : undefined, RESOURCE));
    expect(run(personal(5, [1, 2, 12]))).toBe("MALFORMED_MESSAGE structure");
    for (const mask of [[1, 2], [1]]) expect(run(personal(5, mask))).toBe("VALID");
    expect(run(payload(5, SERVICE, [1], []), issuers, false)).toBe("MALFORMED_MESSAGE structure");
    expect(run(personal(5, [1]), deepChain(false), false)).toBe("MALFORMED_MESSAGE structure");
    expect(run(personal(5, [1]), issuers, false)).toBe("MISSING_DEPENDENCY root-descriptor");
    expect(run(personal(5, [13]))).toBe("AUTHORIZATION_FAILED c4");
    const bad = [parseDeviceCertificate(brokenSignature(cert(personal(2, [1, 2, 12]), 1)))];
    expect(run(personal(5, [1]), bad)).toBe("INVALID_SIGNATURE c2-signature");
    expect(run(personal(5, [13]), [])).toBe("VALID");
  });

  it("checks the issuer's kind, device/manage and root (unsigned_preflight_checks_issuer_kind_manage_and_root)", () => {
    const leaf = personal(5, [1]);
    for (const issuer of [
      personal(2, [1, 2]),
      payload(2, SERVICE, [1, 2], [RESOURCE]),
      payload(2, PAIRING, [1, 2], [RESOURCE]),
    ])
      expect(ruleOf(preflightIssuance(leaf, [cert(issuer, 1)], ROOT.descriptor, RESOURCE))).toBe(
        "AUTHORIZATION_FAILED c3",
      );
    // (c1) wins even before the missing root descriptor.
    const foreign = cert(payload(2, PERSONAL, [1, 2, 12], [], id(8)), 8);
    expect(ruleOf(preflightIssuance(leaf, [foreign], undefined, RESOURCE))).toBe(
      "MALFORMED_MESSAGE structure",
    );
  });
});

describe("chain bytes", () => {
  it("re-encodes to the exact certificate bytes it was read from", () => {
    const c = chain(deepChain(false));
    const bytes = encode(certificateChainToCbor(c));
    const again = certificateChainFromCbor(decodeStrict(bytes), id(1));
    expect(toHex(encode(certificateChainToCbor(again)))).toBe(toHex(bytes));
    expect(again.issuers.map(toHex)).toEqual(c.issuers.map(toHex));
  });
});
