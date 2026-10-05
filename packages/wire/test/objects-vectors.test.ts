import { fromHex, LfcpError, type PrincipalId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { cborMap } from "../src/cbor/index.js";
import {
  decodeDataUnitPayload,
  decodePrincipalDescriptor,
  expectedSignerOf,
  type Parsed,
  type PrincipalDescriptor,
  parseControlRecord,
  parseDataUnit,
  parseKeyPackage,
  parseSignedObject,
  parseSnapshot,
  snapshotPayloadFromCbor,
  verifySignedObject,
} from "../src/index.js";
import * as V from "./payload-vectors.fixtures.js";

// LFCP-016 vector run: every LFCP-TEST-VECTORS-01 case at spec tag
// mvp-0.1-baseline.2 that carries a signed object, plus the in-scope
// wire/fixtures/manifest.json must-fail entries.

const DESCRIPTORS = new Map<string, PrincipalDescriptor>(
  [V.OWNER_DESCRIPTOR, V.BOB_DESCRIPTOR, V.CAROL_DESCRIPTOR, V.INVITE_DESCRIPTOR].map((hex) => {
    const d = decodePrincipalDescriptor(fromHex(hex));
    return [toHex(d.principalId), d];
  }),
);
const descriptorOf = (id: PrincipalId): PrincipalDescriptor => {
  const d = DESCRIPTORS.get(toHex(id));
  if (d === undefined) throw new Error(`no fixture Principal ${toHex(id)}`);
  return d;
};

// SDK error code -> LFCP-WIRE-01 §62 code for a received persistent object
// outside HELLO/AUTH (ADR 0001: N1, N4, N6, N7, CB1-CB3, P1, P2).
const WIRE_CODE: Record<string, string> = {
  COSE_MALFORMED: "MALFORMED_MESSAGE",
  INVALID_STRUCTURE: "MALFORMED_MESSAGE",
  UNSUPPORTED_VALUE: "MALFORMED_MESSAGE",
  INVALID_PRINCIPAL_DESCRIPTOR: "MALFORMED_MESSAGE",
  PRINCIPAL_ID_MISMATCH: "MALFORMED_MESSAGE",
};
const wireCodeOf = (e: unknown): string => {
  if (!(e instanceof LfcpError)) return `not-an-LfcpError: ${String(e)}`;
  return e.code.startsWith("CBOR_") ? "MALFORMED_MESSAGE" : (WIRE_CODE[e.code] ?? e.code);
};

type Kind = "control_record" | "data_unit" | "key_package" | "snapshot";
const PARSE: Record<Kind, (bytes: Uint8Array) => Parsed<unknown>> = {
  control_record: parseControlRecord,
  data_unit: parseDataUnit,
  key_package: parseKeyPackage,
  snapshot: parseSnapshot,
};

/** Signer the object must verify against: the payload's actor/sender/publisher, or a Control Record's issuer. */
const expectedSigner = (kind: Kind, parsed: Parsed<unknown>): PrincipalId => {
  const p = parsed.payload as Parameters<typeof expectedSignerOf>[0] & { issuer?: PrincipalId };
  return kind === "control_record" ? (p.issuer as PrincipalId) : expectedSignerOf(p);
};

/** Structure (016) then signature against the expected signer (015 + 016 hook). */
function run(kind: Kind, hex: string): { accepted: true } | { code: string } {
  let parsed: Parsed<unknown>;
  try {
    parsed = PARSE[kind](fromHex(hex));
  } catch (e) {
    return { code: wireCodeOf(e) };
  }
  const v = verifySignedObject(parsed.signed, descriptorOf(expectedSigner(kind, parsed)));
  return v.valid ? { accepted: true } : { code: "INVALID_SIGNATURE" };
}

describe.each(V.POSITIVES)("positive $id", (c) => {
  const parsed = PARSE[c.kind](fromHex(c.cose));

  it("parses, keeping the exact bytes, payload bytes and object ID", () => {
    expect(toHex(parsed.signed.bytes)).toBe(c.cose);
    expect(toHex(parsed.signed.payloadBytes)).toBe(c.payload);
    expect(toHex(parsed.signed.id)).toBe(c.objectId);
  });

  it("is signed by the payload's expected signer (kid and signature)", () => {
    expect(toHex(parsed.signed.kid)).toBe(toHex(expectedSigner(c.kind, parsed)));
    expect(run(c.kind, c.cose)).toEqual({ accepted: true });
  });
});

describe("positive payload fields", () => {
  it("C0_genesis is a Genesis record at control_seq 0 with a null link", () => {
    const { payload } = parseControlRecord(fromHex(V.C0_COSE));
    expect(payload.controlType).toBe(0n);
    expect(payload.controlSeq).toBe(0n);
    expect(payload.prevControlId).toBeNull();
    expect(payload.extension).toBe(false);
  });

  it("C1..C6 link each record to the previous record ID", () => {
    const chain = [V.C0_COSE, V.C1_COSE, V.C2_COSE, V.C3_COSE, V.C4_COSE, V.C5_COSE, V.C6_COSE];
    const parsed = chain.map((hex) => parseControlRecord(fromHex(hex)));
    for (let i = 1; i < parsed.length; i++) {
      const { payload } = parsed[i] as (typeof parsed)[number];
      expect(payload.controlSeq).toBe(BigInt(i));
      expect(toHex(payload.prevControlId as Uint8Array)).toBe(
        toHex((parsed[i - 1] as (typeof parsed)[number]).signed.id),
      );
    }
  });

  it("D1 starts the actor chain and D2 links to D1", () => {
    const d1 = parseDataUnit(fromHex(V.D1_COSE));
    const d2 = parseDataUnit(fromHex(V.D2_COSE));
    expect(d1.payload.actorSeq).toBe(1n);
    expect(d1.payload.prevDataUnitId).toBeNull();
    expect(d2.payload.actorSeq).toBe(2n);
    expect(toHex(d2.payload.prevDataUnitId as Uint8Array)).toBe(toHex(d1.signed.id));
  });

  it("SNAPSHOT-02 carries a canonical frontier with an extra range", () => {
    const { payload } = parseSnapshot(fromHex(V.SNAPSHOT_02_COSE));
    const withExtras = payload.frontier.filter((h) => h.extras.length > 0);
    expect(withExtras.map((h) => h.extras)).toEqual([[[105n, 107n]]]);
  });

  it("owner_transfer offer and accept parse as canonical signed objects (typed in LFCP-019)", () => {
    expect(() => parseSignedObject(fromHex(V.OFFER_COSE))).not.toThrow();
    expect(() => parseSignedObject(fromHex(V.ACCEPT_COSE))).not.toThrow();
  });
});

// Negatives this layer decides, with the code the vector expects.
const DECIDED: Record<string, string> = {
  tagged_cose_D1: "MALFORMED_MESSAGE", // N1, via parseSignedObject (015)
  noncanonical_payload_D1: "MALFORMED_MESSAGE", // N7, via parseSignedObject (015)
  actor_seq_zero_D1: "MALFORMED_MESSAGE", // §8, N4
  have_empty_extra_list: "MALFORMED_MESSAGE", // §28.1 rule 2, N6
  have_range_reversed: "MALFORMED_MESSAGE", // §28.1 rule 4
  have_range_not_above_contiguous: "MALFORMED_MESSAGE", // §28.1 rule 5
  have_ranges_unsorted: "MALFORMED_MESSAGE", // §28.1 rule 6
  have_ranges_overlapping: "MALFORMED_MESSAGE", // §28.1 rule 7
  have_ranges_adjacent: "MALFORMED_MESSAGE", // §28.1 rule 8
  frontier_duplicate_principal: "MALFORMED_MESSAGE", // §28.1 rule 9
  frontier_unsorted: "MALFORMED_MESSAGE", // §28.2
  tampered_D1: "INVALID_SIGNATURE", // G1/N2, expected signer = actor
  invalid_signature_D1: "INVALID_SIGNATURE", // G1/N2
  wrong_kid_D1: "INVALID_SIGNATURE", // G1/N2: kid is Carol, the actor is Bob
};

// Stateful or cryptographic negatives: structurally valid and correctly
// signed, so they pass this layer. The owning task decides them.
const DEFERRED: Record<string, string> = {
  noncanonical_aad_D1: "LFCP-025 (AEAD; client-local, N3)",
  aead_failure_D1: "LFCP-025 (AEAD; client-local, N3)",
  actor_seq1_prev_not_null_D1: "LFCP-025/LFCP-028 (§26.2 report to the sync engine)",
  control_fork_C6: "LFCP-020 (CONTROL_CONFLICT)",
  hpke_recipient_mismatch_KP0: "LFCP-024 (HPKE; client-local, N5)",
  stale_epoch_absent_actor: "LFCP-023 (STALE_DATA_EPOCH, cutoff frontier)",
};

describe.each(V.NEGATIVES)("negative $id", (c) => {
  it(c.id in DECIDED ? `fails with ${DECIDED[c.id]}` : `passes 016; ${DEFERRED[c.id]}`, () => {
    const result = run(c.kind, c.cose);
    if (c.id in DECIDED) {
      expect(result).toEqual({ code: DECIDED[c.id] });
      expect(result).toEqual({ code: c.code });
    } else {
      expect(DEFERRED[c.id]).toBeDefined();
      expect(result).toEqual({ accepted: true });
    }
  });
});

it("every negative is either decided here or deferred to a named task", () => {
  const ids = V.NEGATIVES.map((c) => c.id).sort();
  expect(ids).toEqual([...Object.keys(DECIDED), ...Object.keys(DEFERRED)].sort());
});

it("actor_equivocation conflicting_D2 is a valid object; equivocation is LFCP-025/LFCP-028", () => {
  expect(run("data_unit", V.EQUIVOCATING_D2)).toEqual({ accepted: true });
  expect(parseDataUnit(fromHex(V.EQUIVOCATING_D2)).signed.id).not.toEqual(
    parseDataUnit(fromHex(V.D2_COSE)).signed.id,
  );
});

describe("CDDL fixture manifest: in-scope must-fail entries", () => {
  const code = (fn: () => unknown): string | undefined => {
    try {
      fn();
    } catch (e) {
      return e instanceof LfcpError ? e.code : String(e);
    }
    return undefined;
  };

  it("data-unit <- D1 cose_sign1 with prefix d2 (tag 18)", () => {
    expect(code(() => parseDataUnit(fromHex(`d2${V.D1_COSE}`)))).toBe("COSE_MALFORMED");
  });

  it("data-unit <- tagged_cose_D1", () => {
    expect(code(() => parseDataUnit(fromHex(V.TAGGED_COSE_D1)))).toBe("COSE_MALFORMED");
  });

  it("data-unit <- C0_genesis cose_sign1 (a Control Record is not a Data Unit)", () => {
    expect(code(() => parseDataUnit(fromHex(V.C0_COSE)))).toBe("INVALID_STRUCTURE");
  });

  it("data-unit-payload <- C0_genesis payload_cbor", () => {
    expect(code(() => decodeDataUnitPayload(fromHex(V.C0_PAYLOAD)))).toBe("INVALID_STRUCTURE");
  });

  it("snapshot-payload <- invalid-snapshot-frontier-map.diag (field 5 is a map)", () => {
    const id = (b: number) => new Uint8Array(32).fill(b);
    const diag = cborMap([
      [0, id(0x11)],
      [1, 1],
      [2, id(0x22)],
      [3, 1],
      [4, id(0x33)],
      [
        5,
        cborMap([
          [0, id(0x44)],
          [1, 18],
        ]),
      ],
      [6, new Uint8Array(20).fill(0x77)],
    ]);
    expect(code(() => snapshotPayloadFromCbor(diag))).toBe("INVALID_STRUCTURE");
  });

  it("principal-descriptor <- descriptor_extra_field (P1)", () => {
    expect(code(() => decodePrincipalDescriptor(fromHex(V.DESCRIPTOR_EXTRA_FIELD)))).toBe(
      "INVALID_PRINCIPAL_DESCRIPTOR",
    );
  });

  // lfcp-protected-header <- principal_owner descriptor_cbor is covered in objects.test.ts (item 6).
  // Out of scope: genesis-record-payload <- C1 (typed bodies, LFCP-019) and
  // typed-lfcp-message <- invalid-hello-with-challenge-body.diag (message codec, LFCP-026).
});
