import { describe, expect, it } from "vitest";
import {
  compareCanonicalFrontierOrder,
  controlRecordId,
  dataUnitId,
  fromHex,
  hash32,
  idEquals,
  LfcpError,
  principalId,
  resourceId,
  toHex,
} from "../src/index.js";

// LFCP-TEST-VECTORS-01 fixtures.resource.id
const RESOURCE = "c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc241";
// LFCP-TEST-VECTORS-01 case principal_bob expected.principal_id
const BOB = "3ddf22ff145274bcc59c56ffddaab8c123ffea4ac95ff8e9cedbeb788bf0a9c5";
// LFCP-TEST-VECTORS-01 case principal_carol expected.principal_id
const CAROL = "a6e402657a505a183a2c2685ecc3a0457fef86d4e251abd48efe943c1282da48";
// LFCP-TEST-VECTORS-01 case dek_commitments expected.dek0_commitment
const DEK0_COMMITMENT = "9239077c0c32fc80bc1a51b8aad2917aebb1316853b85ffda562b1800c0ced30";
// LFCP-TEST-VECTORS-01 case C0_genesis expected.record_id
const C0_RECORD = "3b141a9d660b274f73a042dbe47dcb1fe5b9f1d8d96f782cc8e4728695704adc";
// LFCP-TEST-VECTORS-01 case D1_bob_epoch0_seq1 expected.unit_id
const D1_UNIT = "708b5a5f1ab7b7c9146b3bd7e4902831aa6666913608502c13b1d32c3650be9f";

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

const constructors = [
  ["ResourceId", resourceId, RESOURCE],
  ["PrincipalId", principalId, BOB],
  ["Hash32", hash32, DEK0_COMMITMENT],
  ["ControlRecordId", controlRecordId, C0_RECORD],
  ["DataUnitId", dataUnitId, D1_UNIT],
] as const;

describe.each(constructors)("%s", (_name, make, vectorHex) => {
  it("accepts the 32-byte vector value", () => {
    expect(toHex(make(fromHex(vectorHex)))).toBe(vectorHex);
  });

  it.each([0, 1, 31, 33, 64])("rejects %i bytes", (n) => {
    expect(codeOf(() => make(new Uint8Array(n)))).toBe("INVALID_LENGTH");
  });

  it("rejects a hex string where raw bytes are required", () => {
    expect(codeOf(() => make(vectorHex as unknown as Uint8Array))).toBe("INVALID_LENGTH");
  });

  it("copies its input so later writes cannot change the id", () => {
    const source = fromHex(vectorHex);
    const id = make(source);
    source.fill(0);
    expect(toHex(id)).toBe(vectorHex);
  });
});

describe("idEquals", () => {
  it("compares identifiers of one kind by bytes", () => {
    expect(idEquals(resourceId(fromHex(RESOURCE)), resourceId(fromHex(RESOURCE)))).toBe(true);
    expect(idEquals(principalId(fromHex(BOB)), principalId(fromHex(CAROL)))).toBe(false);
  });
});

describe("compareCanonicalFrontierOrder", () => {
  it("orders Principal IDs by raw unsigned bytes (LFCP-WIRE-01 §28.2)", () => {
    // LFCP-TEST-VECTORS-01 case SNAPSHOT-01: the frontier lists BOB before CAROL
    const ids = [principalId(fromHex(CAROL)), principalId(fromHex(BOB))];
    ids.sort(compareCanonicalFrontierOrder);
    expect(ids.map(toHex)).toEqual([BOB, CAROL]);
    expect(compareCanonicalFrontierOrder(ids[0] as never, ids[0] as never)).toBe(0);
  });

  it("compares bytes as unsigned", () => {
    const low = principalId(new Uint8Array(32).fill(0x7f));
    const high = principalId(new Uint8Array(32).fill(0x80));
    expect(compareCanonicalFrontierOrder(low, high)).toBeLessThan(0);
  });
});
