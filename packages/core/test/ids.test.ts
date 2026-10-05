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

// Synthetic 32-byte values; the published IDs are checked by the conformance
// runner (LFCP-017).
const RESOURCE = "11".repeat(32);
const BOB = "3d".repeat(32);
const CAROL = "a6".repeat(32);
const DEK0_COMMITMENT = "92".repeat(32);
const C0_RECORD = "3b".repeat(32);
const D1_UNIT = "70".repeat(32);

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
  it("accepts a 32-byte value", () => {
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
