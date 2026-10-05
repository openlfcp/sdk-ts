import { describe, expect, it } from "vitest";
import * as core from "../src/index.js";
import {
  formatObjectId,
  generateObjectId,
  isObjectId,
  LfcpError,
  parseObjectId,
} from "../src/index.js";

const CANONICAL = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

describe("ObjectId validation (SHARED-OBJECTS-PROFILE-01 §19)", () => {
  it("accepts a canonical UUIDv7", () => {
    // SHARED-OBJECTS-TEST-VECTORS-01 case D06-uuidv7-valid
    const text = "019a2f85-7b31-7c42-b85a-fc843e2f40ad";
    expect(isObjectId(text)).toBe(true);
    expect(formatObjectId(parseObjectId(text))).toBe(text);
  });

  it.each([
    // SHARED-OBJECTS-TEST-VECTORS-01 case D07-uuid-invalid-uppercase
    ["019A2F85-7B31-7C42-B85A-FC843E2F40AD", "upper case"],
    // SHARED-OBJECTS-TEST-VECTORS-01 case D08-uuid-invalid-version
    ["019a2f85-7b31-6c42-b85a-fc843e2f40ad", "version 6"],
    ["019a2f85-7b31-4c42-b85a-fc843e2f40ad", "version 4"],
    ["019a2f85-7b31-7c42-c85a-fc843e2f40ad", "variant 110"],
    ["019a2f85-7b31-7c42-785a-fc843e2f40ad", "variant 0"],
    ["019a2f857b317c42b85afc843e2f40ad", "no hyphens"],
    ["{019a2f85-7b31-7c42-b85a-fc843e2f40ad}", "braces"],
    ["urn:uuid:019a2f85-7b31-7c42-b85a-fc843e2f40ad", "URN prefix"],
    [" 019a2f85-7b31-7c42-b85a-fc843e2f40ad", "leading space"],
    ["019a2f85-7b31-7c42-b85a-fc843e2f40a", "too short"],
  ])("rejects %j (%s)", (text) => {
    expect(isObjectId(text)).toBe(false);
    expect(codeOf(() => parseObjectId(text))).toBe("INVALID_UUIDV7");
  });
});

describe("generateObjectId (RFC 9562 §5.7)", () => {
  it("lays out timestamp, version, variant and random bits", () => {
    const id = generateObjectId({
      now: 0x019a2f857b31,
      random: () => Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    });
    expect(id).toBe("019a2f85-7b31-7fff-bfff-ffffffffffff");
    const zeros = generateObjectId({ now: 0, random: () => new Uint8Array(10) });
    expect(zeros).toBe("00000000-0000-7000-8000-000000000000");
  });

  it("produces canonical, distinct ids from the platform CSPRNG", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generateObjectId()));
    expect(ids.size).toBe(1000);
    for (const id of ids) expect(id).toMatch(CANONICAL);
  });

  it.each([-1, 2 ** 48, 1.5, Number.NaN])("rejects timestamp %s", (now) => {
    expect(codeOf(() => generateObjectId({ now }))).toBe("INVALID_UUIDV7");
  });
});

describe("Object IDs carry no ordering", () => {
  it("exposes no comparison, sorting or timestamp extraction", () => {
    // UUIDv7 time and lexical order are not LFCP causality, conflict
    // precedence or authorization order (BACKLOG LFCP-012, Profile §19).
    const names = Object.keys(core).filter((n) => /objectid/i.test(n));
    expect(names.sort()).toEqual([
      "formatObjectId",
      "generateObjectId",
      "isObjectId",
      "parseObjectId",
    ]);
    expect(
      Object.keys(core).filter((n) => /timestamp|uuid.*(order|compare|sort)/i.test(n)),
    ).toEqual([]);
  });
});
