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
    // RFC 9562 Appendix A.6 example UUIDv7. The Shared Objects vectors D06-D08
    // run in the conformance runner (LFCP-032).
    const text = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
    expect(isObjectId(text)).toBe(true);
    expect(formatObjectId(parseObjectId(text))).toBe(text);
  });

  it.each([
    ["017F22E2-79B0-7CC3-98C4-DC0C0C07398F", "upper case"],
    ["017f22e2-79b0-6cc3-98c4-dc0c0c07398f", "version 6"],
    ["017f22e2-79b0-4cc3-98c4-dc0c0c07398f", "version 4"],
    ["017f22e2-79b0-7cc3-c8c4-dc0c0c07398f", "variant 110"],
    ["017f22e2-79b0-7cc3-78c4-dc0c0c07398f", "variant 0"],
    ["017f22e279b07cc398c4dc0c0c07398f", "no hyphens"],
    ["{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}", "braces"],
    ["urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f", "URN prefix"],
    [" 017f22e2-79b0-7cc3-98c4-dc0c0c07398f", "leading space"],
    ["017f22e2-79b0-7cc3-98c4-dc0c0c07398", "too short"],
  ])("rejects %j (%s)", (text) => {
    expect(isObjectId(text)).toBe(false);
    expect(codeOf(() => parseObjectId(text))).toBe("INVALID_UUIDV7");
  });
});

describe("generateObjectId (RFC 9562 §5.7)", () => {
  it("lays out timestamp, version, variant and random bits", () => {
    const id = generateObjectId({
      now: 0x017f22e279b0,
      random: () => Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    });
    expect(id).toBe("017f22e2-79b0-7fff-bfff-ffffffffffff");
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
