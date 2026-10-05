import { describe, expect, it } from "vitest";
import { actorSequence, dataEpoch, LfcpError, toHex, UINT64_MAX, uint64BE } from "../src/index.js";

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

describe("uint64BE", () => {
  it.each([
    [0n, "0000000000000000"],
    [1n, "0000000000000001"],
    [2n ** 32n, "0000000100000000"],
    [2n ** 53n, "0020000000000000"],
    [2n ** 64n - 1n, "ffffffffffffffff"],
    [0x0102030405060708n, "0102030405060708"],
  ])("encodes %s exactly", (n, hex) => {
    expect(toHex(uint64BE(n))).toBe(hex);
  });

  it("accepts safe-integer numbers", () => {
    expect(toHex(uint64BE(2 ** 32))).toBe("0000000100000000");
    expect(toHex(uint64BE(Number.MAX_SAFE_INTEGER))).toBe("001fffffffffffff");
  });

  it.each([
    ["2^64", 2n ** 64n],
    ["-1", -1n],
    ["-1 (number)", -1],
    ["2^53 as a number (not safe)", 2 ** 53],
    ["1.5", 1.5],
    ["NaN", Number.NaN],
    ["a string", "1" as unknown as number],
  ])("rejects %s with OUT_OF_RANGE, never truncating", (_name, n) => {
    expect(codeOf(() => uint64BE(n as bigint))).toBe("OUT_OF_RANGE");
  });
});

describe("dataEpoch", () => {
  it.each([0n, 1n, 2n ** 32n, 2n ** 53n, UINT64_MAX])("accepts %s", (n) => {
    expect(dataEpoch(n)).toBe(n);
  });

  it("rejects 2^64 and negatives", () => {
    expect(codeOf(() => dataEpoch(2n ** 64n))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => dataEpoch(-1n))).toBe("OUT_OF_RANGE");
  });
});

describe("actorSequence", () => {
  it.each([1n, 2n ** 32n, 2n ** 53n, UINT64_MAX])("accepts %s", (n) => {
    expect(actorSequence(n)).toBe(n);
  });

  it("rejects 0 (sequences begin at 1, §8) and 2^64", () => {
    expect(codeOf(() => actorSequence(0n))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => actorSequence(0))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => actorSequence(2n ** 64n))).toBe("OUT_OF_RANGE");
  });
});
