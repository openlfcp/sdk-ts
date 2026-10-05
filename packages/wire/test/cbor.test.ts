import { fromHex, LfcpError, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  type CborValue,
  cborMap,
  decodeStrict,
  encode,
  isDeterministic,
  MAX_DEPTH,
} from "../src/cbor/index.js";

const hex = (v: CborValue): string => toHex(encode(v));
const decodeHex = (h: string): CborValue => decodeStrict(fromHex(h));
const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};

describe("integers: shortest encoding (§5.1, §5.2 rule 1)", () => {
  it.each([
    [0, "00"],
    [23, "17"],
    [24, "1818"],
    [255, "18ff"],
    [256, "190100"],
    [65535, "19ffff"],
    [65536, "1a00010000"],
    [2 ** 32 - 1, "1affffffff"],
    [2 ** 32, "1b0000000100000000"],
    [Number.MAX_SAFE_INTEGER, "1b001fffffffffffff"],
    [2n ** 53n, "1b0020000000000000"],
    [2n ** 64n - 1n, "1bffffffffffffffff"],
    [-1, "20"],
    [-8, "27"],
    [-24, "37"],
    [-25, "3818"],
    [-257, "390100"],
    [-(2n ** 64n), "3bffffffffffffffff"],
  ] as const)("%s -> %s", (value, expected) => {
    expect(hex(value)).toBe(expected);
    expect(decodeHex(expected)).toEqual(value);
  });

  it("decodes safe integers as number and larger ones as bigint", () => {
    expect(decodeHex("1b001fffffffffffff")).toBe(Number.MAX_SAFE_INTEGER);
    expect(decodeHex("1b0020000000000000")).toBe(2n ** 53n);
    expect(decodeHex("3b001ffffffffffffe")).toBe(-Number.MAX_SAFE_INTEGER);
    expect(decodeHex("3b001fffffffffffff")).toBe(-(2n ** 53n));
  });

  it("encodes a bigint and a number of the same value identically", () => {
    expect(hex(10n)).toBe(hex(10));
    expect(hex(-0)).toBe("00");
  });

  it.each([
    [2n ** 64n, "CBOR_OUT_OF_RANGE"],
    [-(2n ** 64n) - 1n, "CBOR_OUT_OF_RANGE"],
    [2 ** 53, "CBOR_OUT_OF_RANGE"],
    [1.5, "CBOR_UNSUPPORTED_TYPE"],
    [Number.NaN, "CBOR_UNSUPPORTED_TYPE"],
    [Number.POSITIVE_INFINITY, "CBOR_UNSUPPORTED_TYPE"],
  ] as const)("refuses to encode %s", (value, code) => {
    expect(codeOf(() => encode(value))).toBe(code);
  });

  it.each(["1817", "1900ff", "1a0000ffff", "1b00000000ffffffff", "3817", "390017"])(
    "rejects the non-shortest head %s",
    (h) => {
      expect(codeOf(() => decodeHex(h))).toBe("CBOR_NON_CANONICAL");
      expect(isDeterministic(fromHex(h))).toBe(false);
    },
  );
});

describe("strings and lengths", () => {
  it("encodes byte and text strings with definite, shortest lengths", () => {
    expect(hex(new Uint8Array(0))).toBe("40");
    expect(hex(Uint8Array.from([1, 2]))).toBe("420102");
    expect(hex(new Uint8Array(24)).slice(0, 4)).toBe("5818");
    expect(hex(new Uint8Array(256)).slice(0, 6)).toBe("590100");
    expect(hex("")).toBe("60");
    expect(hex("a")).toBe("6161");
    expect(hex("ü")).toBe("62c3bc");
    expect(hex("LFCP-WIRE-01")).toBe("6c4c4643502d574952452d3031");
  });

  it.each(["580100", "780161", "980000", "b80000"])(
    "rejects the non-shortest length in %s",
    (h) => {
      expect(codeOf(() => decodeHex(h))).toBe("CBOR_NON_CANONICAL");
    },
  );

  it("rejects invalid UTF-8 and lone surrogates", () => {
    expect(codeOf(() => decodeHex("61ff"))).toBe("CBOR_INVALID_UTF8");
    expect(codeOf(() => decodeHex("62c328"))).toBe("CBOR_INVALID_UTF8");
    expect(codeOf(() => encode("\ud800"))).toBe("CBOR_INVALID_UTF8");
  });
});

describe("arrays", () => {
  it("preserves order exactly (§5.2 rule 5)", () => {
    expect(hex([1, [2, 3]])).toBe("8201820203");
    expect(hex([3, 2, 1])).toBe("83030201");
    expect(decodeHex("83030201")).toEqual([3, 2, 1]);
  });
});

describe("maps (§5.2 rules 3 and 4)", () => {
  it("orders keys by encoded length, then bytewise", () => {
    // 1-byte keys: 0x0a (10), 0x20 (-1), 0x40 (h''), 0x60 (""); 2-byte keys: 0x1864 (100), 0x6161 ("a").
    // Plain bytewise order would put 100 (0x1864) before -1 (0x20); §5.2 rule 4 does not.
    const m = cborMap([
      ["a", null],
      [100, null],
      ["", null],
      [new Uint8Array(0), null],
      [-1, null],
      [10, null],
    ]);
    expect(hex(m)).toBe("a60af620f640f660f61864f66161f6");
  });

  it("does not depend on entry order", () => {
    const a = cborMap([
      [1, "x"],
      [0, "y"],
    ]);
    const b = cborMap([
      [0, "y"],
      [1, "x"],
    ]);
    expect(hex(a)).toBe(hex(b));
    expect(hex(a)).toBe("a2006179016178");
  });

  it("rejects duplicate keys when encoding, including number/bigint twins", () => {
    expect(
      codeOf(() =>
        encode(
          cborMap([
            [1, 1],
            [1, 2],
          ]),
        ),
      ),
    ).toBe("CBOR_DUPLICATE_KEY");
    expect(
      codeOf(() =>
        encode(
          cborMap([
            [1, 1],
            [1n, 1],
          ]),
        ),
      ),
    ).toBe("CBOR_DUPLICATE_KEY");
  });

  it("rejects duplicate and unsorted keys when decoding", () => {
    expect(codeOf(() => decodeHex("a201000100"))).toBe("CBOR_DUPLICATE_KEY");
    expect(codeOf(() => decodeHex("a3010002000100"))).toBe("CBOR_DUPLICATE_KEY");
    expect(codeOf(() => decodeHex("a202000100"))).toBe("CBOR_NON_CANONICAL");
    expect(codeOf(() => decodeHex("a2186400200a"))).toBe("CBOR_NON_CANONICAL");
  });

  it("rejects keys that are not integers, text or byte strings", () => {
    expect(codeOf(() => decodeHex("a18000"))).toBe("CBOR_UNSUPPORTED_TYPE");
    expect(codeOf(() => decodeHex("a1f500"))).toBe("CBOR_UNSUPPORTED_TYPE");
    expect(codeOf(() => cborMap([[true as never, 1]]))).toBe("CBOR_UNSUPPORTED_TYPE");
  });

  it("decodes into an explicit map, never a JS object", () => {
    const m = decodeHex("a2006179016178");
    expect(m).toMatchObject({
      kind: "cbor-map",
      entries: [
        [0, "y"],
        [1, "x"],
      ],
    });
  });
});

describe("rejected encodings", () => {
  it.each([
    ["9fff", "CBOR_INDEFINITE_LENGTH"],
    ["5f4101ff", "CBOR_INDEFINITE_LENGTH"],
    ["7f6161ff", "CBOR_INDEFINITE_LENGTH"],
    ["bf0000ff", "CBOR_INDEFINITE_LENGTH"],
    ["ff", "CBOR_INDEFINITE_LENGTH"],
    ["c000", "CBOR_UNSUPPORTED_TYPE"],
    ["d28440a04040", "CBOR_UNSUPPORTED_TYPE"],
    ["d81840", "CBOR_UNSUPPORTED_TYPE"],
    ["f93c00", "CBOR_UNSUPPORTED_TYPE"],
    ["fa3f800000", "CBOR_UNSUPPORTED_TYPE"],
    ["fb3ff0000000000000", "CBOR_UNSUPPORTED_TYPE"],
    ["f7", "CBOR_UNSUPPORTED_TYPE"],
    ["f0", "CBOR_UNSUPPORTED_TYPE"],
    ["f818", "CBOR_UNSUPPORTED_TYPE"],
    ["1c", "CBOR_UNSUPPORTED_TYPE"],
    ["0000", "CBOR_TRAILING_BYTES"],
    ["", "CBOR_TRUNCATED"],
    ["18", "CBOR_TRUNCATED"],
    ["4200", "CBOR_TRUNCATED"],
    ["8201", "CBOR_TRUNCATED"],
    ["a100", "CBOR_TRUNCATED"],
    ["5bffffffffffffffff", "CBOR_TRUNCATED"],
    ["9bffffffffffffffff", "CBOR_TRUNCATED"],
  ])("decodeStrict(%s) -> %s", (h, code) => {
    expect(codeOf(() => decodeHex(h))).toBe(code);
    expect(isDeterministic(fromHex(h))).toBe(false);
  });

  it("refuses JS values outside the data model", () => {
    for (const v of [undefined, {}, new Map(), () => 1, Symbol("s")]) {
      expect(codeOf(() => encode(v as unknown as CborValue))).toBe("CBOR_UNSUPPORTED_TYPE");
    }
  });

  it("limits nesting depth on both sides", () => {
    let deep: CborValue = [];
    for (let i = 0; i < MAX_DEPTH + 1; i += 1) deep = [deep];
    expect(codeOf(() => encode(deep))).toBe("CBOR_TOO_DEEP");
    const bytes = new Uint8Array(MAX_DEPTH + 2).fill(0x81);
    bytes[bytes.length - 1] = 0x80;
    expect(codeOf(() => decodeStrict(bytes))).toBe("CBOR_TOO_DEEP");
  });
});

// Small deterministic PRNG (mulberry32) so property tests are reproducible.
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const INTS: (number | bigint)[] = [
  0,
  1,
  23,
  24,
  255,
  256,
  65535,
  65536,
  2 ** 32 - 1,
  2 ** 32,
  Number.MAX_SAFE_INTEGER,
  2n ** 53n,
  2n ** 64n - 1n,
  -1,
  -24,
  -25,
  -256,
  -257,
  -65536,
  -65537,
  -(2 ** 32),
  -(2 ** 32) - 1,
  -Number.MAX_SAFE_INTEGER,
  -(2n ** 53n),
  -(2n ** 64n),
];
const CHARS = ["a", "Z", "0", "-", "ü", "€", "😀", "\u0000"];

function randomValue(rand: () => number, depth: number): CborValue {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;
  const kind = Math.floor(rand() * (depth > 2 ? 5 : 7));
  switch (kind) {
    case 0:
      return pick(INTS);
    case 1:
      return Uint8Array.from({ length: Math.floor(rand() * 30) }, () => Math.floor(rand() * 256));
    case 2:
      return Array.from({ length: Math.floor(rand() * 6) }, () => pick(CHARS)).join("");
    case 3:
      return pick([true, false, null]);
    case 4:
      return Math.floor(rand() * 2 ** 31) - 2 ** 30;
    case 5:
      return Array.from({ length: Math.floor(rand() * 4) }, () => randomValue(rand, depth + 1));
    default: {
      const keys = new Map<string, readonly [number | string, CborValue]>();
      const n = Math.floor(rand() * 5);
      for (let i = 0; i < n; i += 1) {
        const key = rand() < 0.5 ? Math.floor(rand() * 300) - 50 : pick(CHARS);
        keys.set(`${typeof key}:${key}`, [key, randomValue(rand, depth + 1)]);
      }
      return cborMap(keys.values());
    }
  }
}

describe("properties", () => {
  it("round-trips: encode -> decodeStrict -> encode gives identical bytes", () => {
    const rand = prng(0x13);
    for (let i = 0; i < 500; i += 1) {
      const value = randomValue(rand, 0);
      const first = encode(value);
      expect(toHex(encode(value))).toBe(toHex(first));
      expect(toHex(encode(decodeStrict(first)))).toBe(toHex(first));
      expect(isDeterministic(first)).toBe(true);
    }
  });

  it("never accepts a mutated encoding unless it is itself deterministic", () => {
    const rand = prng(0x2a);
    let rejected = 0;
    for (let i = 0; i < 500; i += 1) {
      const bytes = encode(randomValue(rand, 0));
      const mutated = Uint8Array.from(bytes);
      const at = Math.floor(rand() * mutated.length);
      mutated[at] = (mutated[at] as number) ^ (1 << Math.floor(rand() * 8));
      let decoded: CborValue | undefined;
      try {
        decoded = decodeStrict(mutated);
      } catch (e) {
        expect(e).toBeInstanceOf(LfcpError);
        rejected += 1;
      }
      // decodeStrict and the re-encode comparison must agree.
      if (decoded !== undefined) expect(toHex(encode(decoded))).toBe(toHex(mutated));
      expect(isDeterministic(mutated)).toBe(decoded !== undefined);
    }
    expect(rejected).toBeGreaterThan(0);
  });

  it("rejects every lengthened head", () => {
    const rand = prng(0x99);
    for (let i = 0; i < 300; i += 1) {
      const bytes = encode(randomValue(rand, 0));
      const ib = bytes[0] as number;
      const major = ib >> 5;
      const ai = ib & 0x1f;
      if (major > 5 || ai >= 24) continue;
      const longer = new Uint8Array(bytes.length + 1);
      longer[0] = (major << 5) | 24;
      longer[1] = ai;
      longer.set(bytes.subarray(1), 2);
      expect(codeOf(() => decodeStrict(longer))).toBe("CBOR_NON_CANONICAL");
      expect(isDeterministic(longer)).toBe(false);
    }
  });
});
