import { ed25519 } from "@noble/curves/ed25519.js";
import { fromHex, toHex } from "@openlfcp/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { detectNativeEd25519, passesProbes } from "../src/ed25519-native.js";
import {
  ed25519Backend,
  generateSigningKeyPair,
  setNativeEd25519ForTesting,
  verifyEd25519,
  verifyEd25519Noble,
} from "../src/keys.js";
import { BAD_POINTS, CONSTRUCTED, L_LE, OFF_CURVE, RFC8032 } from "./ed25519-vectors.js";

// The native backend (Node's crypto) against the strict noble path: same
// answer on every input, a fallback when native is missing or throws, and a
// probe that refuses a backend with different (cofactored) semantics.

const HOST_PROCESS_GLOBAL = "process";
const host = (globalThis as Record<string, unknown>)[HOST_PROCESS_GLOBAL] as {
  getBuiltinModule: (id: string) => unknown;
};

const base = RFC8032.TEST_1;
const valid = () =>
  [fromHex(base.publicKey), fromHex(base.message), fromHex(base.signature)] as const;

afterEach(() => {
  vi.restoreAllMocks();
  setNativeEd25519ForTesting(undefined);
});

describe("native Ed25519 detection", () => {
  it("uses Node's crypto in Node", () => {
    expect(ed25519Backend()).toBe("native");
  });

  it("detects once and caches the result", () => {
    const spy = vi.spyOn(host, "getBuiltinModule");
    setNativeEd25519ForTesting(undefined);
    for (let i = 0; i < 5; i++) expect(verifyEd25519(...valid())).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("falls back to noble when the platform has no native Ed25519", () => {
    vi.spyOn(host, "getBuiltinModule").mockReturnValue(undefined);
    setNativeEd25519ForTesting(undefined);
    expect(ed25519Backend()).toBe("noble");
    expect(verifyEd25519(...valid())).toBe(true);
    const [a, , s] = valid();
    expect(verifyEd25519(a, Uint8Array.of(1), s)).toBe(false);
    expect(verifyHex(CONSTRUCTED.MIXED_ORDER_A)).toBe(false);
  });

  it("falls back to noble when the native module lacks verify", () => {
    vi.spyOn(host, "getBuiltinModule").mockReturnValue({});
    expect(detectNativeEd25519()).toBeNull();
  });

  it("refuses a backend that throws 'unsupported' at detection", () => {
    vi.spyOn(host, "getBuiltinModule").mockReturnValue({
      createPublicKey: () => {
        throw new Error("unsupported");
      },
      verify: () => true,
    });
    expect(detectNativeEd25519()).toBeNull();
  });

  it("refuses a cofactored backend: the probes catch the different semantics", () => {
    const cofactored = (a: Uint8Array, m: Uint8Array, s: Uint8Array) => ed25519.verify(s, m, a);
    expect(passesProbes(cofactored)).toBe(false);
    expect(passesProbes(() => true)).toBe(false);
    expect(passesProbes(verifyEd25519Noble)).toBe(true);
  });
});

describe("native Ed25519 that throws at verification", () => {
  it("lets noble decide each call", () => {
    const native = vi.fn(() => {
      throw new Error("unsupported");
    });
    setNativeEd25519ForTesting(native);
    expect(verifyEd25519(...valid())).toBe(true);
    const [a, , s] = valid();
    expect(verifyEd25519(a, Uint8Array.of(1), s)).toBe(false);
    expect(verifyHex(CONSTRUCTED.MIXED_ORDER_R)).toBe(false);
    expect(native).toHaveBeenCalled();
  });
});

const verifyHex = (v: { publicKey: string; message: string; signature: string }) =>
  verifyEd25519(fromHex(v.publicKey), fromHex(v.message), fromHex(v.signature));

/** Answers of the native and noble paths for one input. */
function both(a: Uint8Array, m: Uint8Array, s: Uint8Array): [boolean, boolean] {
  setNativeEd25519ForTesting(undefined);
  expect(ed25519Backend()).toBe("native");
  const native = verifyEd25519(a, m, s);
  setNativeEd25519ForTesting(null);
  const noble = verifyEd25519(a, m, s);
  return [native, noble];
}

function flip(bytes: Uint8Array, index: number, bit: number): Uint8Array {
  const out = Uint8Array.from(bytes);
  out[index] = (out[index] as number) ^ (1 << bit);
  return out;
}

describe("native and noble agree", () => {
  it("on every combination of the edge-case points as A and as R", () => {
    const points = [...Object.values(BAD_POINTS), OFF_CURVE, base.publicKey];
    const [, m, s] = valid();
    for (const a of points) {
      for (const r of points) {
        const sig = fromHex(r + toHex(s).slice(64));
        const [native, noble] = both(fromHex(a), m, sig);
        expect(native, `A=${a} R=${r}`).toBe(noble);
      }
    }
  });

  it("on S at and above L, and with the top bits of S set", () => {
    const [a, m, s] = valid();
    const sHex = toHex(s);
    for (const tail of [L_LE, `${"ff".repeat(31)}0f`, `${sHex.slice(64, 126)}${"f0"}`]) {
      const [native, noble] = both(a, m, fromHex(sHex.slice(0, 64) + tail));
      expect(native).toBe(noble);
      expect(native).toBe(false);
    }
  });

  it("on every constructed and RFC vector", () => {
    for (const v of [...Object.values(RFC8032), ...Object.values(CONSTRUCTED)]) {
      const [native, noble] = both(fromHex(v.publicKey), fromHex(v.message), fromHex(v.signature));
      expect(native).toBe(noble);
    }
  });

  it("on random valid signatures and single-bit mutations of each part", () => {
    for (let i = 0; i < 40; i++) {
      const key = generateSigningKeyPair();
      const m = Uint8Array.from({ length: i * 7 }, (_, j) => (i * 31 + j) & 0xff);
      const s = key.sign(m);
      const a = key.publicKey;
      const cases: [Uint8Array, Uint8Array, Uint8Array][] = [
        [a, m, s],
        [flip(a, i % 32, i % 8), m, s],
        [a, m.length > 0 ? flip(m, i % m.length, i % 8) : Uint8Array.of(0), s],
        [a, m, flip(s, i % 32, i % 8)],
        [a, m, flip(s, 32 + (i % 32), i % 8)],
        [a, m, flip(s, 31, 7)],
        [flip(a, 31, 7), m, s],
      ];
      for (const [ca, cm, cs] of cases) {
        const [native, noble] = both(ca, cm, cs);
        expect(native, `${toHex(ca)} ${toHex(cm)} ${toHex(cs)}`).toBe(noble);
      }
      expect(both(a, m, s)).toEqual([true, true]);
    }
  });

  it("on malformed input: both return false and never throw", () => {
    const [a, m, s] = valid();
    for (const [ca, cs] of [
      [a.subarray(0, 31), s],
      [a, s.subarray(0, 63)],
      [new Uint8Array(33), s],
      [a, new Uint8Array(65)],
    ] as const) {
      expect(both(ca, m, cs)).toEqual([false, false]);
    }
  });
});
