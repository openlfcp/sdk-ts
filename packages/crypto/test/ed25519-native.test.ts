import { ed25519 } from "@noble/curves/ed25519.js";
import { fromHex, toHex } from "@openlfcp/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type AsyncEd25519Verify,
  detectNativeEd25519,
  detectWebCryptoEd25519,
  passesProbes,
  passesProbesAsync,
} from "../src/ed25519-native.js";
import {
  detectEd25519Backend,
  ed25519Backend,
  generateSigningKeyPair,
  prepareEd25519Verify,
  setNativeEd25519ForTesting,
  setWebCryptoEd25519ForTesting,
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
  vi.unstubAllGlobals();
  setNativeEd25519ForTesting(undefined);
  setWebCryptoEd25519ForTesting(undefined);
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

// WebCrypto (browsers, Obsidian mobile): asynchronous, so the receive path
// pre-verifies with prepareEd25519Verify and verifyEd25519 uses the answer.
// Node 24 has WebCrypto Ed25519, so the real backend is exercised here with
// the synchronous native one forced off.

/** The WebCrypto answer for one input: prepare, then the synchronous verify. */
async function viaWebCrypto(a: Uint8Array, m: Uint8Array, s: Uint8Array): Promise<boolean> {
  setNativeEd25519ForTesting(null);
  await prepareEd25519Verify(a, m, s);
  return verifyEd25519(a, m, s);
}

function nobleAnswer(a: Uint8Array, m: Uint8Array, s: Uint8Array): boolean {
  setNativeEd25519ForTesting(null);
  return verifyEd25519(a, m, s);
}

/** Every input of the native agreement tests above, as [A, M, signature]. */
function agreementCases(): [Uint8Array, Uint8Array, Uint8Array][] {
  const out: [Uint8Array, Uint8Array, Uint8Array][] = [];
  const [a, m, s] = valid();
  const sHex = toHex(s);
  const points = [...Object.values(BAD_POINTS), OFF_CURVE, base.publicKey];
  for (const pa of points)
    for (const pr of points) out.push([fromHex(pa), m, fromHex(pr + sHex.slice(64))]);
  for (const tail of [L_LE, `${"ff".repeat(31)}0f`, `${sHex.slice(64, 126)}${"f0"}`])
    out.push([a, m, fromHex(sHex.slice(0, 64) + tail)]);
  for (const v of [...Object.values(RFC8032), ...Object.values(CONSTRUCTED)])
    out.push([fromHex(v.publicKey), fromHex(v.message), fromHex(v.signature)]);
  for (let i = 0; i < 10; i++) {
    const key = generateSigningKeyPair();
    const msg = Uint8Array.from({ length: 1 + i * 7 }, (_, j) => (i * 31 + j) & 0xff);
    const sig = key.sign(msg);
    const pk = key.publicKey;
    out.push(
      [pk, msg, sig],
      [flip(pk, i % 32, i % 8), msg, sig],
      [pk, flip(msg, i % msg.length, i % 8), sig],
      [pk, msg, flip(sig, i % 32, i % 8)],
      [pk, msg, flip(sig, 32 + (i % 32), i % 8)],
      [pk, msg, flip(sig, 31, 7)],
      [flip(pk, 31, 7), msg, sig],
    );
  }
  out.push([a.subarray(0, 31), m, s], [a, m, s.subarray(0, 63)], [new Uint8Array(33), m, s]);
  return out;
}

describe("WebCrypto Ed25519 detection", () => {
  it("is used when there is no synchronous native backend", async () => {
    setNativeEd25519ForTesting(null);
    expect(await detectEd25519Backend()).toBe("webcrypto");
    expect(ed25519Backend()).toBe("webcrypto");
  });

  it("is not consulted when the synchronous native backend exists", async () => {
    const web = vi.fn<AsyncEd25519Verify>(async () => true);
    setWebCryptoEd25519ForTesting(web);
    await prepareEd25519Verify(...valid());
    expect(web).not.toHaveBeenCalled();
    expect(await detectEd25519Backend()).toBe("native");
  });

  it("detects once and caches the result", async () => {
    const subtle = globalThis.crypto.subtle;
    const importKey = vi.fn(subtle.importKey.bind(subtle));
    vi.stubGlobal("crypto", { subtle: { importKey, verify: subtle.verify.bind(subtle) } });
    setNativeEd25519ForTesting(null);
    setWebCryptoEd25519ForTesting(undefined);
    for (let i = 0; i < 5; i++) expect(await viaWebCrypto(...valid())).toBe(true);
    // Three distinct probe keys, then the one key of the input, imported once.
    expect(importKey).toHaveBeenCalledTimes(4);
  });

  it("falls back to noble when the platform has no WebCrypto", async () => {
    vi.stubGlobal("crypto", {});
    expect(await detectWebCryptoEd25519()).toBeNull();
    setNativeEd25519ForTesting(null);
    setWebCryptoEd25519ForTesting(undefined);
    expect(await detectEd25519Backend()).toBe("noble");
    expect(await viaWebCrypto(...valid())).toBe(true);
    const [a, , s] = valid();
    expect(await viaWebCrypto(a, Uint8Array.of(1), s)).toBe(false);
    expect(await viaWebCrypto(...hex(CONSTRUCTED.MIXED_ORDER_A))).toBe(false);
  });

  it("refuses a WebCrypto without Ed25519 ('unsupported' at import)", async () => {
    vi.stubGlobal("crypto", {
      subtle: {
        importKey: () => Promise.reject(new DOMException("unsupported", "NotSupportedError")),
        verify: () => Promise.resolve(true),
      },
    });
    expect(await detectWebCryptoEd25519()).toBeNull();
  });

  it("refuses a cofactored backend: the async probes catch it", async () => {
    const cofactored: AsyncEd25519Verify = async (a, m, s) => ed25519.verify(s, m, a);
    expect(await passesProbesAsync(cofactored)).toBe(false);
    expect(await passesProbesAsync(async () => true)).toBe(false);
    expect(await passesProbesAsync(async (a, m, s) => verifyEd25519Noble(a, m, s))).toBe(true);
  });
});

describe("WebCrypto Ed25519 at verification", () => {
  it("decides the synchronous verify for the exact prepared bytes, once", async () => {
    // A lying backend shows whose answer is used; real ones pass the probes.
    setWebCryptoEd25519ForTesting(async () => false);
    const input = valid();
    expect(await viaWebCrypto(...input)).toBe(false);
    expect(verifyEd25519(...input)).toBe(true); // used once; then noble
    await prepareEd25519Verify(...input);
    const [a, m, s] = input;
    expect(verifyEd25519(a, Uint8Array.of(...m, 0), s)).toBe(false); // other message: noble
  });

  it("lets noble decide when WebCrypto rejects ('unsupported')", async () => {
    const web = vi.fn<AsyncEd25519Verify>(() => Promise.reject(new Error("unsupported")));
    setWebCryptoEd25519ForTesting(web);
    expect(await viaWebCrypto(...valid())).toBe(true);
    const [a, , s] = valid();
    expect(await viaWebCrypto(a, Uint8Array.of(1), s)).toBe(false);
    expect(await viaWebCrypto(...hex(CONSTRUCTED.MIXED_ORDER_R))).toBe(false);
    expect(web).toHaveBeenCalled();
  });

  it("agrees with noble on valid, invalid, malformed and non-canonical inputs", async () => {
    const real = await detectWebCryptoEd25519();
    expect(real).not.toBeNull();
    const web = vi.fn(real as AsyncEd25519Verify);
    setWebCryptoEd25519ForTesting(web);
    for (const [a, m, s] of agreementCases()) {
      const noble = nobleAnswer(a, m, s);
      expect(await viaWebCrypto(a, m, s), `${toHex(a)} ${toHex(m)} ${toHex(s)}`).toBe(noble);
    }
    expect(web.mock.calls.length).toBeGreaterThan(50);
  });
});

function hex(v: { publicKey: string; message: string; signature: string }) {
  return [fromHex(v.publicKey), fromHex(v.message), fromHex(v.signature)] as const;
}
