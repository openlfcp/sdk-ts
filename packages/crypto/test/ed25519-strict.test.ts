import { ed25519 } from "@noble/curves/ed25519.js";
import { fromHex, toHex } from "@openlfcp/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { importSigningKey, isValidEd25519PublicKey, verifyEd25519 } from "../src/index.js";
import { ed25519Backend, setNativeEd25519ForTesting } from "../src/keys.js";
import { BAD_POINTS, CONSTRUCTED, L_LE, OFF_CURVE, RFC8032 } from "./ed25519-vectors.js";

// Strict Ed25519 (LFCP-WIRE-01 §10.5.1). The edge cases are named hex
// vectors in ed25519-vectors.ts.

const verifyHex = (v: { publicKey: string; message: string; signature: string }) =>
  verifyEd25519(fromHex(v.publicKey), fromHex(v.message), fromHex(v.signature));
const nobleVerifyHex = (v: { publicKey: string; message: string; signature: string }) =>
  ed25519.verify(fromHex(v.signature), fromHex(v.message), fromHex(v.publicKey));

/** Adds two 32-byte little-endian integers (no overflow in these cases). */
function addLE(a: string, b: string): string {
  const x = fromHex(a);
  const y = fromHex(b);
  const out = new Uint8Array(32);
  let carry = 0;
  for (let i = 0; i < 32; i++) {
    const t = (x[i] as number) + (y[i] as number) + carry;
    out[i] = t & 0xff;
    carry = t >> 8;
  }
  return toHex(out);
}

const withR = (signature: string, r: string) => r + signature.slice(64);
const withS = (signature: string, s: string) => signature.slice(0, 64) + s;

// Every vector runs on both backends: they must agree on every input.
describe.each(["native", "noble"] as const)("backend %s", (backend) => {
  beforeAll(() => {
    setNativeEd25519ForTesting(backend === "noble" ? null : undefined);
    expect(ed25519Backend()).toBe(backend);
  });
  afterAll(() => setNativeEd25519ForTesting(undefined));

  describe(`strict Ed25519 (§10.5.1) on ${backend}: RFC 8032 §7.1`, () => {
    for (const [name, v] of Object.entries(RFC8032)) {
      it(`${name} signs and verifies`, () => {
        const key = importSigningKey(fromHex(v.secretKey));
        expect(toHex(key.publicKey)).toBe(v.publicKey);
        expect(toHex(key.sign(fromHex(v.message)))).toBe(v.signature);
        expect(verifyHex(v)).toBe(true);
        expect(isValidEd25519PublicKey(fromHex(v.publicKey))).toBe(true);
      });
    }
  });

  describe(`strict Ed25519 (§10.5.1) on ${backend}: rejections`, () => {
    const base = RFC8032.TEST_1;

    it("rule 1: S = L and S + L are refused", () => {
      expect(verifyHex({ ...base, signature: withS(base.signature, L_LE) })).toBe(false);
      const sPlusL = addLE(base.signature.slice(64), L_LE);
      expect(verifyHex({ ...base, signature: withS(base.signature, sPlusL) })).toBe(false);
    });

    it("rule 2: y ≥ p and x = 0 with the sign bit set are refused, for A and for R", () => {
      for (const bad of [BAD_POINTS.Y_GE_P, BAD_POINTS.X0_SIGN_BIT]) {
        expect(verifyHex({ ...base, publicKey: bad })).toBe(false);
        expect(verifyHex({ ...base, signature: withR(base.signature, bad) })).toBe(false);
        expect(isValidEd25519PublicKey(fromHex(bad))).toBe(false);
      }
    });

    it("rule 3: small-order A and R are refused", () => {
      for (const [name, point] of Object.entries(BAD_POINTS)) {
        if (!name.startsWith("SMALL_ORDER")) continue;
        expect(verifyHex({ ...base, publicKey: point }), name).toBe(false);
        expect(verifyHex({ ...base, signature: withR(base.signature, point) }), name).toBe(false);
        expect(isValidEd25519PublicKey(fromHex(point)), name).toBe(false);
      }
    });

    it("rule 3: a small-order R that both equations accept: noble accepts, strict rejects", () => {
      expect(nobleVerifyHex(CONSTRUCTED.SMALL_ORDER_R)).toBe(true);
      expect(verifyHex(CONSTRUCTED.SMALL_ORDER_R)).toBe(false);
    });

    it("rule 4: a mixed-order R ([r]B + T8): noble's cofactored verify accepts, strict rejects", () => {
      expect(nobleVerifyHex(CONSTRUCTED.MIXED_ORDER_R)).toBe(true);
      expect(verifyHex(CONSTRUCTED.MIXED_ORDER_R)).toBe(false);
    });

    it("an off-curve A or R is refused", () => {
      expect(verifyHex({ ...base, publicKey: OFF_CURVE })).toBe(false);
      expect(verifyHex({ ...base, signature: withR(base.signature, OFF_CURVE) })).toBe(false);
      expect(isValidEd25519PublicKey(fromHex(OFF_CURVE))).toBe(false);
    });

    it("rule 4: a mixed-order A (A + T8): noble's cofactored verify accepts, strict rejects", () => {
      expect(nobleVerifyHex(CONSTRUCTED.MIXED_ORDER_A)).toBe(true);
      expect(verifyHex(CONSTRUCTED.MIXED_ORDER_A)).toBe(false);
      // A mixed-order key is not itself of small order: rule 4 is what refuses it.
      expect(isValidEd25519PublicKey(fromHex(CONSTRUCTED.MIXED_ORDER_A.publicKey))).toBe(true);
    });

    it("returns false, never throws, for malformed input", () => {
      const bad = [
        { ...base, publicKey: "00" },
        { ...base, signature: base.signature.slice(0, 126) },
        { ...base, signature: `${base.signature}00` },
      ];
      for (const v of bad) expect(verifyHex(v)).toBe(false);
      expect(verifyEd25519(null as never, new Uint8Array(), new Uint8Array(64))).toBe(false);
      expect(isValidEd25519PublicKey(new Uint8Array(31))).toBe(false);
    });
  });
});
