import { describe, expect, it } from "vitest";
import { bytesEqual, fromBase64url, fromHex, LfcpError, toBase64url, toHex } from "../src/index.js";

const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : "not-an-LfcpError";
  }
  return undefined;
};

describe("hex", () => {
  it("round-trips lowercase even-length hex", () => {
    const bytes = Uint8Array.from([0, 1, 0x7f, 0x80, 0xfe, 0xff]);
    expect(toHex(bytes)).toBe("00017f80feff");
    expect(fromHex("00017f80feff")).toEqual(bytes);
    expect(fromHex("")).toEqual(new Uint8Array(0));
  });

  it.each(["ABCD", "0xab", "abc", "zz", " ab"])("rejects %j", (text) => {
    expect(codeOf(() => fromHex(text))).toBe("INVALID_HEX");
  });
});

describe("base64url", () => {
  it("round-trips every length from 0 to 40 bytes", () => {
    for (let n = 0; n <= 40; n += 1) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const text = toBase64url(bytes);
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(fromBase64url(text)).toEqual(bytes);
    }
  });

  it("encodes 32 bytes (an ID) as 43 unpadded characters", () => {
    // RFC 4648 §5 by hand: 0x00..0x1f. Published IDs are checked by the
    // conformance runner (LFCP-017; Shared Objects vectors: LFCP-032).
    const id = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(toBase64url(id)).toBe("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
    expect(fromBase64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")).toEqual(id);
  });

  it.each([
    ["AA==", "padding"],
    ["AA=", "padding"],
    ["A+B/", "standard base64 alphabet"],
    ["A", "length 1 modulo 4"],
    ["AAAAA", "length 1 modulo 4"],
    ["AB", "non-zero trailing bits (one byte)"],
    ["AAB", "non-zero trailing bits (two bytes)"],
    ["AA A", "whitespace"],
  ])("rejects %j (%s)", (text) => {
    expect(codeOf(() => fromBase64url(text))).toBe("INVALID_BASE64URL");
  });

  it("accepts canonical short forms", () => {
    expect(fromBase64url("")).toEqual(new Uint8Array(0));
    expect(fromBase64url("AA")).toEqual(Uint8Array.from([0]));
    expect(fromBase64url("AAE")).toEqual(Uint8Array.from([0, 1]));
    expect(fromBase64url("_w")).toEqual(Uint8Array.from([0xff]));
  });
});

describe("bytesEqual", () => {
  it("compares contents and lengths", () => {
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 2]))).toBe(true);
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 3]))).toBe(false);
    expect(bytesEqual(Uint8Array.from([1]), Uint8Array.from([1, 0]))).toBe(false);
  });
});
