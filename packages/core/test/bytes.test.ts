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

  it("matches the LFCP-WIRE-01 §18.2 invitation URI encoding", () => {
    // LFCP-TEST-VECTORS-01 fixtures.resource.id and case invite_uri expected.resource_b64url
    const resource = fromHex("c8c3041cd1e87009c39a3fe5a02f4812b8ca2733f3aa6c0117530d4cfc3cc241");
    expect(toBase64url(resource)).toBe("yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE");
    // LFCP-TEST-VECTORS-01 case C2_invite_grant expected.record_id and invite_uri expected.grant_id_b64url
    const grant = fromHex("a77e8c2cebad4458e9ca036bef606cd9a7305395127b6a8479e7a088506334c2");
    expect(fromBase64url("p36MLOutRFjpygNr72Bs2acwU5USe2qEeeegiFBjNMI")).toEqual(grant);
  });

  it("encodes a 32-byte Principal ID as the PrincipalRef payload needs", () => {
    // SHARED-OBJECTS-TEST-VECTORS-01 case D03-principal-ref-andrey (the part after "p:")
    const id = fromHex("bd07952a86218f6f57a360520c0403acd3c72f275907e8cb38a3d6362ab4c9f4");
    expect(toBase64url(id)).toBe("vQeVKoYhj29Xo2BSDAQDrNPHLydZB-jLOKPWNiq0yfQ");
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
