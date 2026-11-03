import { LfcpError } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { cborMap, encode } from "../src/cbor/index.js";
import {
  controlBodyToCbor,
  DEVICE_CERT_LABEL,
  decodeControlRecord,
  parseDeviceCertificate,
  principalDescriptorToCbor,
} from "../src/index.js";
import { cert, deepChain, id, keys, personal, RESOURCE } from "./identity.js";

// LFCP-WIRE-01 §7.3 bounds are refused on the raw bytes, before the CBOR
// decoder runs (review of #7, R1). The decoder would report a declared
// count beyond the input as CBOR_TRUNCATED; a refusal by the scan is
// INVALID_STRUCTURE "(scan)", which shows that no element was walked or
// decoded. Large inputs check that the refusal does not depend on their size.

const head = (major: number, n: number): Uint8Array => {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of((major << 5) | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
};
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const bstr = (b: Uint8Array) => cat(head(2, b.length), b);

/** A certificate whose mask is `mask` (raw bytes after the array head) declared with `count`. */
function certificateWithMask(count: number, maskItems: Uint8Array, scope = cat(head(4, 0))) {
  const payload = cat(
    head(4, 7),
    encode(DEVICE_CERT_LABEL),
    encode(id(1)),
    encode(principalDescriptorToCbor(keys(2).descriptor)),
    head(0, 0),
    head(4, count),
    maskItems,
    scope,
    encode(new Uint8Array(16)),
  );
  const protectedBytes = encode(
    cborMap([
      [1, -8],
      [4, id(1)],
    ]),
  );
  return cat(head(4, 4), bstr(protectedBytes), head(5, 0), bstr(payload), bstr(new Uint8Array(64)));
}

const scanRefusal = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    if (e instanceof LfcpError) return `${e.code}${e.message.includes("(scan)") ? " scan" : ""}`;
    throw e;
  }
  return "ACCEPTED";
};

describe("certificate bounds on raw bytes (§7.3)", () => {
  it("refuses a mask of a million codes before decoding it", () => {
    const bytes = certificateWithMask(1_000_000, new Uint8Array(1_000_000));
    expect(bytes.length).toBeGreaterThan(1_000_000);
    expect(scanRefusal(() => parseDeviceCertificate(bytes))).toBe("INVALID_STRUCTURE scan");
  });

  it("refuses a declared count beyond the limit without walking its elements", () => {
    // Declared counts with no elements at all: the decoder would say CBOR_TRUNCATED.
    expect(
      scanRefusal(() => parseDeviceCertificate(certificateWithMask(1_000_000, new Uint8Array()))),
    ).toBe("INVALID_STRUCTURE scan");
    expect(
      scanRefusal(() =>
        parseDeviceCertificate(certificateWithMask(1, Uint8Array.of(1), head(4, 65))),
      ),
    ).toBe("INVALID_STRUCTURE scan");
  });

  it("refuses large byte strings in the mask without copying them", () => {
    const big = bstr(new Uint8Array(262_144));
    const items = cat(...Array.from({ length: 33 }, () => big));
    expect(scanRefusal(() => parseDeviceCertificate(certificateWithMask(33, items)))).toBe(
      "INVALID_STRUCTURE scan",
    );
    expect(scanRefusal(() => parseDeviceCertificate(certificateWithMask(1, big)))).toBe(
      "INVALID_STRUCTURE scan",
    );
  });

  it("accepts what the decoder accepts", () => {
    const c = cert(personal(2, [1, 2, 12, 2n ** 64n - 1n]), 1);
    expect(parseDeviceCertificate(c.signed.bytes).payload).toEqual(c.payload);
  });
});

describe("chain bounds inside Control Records (§15 field 5, §23.3 field 2, §17.4 field 1)", () => {
  /** A raw record of `type` whose body has `chain` (raw bytes) under `key`. */
  function record(type: number, key: number, chain: Uint8Array) {
    const body = cat(head(5, 1), head(0, key), chain);
    const payload = cat(
      head(5, 6),
      head(0, 0),
      encode(RESOURCE),
      head(0, 1),
      head(0, 1),
      head(0, 2),
      encode(new Uint8Array(32)),
      head(0, 3),
      head(0, type),
      head(0, 4),
      encode(id(1)),
      head(0, 5),
      body,
    );
    const protectedBytes = encode(
      cborMap([
        [1, -8],
        [4, id(1)],
      ]),
    );
    return cat(
      head(4, 4),
      bstr(protectedBytes),
      head(5, 0),
      bstr(payload),
      bstr(new Uint8Array(64)),
    );
  }

  it("refuses a chain of more than four certificates before reading any", () => {
    for (const [type, key] of [
      [0, 5],
      [6, 2],
      [9, 1],
    ] as const)
      expect(scanRefusal(() => decodeControlRecord(record(type, key, head(4, 1_000_000))))).toBe(
        "INVALID_STRUCTURE scan",
      );
  });

  it("refuses a managing leaf four deep and an oversized embedded mask", () => {
    const chain = (certs: Uint8Array[]) => cat(head(4, certs.length), ...certs.map(bstr));
    const deep = deepChain(true).map((c) => c.signed.bytes);
    expect(scanRefusal(() => decodeControlRecord(record(9, 1, chain(deep))))).toBe(
      "INVALID_STRUCTURE scan",
    );
    const huge = certificateWithMask(1_000_000, new Uint8Array());
    expect(scanRefusal(() => decodeControlRecord(record(9, 1, chain([huge]))))).toBe(
      "INVALID_STRUCTURE scan",
    );
  });

  it("leaves other records to the decoder", () => {
    const value = controlBodyToCbor({
      type: "CAPABILITY_REVOKE",
      grantId: new Uint8Array(32) as never,
    });
    expect(scanRefusal(() => decodeControlRecord(record(2, 0, encode(value))))).not.toContain(
      "scan",
    );
  });
});
