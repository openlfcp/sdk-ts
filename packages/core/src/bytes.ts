import { LfcpError } from "./errors.js";

const HEX = "0123456789abcdef";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_VALUE = new Map([...B64URL].map((c, i) => [c, i]));

/** Lowercase hexadecimal, two digits per byte. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX.charAt(b >> 4) + HEX.charAt(b & 0x0f);
  return out;
}

/**
 * Parses lowercase, even-length hexadecimal. Upper case, a `0x` prefix and
 * odd lengths are rejected with `INVALID_HEX`.
 */
export function fromHex(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) {
    throw new LfcpError(
      "INVALID_HEX",
      "expected lowercase hexadecimal with an even number of digits",
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Unpadded base64url (RFC 4648 §5), the encoding LFCP uses in URIs and references. */
export function toBase64url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n =
      ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out +=
      B64URL.charAt(n >> 18) +
      B64URL.charAt((n >> 12) & 63) +
      B64URL.charAt((n >> 6) & 63) +
      B64URL.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += B64URL.charAt(n >> 18) + B64URL.charAt((n >> 12) & 63);
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += B64URL.charAt(n >> 18) + B64URL.charAt((n >> 12) & 63) + B64URL.charAt((n >> 6) & 63);
  }
  return out;
}

/**
 * Parses canonical unpadded base64url. Rejects padding, characters outside
 * the URL-safe alphabet, a length of 1 modulo 4 and non-zero trailing bits,
 * so every byte string has exactly one accepted encoding.
 */
export function fromBase64url(text: string): Uint8Array {
  const fail = (why: string): never => {
    throw new LfcpError("INVALID_BASE64URL", `not canonical unpadded base64url: ${why}`);
  };
  const rem = text.length % 4;
  if (rem === 1) fail("length is 1 modulo 4");
  const values: number[] = [];
  for (const c of text) {
    const v = B64URL_VALUE.get(c);
    if (v === undefined)
      fail(c === "=" ? "padding is not allowed" : `character ${JSON.stringify(c)}`);
    values.push(v as number);
  }
  // The last character of a 2- or 3-character group carries 4 or 2 bits that
  // are not part of any byte; they must be zero (RFC 4648 §3.5).
  const last = values[values.length - 1] ?? 0;
  if ((rem === 2 && (last & 0x0f) !== 0) || (rem === 3 && (last & 0x03) !== 0))
    fail("non-zero trailing bits");
  const out = new Uint8Array((values.length * 6) >> 3);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const v of values) {
    acc = ((acc << 6) | v) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Byte-for-byte equality. Not constant-time: do not use it to compare secrets. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
