import { LfcpError } from "@openlfcp/core";
import { strictUtf8Decoder, utf8Encoder } from "./text.js";
import { type CborValue, isCborKey, isCborMap, MAX_DEPTH, UINT64_MAX } from "./value.js";

/** Byte order of encoded map keys (§5.2 rule 4): shorter encodings first, then bytewise. */
export function compareEncodedKeys(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i += 1) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return 0;
}

class Writer {
  private buf = new Uint8Array(256);
  private len = 0;

  private reserve(n: number): void {
    if (this.len + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.len + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
  }

  byte(b: number): void {
    this.reserve(1);
    this.buf[this.len++] = b;
  }

  bytes(b: Uint8Array): void {
    this.reserve(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
  }

  /** Major type and argument in the shortest form (§5.2 rule 1). */
  head(major: number, n: number | bigint): void {
    const m = major << 5;
    const v = BigInt(n);
    if (v < 24n) {
      this.byte(m | Number(v));
    } else if (v <= 0xffn) {
      this.byte(m | 24);
      this.byte(Number(v));
    } else if (v <= 0xffffn) {
      this.byte(m | 25);
      this.bigEndian(v, 2);
    } else if (v <= 0xffff_ffffn) {
      this.byte(m | 26);
      this.bigEndian(v, 4);
    } else {
      this.byte(m | 27);
      this.bigEndian(v, 8);
    }
  }

  private bigEndian(v: bigint, size: number): void {
    for (let i = size - 1; i >= 0; i -= 1) this.byte(Number((v >> BigInt(8 * i)) & 0xffn));
  }

  result(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

function writeInteger(w: Writer, value: number | bigint): void {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new LfcpError(
      Number.isInteger(value) ? "CBOR_OUT_OF_RANGE" : "CBOR_UNSUPPORTED_TYPE",
      Number.isInteger(value)
        ? "integers beyond the safe range must be bigint"
        : "floating-point numbers are not used by LFCP",
    );
  }
  const v = BigInt(value);
  if (v > UINT64_MAX || v < -(UINT64_MAX + 1n))
    throw new LfcpError("CBOR_OUT_OF_RANGE", "integer outside -2^64 .. 2^64-1");
  if (v >= 0n) w.head(0, v);
  else w.head(1, -1n - v);
}

function writeValue(w: Writer, value: CborValue, depth: number): void {
  if (depth > MAX_DEPTH) throw new LfcpError("CBOR_TOO_DEEP", `nesting deeper than ${MAX_DEPTH}`);
  if (value === null) {
    w.byte(0xf6);
    return;
  }
  if (typeof value === "boolean") {
    w.byte(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === "number" || typeof value === "bigint") {
    writeInteger(w, value);
    return;
  }
  if (value instanceof Uint8Array) {
    w.head(2, value.length);
    w.bytes(value);
    return;
  }
  if (typeof value === "string") {
    const raw = utf8Encoder.encode(value);
    // TextEncoder replaces lone surrogates; refuse instead of changing the text.
    if (strictUtf8Decoder.decode(raw) !== value)
      throw new LfcpError("CBOR_INVALID_UTF8", "string contains lone surrogates");
    w.head(3, raw.length);
    w.bytes(raw);
    return;
  }
  if (Array.isArray(value)) {
    w.head(4, value.length);
    for (const item of value as readonly CborValue[]) writeValue(w, item, depth + 1);
    return;
  }
  if (isCborMap(value)) {
    const encoded = value.entries.map(([k, v]) => {
      if (!isCborKey(k))
        throw new LfcpError(
          "CBOR_UNSUPPORTED_TYPE",
          "map keys must be integers, text or byte strings",
        );
      return [encode(k), v] as const;
    });
    encoded.sort((a, b) => compareEncodedKeys(a[0], b[0]));
    for (let i = 1; i < encoded.length; i += 1) {
      if (
        compareEncodedKeys(
          (encoded[i - 1] as readonly [Uint8Array, CborValue])[0],
          (encoded[i] as readonly [Uint8Array, CborValue])[0],
        ) === 0
      ) {
        throw new LfcpError("CBOR_DUPLICATE_KEY", "map contains a duplicate key");
      }
    }
    w.head(5, encoded.length);
    for (const [k, v] of encoded) {
      w.bytes(k);
      writeValue(w, v, depth + 1);
    }
    return;
  }
  throw new LfcpError("CBOR_UNSUPPORTED_TYPE", `cannot encode ${typeof value} as LFCP CBOR`);
}

/**
 * Deterministic CBOR encoding (LFCP-WIRE-01 §5.2): shortest heads,
 * definite lengths, map keys sorted by encoded length then bytewise,
 * duplicate keys rejected, array order kept, no tags.
 */
export function encode(value: CborValue): Uint8Array {
  const w = new Writer();
  writeValue(w, value, 0);
  return w.result();
}
