import { bytesEqual, LfcpError } from "@openlfcp/core";
import { compareEncodedKeys, encode } from "./encode.js";
import { strictUtf8Decoder } from "./text.js";
import { type CborKey, type CborMap, type CborValue, cborMap, MAX_DEPTH } from "./value.js";

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

const asInteger = (v: bigint): number | bigint => (v <= MAX_SAFE && v >= -MAX_SAFE ? Number(v) : v);

class Reader {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}

  need(n: number | bigint): number {
    if (BigInt(this.pos) + BigInt(n) > BigInt(this.bytes.length))
      throw new LfcpError("CBOR_TRUNCATED", "input ends inside an item");
    return Number(n);
  }

  byte(): number {
    this.need(1);
    return this.bytes[this.pos++] as number;
  }

  take(n: number): Uint8Array {
    this.need(n);
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** Reads an argument and enforces the shortest form (§5.2 rule 1). */
  argument(ai: number): bigint {
    if (ai < 24) return BigInt(ai);
    if (ai === 31)
      throw new LfcpError(
        "CBOR_INDEFINITE_LENGTH",
        "indefinite lengths are not allowed (§5.2 rule 2)",
      );
    if (ai > 27)
      throw new LfcpError("CBOR_UNSUPPORTED_TYPE", "reserved additional information value");
    const size = 1 << (ai - 24);
    let v = 0n;
    for (const b of this.take(size)) v = (v << 8n) | BigInt(b);
    const floor = [24n, 0x100n, 0x1_0000n, 0x1_0000_0000n][ai - 24] as bigint;
    if (v < floor)
      throw new LfcpError("CBOR_NON_CANONICAL", "integer or length not in its shortest form");
    return v;
  }
}

function readKey(r: Reader, depth: number): CborKey {
  const v = readValue(r, depth);
  if (
    typeof v === "number" ||
    typeof v === "bigint" ||
    typeof v === "string" ||
    v instanceof Uint8Array
  )
    return v;
  throw new LfcpError("CBOR_UNSUPPORTED_TYPE", "map keys must be integers, text or byte strings");
}

function readValue(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new LfcpError("CBOR_TOO_DEEP", `nesting deeper than ${MAX_DEPTH}`);
  const ib = r.byte();
  const major = ib >> 5;
  const ai = ib & 0x1f;
  switch (major) {
    case 0:
      return asInteger(r.argument(ai));
    case 1:
      return asInteger(-1n - r.argument(ai));
    case 2:
      return r.take(r.need(r.argument(ai)));
    case 3: {
      const raw = r.take(r.need(r.argument(ai)));
      try {
        return strictUtf8Decoder.decode(raw);
      } catch {
        throw new LfcpError("CBOR_INVALID_UTF8", "text string is not well-formed UTF-8");
      }
    }
    case 4: {
      const count = r.argument(ai);
      r.need(count); // every item takes at least one byte
      const items: CborValue[] = [];
      for (let i = 0n; i < count; i += 1n) items.push(readValue(r, depth + 1));
      return items;
    }
    case 5: {
      const count = r.argument(ai);
      r.need(count * 2n);
      const entries: [CborKey, CborValue][] = [];
      const seen = new Set<string>();
      let previous: Uint8Array | null = null;
      for (let i = 0n; i < count; i += 1n) {
        const start = r.pos;
        const key = readKey(r, depth + 1);
        const keyBytes = r.bytes.subarray(start, r.pos);
        const id = Array.from(keyBytes, (b) => b.toString(16).padStart(2, "0")).join("");
        if (seen.has(id)) throw new LfcpError("CBOR_DUPLICATE_KEY", "map contains a duplicate key");
        if (previous && compareEncodedKeys(previous, keyBytes) > 0) {
          throw new LfcpError(
            "CBOR_NON_CANONICAL",
            "map keys are not in deterministic order (§5.2 rule 4)",
          );
        }
        seen.add(id);
        previous = keyBytes;
        entries.push([key, readValue(r, depth + 1)]);
      }
      return cborMap(entries);
    }
    case 6:
      throw new LfcpError("CBOR_UNSUPPORTED_TYPE", "CBOR tags are not used by LFCP (§5.2 rule 6)");
    default:
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 31) throw new LfcpError("CBOR_INDEFINITE_LENGTH", "unexpected break code");
      throw new LfcpError(
        "CBOR_UNSUPPORTED_TYPE",
        "floats, undefined and other simple values are not used by LFCP",
      );
  }
}

/**
 * Decodes exactly one deterministic CBOR item (LFCP-WIRE-01 §5.2) and
 * rejects anything else: indefinite lengths, non-shortest heads, unsorted
 * or duplicate map keys, tags, floats and other simple values, invalid
 * UTF-8, truncated input and trailing bytes.
 */
export function decodeStrict(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const value = readValue(r, 0);
  if (r.pos !== bytes.length)
    throw new LfcpError("CBOR_TRAILING_BYTES", "bytes remain after the top-level item");
  return value;
}

/**
 * The §5.2 receiver check: `bytes` decode strictly and re-encode to exactly
 * the same bytes. Signature and object-ID checks still use the received
 * bytes; this only decides whether they are the deterministic encoding.
 */
export function isDeterministic(bytes: Uint8Array): boolean {
  let value: CborValue;
  try {
    value = decodeStrict(bytes);
  } catch (e) {
    if (e instanceof LfcpError) return false;
    throw e;
  }
  return bytesEqual(encode(value), bytes);
}

export type { CborMap };
