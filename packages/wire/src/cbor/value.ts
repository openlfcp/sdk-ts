import { LfcpError } from "@openlfcp/core";

/**
 * The CBOR data model LFCP uses (LFCP-WIRE-01 §5). Everything else is
 * unrepresentable here and rejected by the decoder:
 *
 * - integers (major types 0 and 1, §5.1): `number` when it is a safe
 *   integer, `bigint` otherwise, in -2^64 .. 2^64-1;
 * - byte strings: `Uint8Array`; text strings: `string` (well-formed UTF-8);
 * - arrays: `CborValue[]`, order preserved (§5.2 rule 5);
 * - maps: `CborMap`, an explicit entry list, never a JS object (§5.2 rule 4);
 * - `true`, `false`, `null`.
 *
 * No tags (§5.2 rule 6: LFCP requires none in deterministic structures), no
 * floating-point numbers, no `undefined`, no other simple values.
 */
export type CborValue = CborKey | boolean | null | readonly CborValue[] | CborMap;

/** Map keys: integers, text strings and byte strings. */
export type CborKey = number | bigint | string | Uint8Array;

/** A CBOR map. Entry order is irrelevant on input; encoding sorts the keys. */
export interface CborMap {
  readonly kind: "cbor-map";
  readonly entries: readonly (readonly [CborKey, CborValue])[];
}

export function isCborMap(value: unknown): value is CborMap {
  return (
    typeof value === "object" && value !== null && (value as { kind?: unknown }).kind === "cbor-map"
  );
}

export function isCborKey(value: unknown): value is CborKey {
  return (
    typeof value === "number" ||
    typeof value === "bigint" ||
    typeof value === "string" ||
    value instanceof Uint8Array
  );
}

/** Builds a map from `[key, value]` pairs. Duplicate keys are rejected when encoding. */
export function cborMap(entries: Iterable<readonly [CborKey, CborValue]>): CborMap {
  const list = [...entries].map(([k, v]) => {
    if (!isCborKey(k))
      throw new LfcpError(
        "CBOR_UNSUPPORTED_TYPE",
        "map keys must be integers, text or byte strings",
      );
    return [k, v] as const;
  });
  return Object.freeze({ kind: "cbor-map", entries: Object.freeze(list) });
}

/** Largest nesting depth accepted when encoding or decoding; an SDK safety limit, not a protocol rule. */
export const MAX_DEPTH = 128;

export const UINT64_MAX = (1n << 64n) - 1n;
