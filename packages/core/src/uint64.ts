import { LfcpError } from "./errors.js";

/**
 * Unsigned 64-bit values of LFCP-WIRE-01 as branded bigints.
 *
 * Constructions such as `uint64_be(epoch)` (§11, §12) need the full uint64
 * range, which a JavaScript number cannot hold exactly above 2^53. The
 * constructors accept a bigint or a safe-integer number and reject anything
 * out of range with OUT_OF_RANGE; a value is never truncated or wrapped.
 */
declare const brand: unique symbol;

/** A Data Epoch (§11, §19): 0 <= epoch <= 2^64 - 1. */
export type DataEpoch = bigint & { readonly [brand]: "DataEpoch" };
/** A per-(Resource, Principal) actor sequence (§8): 1 <= seq <= 2^64 - 1. */
export type ActorSequence = bigint & { readonly [brand]: "ActorSequence" };

export const UINT64_MAX = 2n ** 64n - 1n;

function uint(what: string, value: bigint | number, min: bigint): bigint {
  let n: bigint;
  if (typeof value === "bigint") n = value;
  else if (typeof value === "number" && Number.isSafeInteger(value)) n = BigInt(value);
  else
    throw new LfcpError(
      "OUT_OF_RANGE",
      `${what} must be a bigint or a safe integer, got ${typeof value === "number" ? String(value) : typeof value}`,
    );
  if (n < min || n > UINT64_MAX)
    throw new LfcpError("OUT_OF_RANGE", `${what} must be in ${min}..2^64-1, got ${n}`);
  return n;
}

export const dataEpoch = (value: bigint | number): DataEpoch =>
  uint("a Data Epoch", value, 0n) as DataEpoch;

export const actorSequence = (value: bigint | number): ActorSequence =>
  uint("an actor sequence", value, 1n) as ActorSequence;

/** `uint64_be(value)`: 8 big-endian bytes; OUT_OF_RANGE outside 0..2^64-1. */
export function uint64BE(value: bigint | number): Uint8Array {
  let n = uint("a uint64 value", value, 0n);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
