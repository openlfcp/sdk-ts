import { LfcpError } from "@openlfcp/core";
import { type CborValue, isCborMap } from "./cbor/index.js";

// Readers for the integer-keyed maps of LFCP-WIRE-01 structures. Every
// failure is INVALID_STRUCTURE (MALFORMED_MESSAGE on the wire). Values are
// copied out of the decoded CBOR; nothing here encodes.

export function invalid(what: string, why: string): never {
  throw new LfcpError("INVALID_STRUCTURE", `invalid ${what}: ${why}`);
}

/** Fields of a map whose key set must be `required` plus any of `optional`, nothing else. */
export class Fields {
  readonly #what: string;
  readonly #map: Map<number, CborValue>;

  constructor(
    value: CborValue,
    what: string,
    required: readonly number[],
    optional: readonly number[] = [],
  ) {
    this.#what = what;
    if (!isCborMap(value)) invalid(what, "not a map");
    const allowed = new Set([...required, ...optional]);
    this.#map = new Map();
    for (const [key, field] of value.entries) {
      if (typeof key !== "number" || !allowed.has(key))
        invalid(what, `field ${String(key)} is not allowed`);
      this.#map.set(key, field);
    }
    for (const key of required) if (!this.#map.has(key)) invalid(what, `field ${key} is missing`);
  }

  has(key: number): boolean {
    return this.#map.has(key);
  }

  fail(key: number, why: string): never {
    invalid(this.#what, `field ${key} ${why}`);
  }

  any(key: number): CborValue {
    return this.#map.get(key) as CborValue;
  }

  uint(key: number): bigint {
    const v = this.#map.get(key);
    if ((typeof v === "number" || typeof v === "bigint") && v >= 0) return BigInt(v);
    this.fail(key, "must be an unsigned integer");
  }

  bytes(key: number, length?: number): Uint8Array {
    const v = this.#map.get(key);
    if (!(v instanceof Uint8Array)) this.fail(key, "must be a byte string");
    if (length !== undefined && v.length !== length) this.fail(key, `must be ${length} bytes`);
    return Uint8Array.from(v);
  }

  bytesOrNull(key: number, length: number): Uint8Array | null {
    return this.#map.get(key) === null ? null : this.bytes(key, length);
  }

  text(key: number): string {
    const v = this.#map.get(key);
    if (typeof v !== "string") this.fail(key, "must be a text string");
    return v;
  }

  array(key: number): readonly CborValue[] {
    const v = this.#map.get(key);
    if (!Array.isArray(v)) this.fail(key, "must be an array");
    return v as readonly CborValue[];
  }
}
