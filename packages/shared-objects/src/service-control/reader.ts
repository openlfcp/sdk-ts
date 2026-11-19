import type * as A from "@automerge/automerge";
import { UINT64_MAX } from "@openlfcp/core";

/** One value of the backend: a scalar with its type, or an object with its ID. */
export type ScValue = readonly [type: string, value: unknown];

const OBJECTS = new Set(["map", "list", "text", "table"]);
export const isObject = (v: ScValue | undefined): boolean => v !== undefined && OBJECTS.has(v[0]);
export const isMapValue = (v: ScValue | undefined): v is readonly ["map", string] =>
  v?.[0] === "map";
export const isStr = (v: ScValue | undefined): v is readonly ["str", string] => v?.[0] === "str";
export const isUint = (v: ScValue | undefined): boolean =>
  v?.[0] === "uint" &&
  ((typeof v[1] === "number" && Number.isSafeInteger(v[1]) && v[1] >= 0) ||
    (typeof v[1] === "bigint" && v[1] >= 0n && v[1] <= UINT64_MAX));

/** The UTF-8 length of a string (the portable packages have no TextEncoder type). */
export function utf8Length(text: string): number {
  let n = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    n += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }
  return n;
}

/**
 * The document read through the backend, at the given heads (the causal
 * history of a change, its pre-state or post-state, §3) or at the current
 * heads. Backend types tell an ImmutableString from Text and a uint from an
 * int. `get` is the engine's projection (one value per key); `all` every
 * concurrent value (SOP §45).
 */
export class ScReader {
  constructor(
    readonly backend: ReturnType<typeof A.getBackend>,
    readonly heads?: readonly string[],
  ) {}

  #heads(): string[] | undefined {
    return this.heads === undefined ? undefined : [...this.heads];
  }

  get(obj: string, key: string | number): ScValue | undefined {
    const v = this.backend.getWithType(obj, key, this.#heads());
    return v === null || v === undefined ? undefined : ([String(v[0]), v[1]] as const);
  }

  all(obj: string, key: string | number): ScValue[] {
    return (this.backend.getAll(obj, key, this.#heads()) as unknown[][]).map(
      (v) => [String(v[0]), v[1]] as const,
    );
  }

  keys(obj: string): string[] {
    return this.backend.keys(obj, this.#heads());
  }

  length(obj: string): number {
    return this.backend.length(obj, this.#heads());
  }

  /** The projection of `obj[key]` when it is a map, else undefined. */
  map(obj: string, key: string): string | undefined {
    const v = this.get(obj, key);
    return isMapValue(v) ? v[1] : undefined;
  }

  /** The projection of a value as plain JavaScript (strings, uints, booleans, objects, arrays). */
  plain(v: ScValue | undefined): unknown {
    if (v === undefined) return undefined;
    const [type, value] = v;
    if (type === "map" || type === "table") {
      const out: Record<string, unknown> = {};
      for (const k of this.keys(String(value))) out[k] = this.plain(this.get(String(value), k));
      return out;
    }
    if (type === "list") {
      const id = String(value);
      return Array.from({ length: this.length(id) }, (_, i) => this.plain(this.get(id, i)));
    }
    if (type === "text") return undefined;
    if (type === "uint" && typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER))
      return Number(value);
    return value;
  }

  /**
   * §4 Sizes: over every value present (concurrent values of a map field
   * included), the UTF-8 length of every map key and string, 8 bytes for
   * every other scalar. List elements count by their projection.
   */
  size(v: ScValue | undefined): number {
    if (v === undefined) return 0;
    const [type, value] = v;
    if (type === "str") return utf8Length(String(value));
    if (type === "map" || type === "table") {
      let n = 0;
      const id = String(value);
      for (const k of this.keys(id)) {
        const keyBytes = utf8Length(k);
        for (const e of this.all(id, k)) n += keyBytes + this.size(e);
      }
      return n;
    }
    if (type === "list") {
      const id = String(value);
      let n = 0;
      for (let i = 0; i < this.length(id); i++) n += this.size(this.get(id, i));
      return n;
    }
    return 8;
  }
}
