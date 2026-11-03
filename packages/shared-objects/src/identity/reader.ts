import * as A from "@automerge/automerge";

export type Value = readonly [type: string, value: unknown, op?: string | undefined];
const OBJECTS = new Set(["map", "list", "text", "table"]);

/** SOP §45: identical scalar writes count once; distinct objects never compare equal. */
export function distinct(values: readonly Value[]): Value[] {
  const seen = new Set<string>();
  return values.filter(([type, value]) => {
    if (OBJECTS.has(type)) return true;
    const key = `${type}:${String(value)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Backend types distinguish scalar strings from Text and uint from other numeric types. */
export class IdentityReader {
  readonly backend: ReturnType<typeof A.getBackend>;

  constructor(doc: A.Doc<unknown>) {
    this.backend = A.getBackend(doc);
  }

  all(obj: string, key: string | number): Value[] {
    return distinct(this.backend.getAll(obj, key) as Value[]).map(
      ([type, value, op]) =>
        [
          type,
          typeof value === "bigint" &&
          value <= BigInt(Number.MAX_SAFE_INTEGER) &&
          value >= BigInt(Number.MIN_SAFE_INTEGER)
            ? Number(value)
            : value,
          op,
        ] as Value,
    );
  }

  keys(obj: string): string[] {
    return this.backend.keys(obj).sort();
  }

  map(obj: string, key: string): string | undefined {
    const values = this.all(obj, key);
    return values.length === 1 && values[0]?.[0] === "map" ? String(values[0][1]) : undefined;
  }

  list(obj: string): Value[][] {
    return Array.from({ length: this.backend.length(obj) }, (_, i) => this.all(obj, i));
  }
}
