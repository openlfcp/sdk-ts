import * as A from "@automerge/automerge";

type AMap = Record<string, unknown>;

/** Automerge object types: an object value equals no other value (SOP §45). */
const OBJECTS = new Set(["map", "list", "text", "table"]);

/** A scalar's identity for equality: its Automerge type and its value. */
function scalarKey(type: string, value: unknown): string {
  if (value instanceof Uint8Array)
    return `${type}:${Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  if (value instanceof Date) return `${type}:${value.getTime()}`;
  if (typeof value === "bigint") return `${type}:${value}`;
  return `${type}:${JSON.stringify(value)}`;
}

/**
 * The distinct concurrent values of `map[key]` in `doc` (SOP §45,
 * mvp-0.2-baseline.12): none when absent, one when it is not conflicted or
 * when every concurrent value is equal. Two values are equal when they have
 * the same Automerge scalar type and the same value (strings code point by
 * code point); an object (a map, a list or Text) equals no other value. In
 * Automerge's order of the concurrent values, the first of each equal group.
 */
export function distinctValues(doc: A.Doc<unknown>, map: AMap | undefined, key: string): unknown[] {
  if (map === undefined || !(key in map)) return [];
  const conflicts = A.getConflicts(map as A.Doc<unknown>, key);
  if (conflicts === undefined) return [map[key]];
  const obj = A.getObjectId(map);
  const all = obj === null ? [] : A.getBackend(doc).getAll(obj, key, A.getHeads(doc));
  const typeOf = new Map<string, { type: string; value: unknown }>();
  for (const e of all) {
    const type = e[0] as string;
    if (OBJECTS.has(type)) typeOf.set(e[1] as string, { type, value: undefined });
    else typeOf.set(e[2] as string, { type, value: e[1] });
  }
  const seen = new Set<string>();
  const out: unknown[] = [];
  for (const [opId, value] of Object.entries(conflicts)) {
    const t = typeOf.get(opId);
    const k =
      t === undefined || OBJECTS.has(t.type) ? `object:${opId}` : scalarKey(t.type, t.value);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(value);
  }
  return out;
}

/** Whether `map[key]` has two or more distinct concurrent values (a conflict, SOP §45). */
export function isConflicted(doc: A.Doc<unknown>, map: AMap, key: string): boolean {
  return (
    A.getConflicts(map as A.Doc<unknown>, key) !== undefined &&
    distinctValues(doc, map, key).length > 1
  );
}
