import type * as A from "@automerge/automerge";
import { type CheckedChange, decodedOf } from "../admission/framing.js";
import type { ScBackend } from "./reader.js";

/** A change or read the shadow cannot answer exactly: the caller asks the engine. */
export class ShadowUnsupported extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShadowUnsupported";
  }
}

/** One live operation on a map key or list element: its ID and engine value. */
interface Live {
  readonly id: string;
  readonly type: string;
  readonly value: unknown;
}

/** A list or text element in RGA order; deleted elements stay as tombstones (no live values). */
interface Elem {
  readonly id: string;
  vals: readonly Live[];
}

type Obj =
  | { readonly kind: "map"; readonly keys: Map<string, readonly Live[]> }
  | {
      readonly kind: "list";
      /** Text: an element is as wide as its visible string in UTF-16 code units, as the engine counts. */
      readonly text: boolean;
      readonly elems: Elem[];
      readonly byId: Map<string, Elem>;
    };

/** The change as the shadow needs it: its hash, actor, sequence and operations (A.decodeChange). */
export type ShadowChange = Pick<A.DecodedChange, "hash" | "actor" | "seq" | "startOp" | "ops">;

interface Logged {
  readonly change: ShadowChange;
  readonly undo: (() => void)[];
}

const OBJECTS: ReadonlySet<string> = new Set(["map", "list", "text"]);
const OBJECT_TYPES: Readonly<Record<string, "map" | "list" | "text">> = {
  makeMap: "map",
  makeList: "list",
  makeText: "text",
};

/** Lamport order of operation IDs: counter, then actor bytes (hex compares as the bytes do). */
function compareIds(a: string, b: string): number {
  const at = a.indexOf("@");
  const bt = b.indexOf("@");
  const d = Number(a.slice(0, at)) - Number(b.slice(0, bt));
  if (d !== 0) return d;
  const x = a.slice(at + 1);
  const y = b.slice(bt + 1);
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Keys in the engine's order: by Unicode code point (UTF-8 byte order), not UTF-16 unit. */
function compareKeys(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0) as number);
  const y = Array.from(b, (c) => c.codePointAt(0) as number);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = (x[i] as number) - (y[i] as number);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/** The engine type and value of a decoded scalar operation. */
function scalarOf(op: { datatype?: string; value?: unknown }): [string, unknown] {
  const v = op.value;
  switch (op.datatype) {
    case undefined:
      if (typeof v === "string") return ["str", v];
      if (typeof v === "boolean") return ["boolean", v];
      if (v === null) return ["null", null];
      if (v instanceof Uint8Array || Array.isArray(v)) return ["bytes", Uint8Array.from(v)];
      break;
    case "uint":
      // The engine reads every uint as a bigint.
      if (typeof v === "number" || typeof v === "bigint") return ["uint", BigInt(v)];
      break;
    case "int":
    case "counter":
      return [op.datatype, engineInt(int64Of(v))];
    case "float64":
      return ["f64", v];
    case "timestamp":
      return ["timestamp", v];
  }
  throw new ShadowUnsupported(`a value of datatype ${String(op.datatype)}`);
}

/** An int64 operand as a bigint; anything else is not a value the shadow models. */
function int64Of(v: unknown): bigint {
  if (typeof v === "bigint" || Number.isSafeInteger(v)) return BigInt(v as number | bigint);
  throw new ShadowUnsupported(`an integer operand ${String(v)}`);
}

const SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** An int64 as the engine reads it: a number in [-(2^53 - 1), 2^53 - 1), else a bigint. */
function engineInt(b: bigint): number | bigint {
  return b >= -SAFE && b < SAFE ? Number(b) : b;
}

/**
 * A.§3.5 (E-030): C's visible state as plain JavaScript, kept up to date one
 * applied change at a time, so that admission can read the current state
 * without asking the engine for a read at explicit heads, whose cost grows
 * with the history. It answers the reads ScReader makes (getWithType,
 * getAll, keys, length) at the current heads only, with the engine's types
 * and its order of concurrent values; a change it cannot model exactly
 * (marks, tables, an unknown datatype or object) throws ShadowUnsupported
 * and leaves the state as it was, and the caller goes back to the engine.
 *
 * Every applied change keeps its inverse in an undo log of at most `window`
 * changes, so the newest ones can be rolled back exactly: a change refused
 * after it was applied, or the changes after a concurrent change's fork
 * point, to be applied again after it is judged. Each change is applied
 * once, after its dependencies (the replica drops duplicates before).
 */
export class ShadowDoc implements ScBackend {
  readonly #objs = new Map<string, Obj>([["_root", { kind: "map", keys: new Map() }]]);
  readonly #log: Logged[] = [];

  /** @param window how many of the newest changes can be rolled back. */
  constructor(readonly window = 256) {}

  /** How many changes `undo` can roll back. */
  get depth(): number {
    return this.#log.length;
  }

  /** Applies a checked change (its dependencies already applied). */
  applyChecked(change: CheckedChange): void {
    this.apply(decodedOf(change));
  }

  /**
   * Applies `change`, all its operations or none: on ShadowUnsupported the
   * operations already applied are rolled back before it is thrown.
   */
  apply(change: ShadowChange): void {
    const undo: (() => void)[] = [];
    try {
      for (const [i, op] of change.ops.entries())
        this.#op(`${change.startOp + i}@${change.actor}`, op, undo);
    } catch (e) {
      for (let i = undo.length - 1; i >= 0; i--) (undo[i] as () => void)();
      throw e;
    }
    this.#log.push({ change, undo });
    if (this.#log.length > this.window) this.#log.shift();
  }

  /** The change `back` places before the newest on the undo log (0: the newest). */
  recent(back: number): ShadowChange | undefined {
    return this.#log[this.#log.length - 1 - back]?.change;
  }

  /** Rolls the newest applied change back exactly and returns it; undefined when the log is empty. */
  undo(): ShadowChange | undefined {
    const entry = this.#log.pop();
    if (entry === undefined) return undefined;
    for (let i = entry.undo.length - 1; i >= 0; i--) (entry.undo[i] as () => void)();
    return entry.change;
  }

  #op(id: string, op: A.DecodedChange["ops"][number], undo: (() => void)[]): void {
    const o = op as typeof op & { elemId?: string; insert?: boolean; datatype?: string };
    const obj = this.#objs.get(o.obj);
    if (obj === undefined) throw new ShadowUnsupported(`an operation on unknown object ${o.obj}`);
    const made = OBJECT_TYPES[o.action];
    let created: Live | undefined;
    if (made !== undefined) {
      created = { id, type: made, value: id };
      const fresh: Obj =
        made === "map"
          ? { kind: "map", keys: new Map() }
          : { kind: "list", text: made === "text", elems: [], byId: new Map() };
      this.#objs.set(id, fresh);
      undo.push(() => this.#objs.delete(id));
    } else if (o.action === "set") {
      const [type, value] = scalarOf(o);
      created = { id, type, value };
    } else if (o.action !== "del" && o.action !== "inc")
      throw new ShadowUnsupported(`a ${o.action} operation`);
    const pred = new Set(o.pred ?? []);
    const next = (vals: readonly Live[]): readonly Live[] => {
      // An increment adds to the counters it names and, as any successor, hides the other values.
      if (o.action === "inc")
        return vals.flatMap((v) =>
          !pred.has(v.id)
            ? [v]
            : v.type === "counter"
              ? [{ ...v, value: engineInt(BigInt.asIntN(64, int64Of(v.value) + int64Of(o.value))) }]
              : [],
        );
      const kept = vals.filter((v) => !pred.has(v.id));
      if (created === undefined) return kept;
      const at = kept.findIndex((v) => compareIds(v.id, id) > 0);
      return at < 0 ? [...kept, created] : [...kept.slice(0, at), created, ...kept.slice(at)];
    };

    if (obj.kind === "map") {
      if (o.key === undefined) throw new ShadowUnsupported("a list operation on a map");
      const key = o.key;
      const before = obj.keys.get(key);
      const after = next(before ?? []);
      obj.keys.set(key, after);
      undo.push(() => (before === undefined ? obj.keys.delete(key) : obj.keys.set(key, before)));
      return;
    }
    if (o.elemId === undefined) throw new ShadowUnsupported("a map operation on a list");
    if (o.insert) {
      if (created === undefined) throw new ShadowUnsupported("an insert without a value");
      let pos = 0;
      if (o.elemId !== "_head") {
        const ref = obj.byId.get(o.elemId);
        if (ref === undefined) throw new ShadowUnsupported(`an insert after unknown ${o.elemId}`);
        pos = obj.elems.indexOf(ref) + 1;
      }
      // RGA: skip the elements after the reference with a greater ID (later or concurrent inserts).
      while (pos < obj.elems.length && compareIds((obj.elems[pos] as Elem).id, id) > 0) pos++;
      const elem: Elem = { id, vals: [created] };
      obj.elems.splice(pos, 0, elem);
      obj.byId.set(id, elem);
      undo.push(() => {
        obj.elems.splice(obj.elems.indexOf(elem), 1);
        obj.byId.delete(id);
      });
      return;
    }
    const elem = obj.byId.get(o.elemId);
    if (elem === undefined) throw new ShadowUnsupported(`an operation on unknown ${o.elemId}`);
    const before = elem.vals;
    elem.vals = next(before);
    undo.push(() => {
      elem.vals = before;
    });
  }

  #obj(obj: string): Obj {
    const o = this.#objs.get(obj);
    if (o === undefined) throw new RangeError(`invalid object ID ${obj}`);
    return o;
  }

  #current(heads: unknown): void {
    if (heads !== undefined) throw new ShadowUnsupported("a read at explicit heads");
  }

  #live(obj: string, key: string | number): readonly Live[] {
    const o = this.#obj(obj);
    if (o.kind === "map") return typeof key === "string" ? (o.keys.get(key) ?? []) : [];
    if (typeof key !== "number") return [];
    let i = key;
    for (const e of o.elems) {
      i -= widthOf(o, e);
      if (i < 0) return e.vals;
    }
    return [];
  }

  getWithType(obj: string, key: string | number, heads?: unknown): [string, unknown] | null {
    this.#current(heads);
    const v = this.#live(obj, key).at(-1);
    return v === undefined ? null : [v.type, engineValue(v)];
  }

  /** Oldest first; a scalar with its operation ID, an object with its ID alone (as the engine). */
  getAll(obj: string, key: string | number, heads?: unknown): unknown[][] {
    this.#current(heads);
    return this.#live(obj, key).map((v) =>
      OBJECTS.has(v.type) ? [v.type, v.id] : [v.type, engineValue(v), v.id],
    );
  }

  keys(obj: string, heads?: unknown): string[] {
    this.#current(heads);
    const o = this.#obj(obj);
    if (o.kind !== "map") return [];
    const out: string[] = [];
    for (const [k, vals] of o.keys) if (vals.length > 0) out.push(k);
    return out.sort(compareKeys);
  }

  length(obj: string, heads?: unknown): number {
    this.#current(heads);
    const o = this.#obj(obj);
    if (o.kind === "map") return this.keys(obj).length;
    let n = 0;
    for (const e of o.elems) n += widthOf(o, e);
    return n;
  }
}

/** How many indices an element takes: none when deleted, its UTF-16 length in text, else one. */
function widthOf(o: { readonly text: boolean }, e: Elem): number {
  const v = e.vals.at(-1);
  if (v === undefined) return 0;
  return o.text && typeof v.value === "string" ? v.value.length : 1;
}

/**
 * The value as the engine returns it: a fresh Date and a copy of bytes, never
 * shared state. A timestamp operand beyond the safe integers decodes as a
 * bigint, which the engine reads as a number, so as an Invalid Date.
 */
function engineValue(v: Live): unknown {
  if (v.type === "timestamp") return new Date(Number(v.value as number | bigint));
  if (v.type === "bytes") return Uint8Array.from(v.value as Uint8Array);
  return v.value;
}
