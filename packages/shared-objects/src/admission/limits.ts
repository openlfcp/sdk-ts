// Expansion limits for Automerge chunks (SHARED-OBJECTS-PROFILE-01 §11.1,
// §13.1; SPEC-PATCH-07). Automerge's columnar format run-length encodes its
// columns, and a Snapshot's columns may also be deflated, so a few bytes can
// declare millions of operations or gigabytes of data: a 112-byte change
// expanded to 1,000,000 operations and 1.2 GiB in Automerge JS 3.5.0. This
// walker reads a chunk's structure and the run headers of every column,
// without materialising any value, and refuses a chunk over the limits
// BEFORE the Automerge engine sees it. It runs in time linear in the input
// (plus the capped inflation of a Snapshot's deflated columns).
//
// Counting rules (the profile states them; both SDKs count the same way):
// - every column's value count (its rows): an RLE run of n adds n, a
//   literal run of n adds n, a null run of n adds n; a boolean column adds
//   each run length; a raw value column adds nothing;
// - every group column's sum (the total of its values: pred and succ
//   entries);
// - expanded string bytes: each string value counted once per row it
//   occupies (an RLE run of n copies of a k-byte string adds n * k);
// - structure: no two columns with one specification, every actor index
//   below the number of actors, and (a change) no group value above one
//   plus the number of other actors (an op's predecessors have distinct
//   actors);
// - for a Snapshot, the bytes of all column data after inflation.

import { Inflate } from "fflate";
import { ProfileInvalidError } from "../profile-invalid.js";

/** The exact limits of a change (§11.1): writers stay within them, receivers reject above. */
export const CHANGE_LIMITS = Object.freeze({
  maxRows: 16_384,
  maxGroupSum: 262_144,
  maxStringBytes: 4 * 1024 * 1024,
  maxDeps: 1_024,
  maxActors: 1_024,
});

/**
 * The floor of a Snapshot's limits (§13.1): every receiver accepts at least
 * these. A receiver MAY configure higher limits; above its own it rejects
 * the Snapshot before the engine and falls back to the data round.
 */
export const SNAPSHOT_LIMITS_FLOOR = Object.freeze({
  maxRows: 262_144,
  maxGroupSum: 262_144,
  maxStringBytes: 32 * 1024 * 1024,
  maxInflatedBytes: 32 * 1024 * 1024,
  maxDeps: 1_024,
  maxActors: 1_024,
});

export type SnapshotLimits = typeof SNAPSHOT_LIMITS_FLOOR;

/** §11.2: no object of a document is deeper than this (the root is depth 0). */
export const MAX_DOCUMENT_DEPTH = 256;

/** The operation actions that create an object (§11.2): makeMap, makeList, makeText, makeTable. */
export const OBJECT_ACTIONS: ReadonlySet<number> = new Set([0, 2, 4, 6]);

/** What a chunk expands to (for tests and diagnostics). */
export interface ChunkExpansion {
  /** The largest value count of any column (a change's op count is its action column's). */
  readonly maxRows: number;
  readonly groupSum: number;
  readonly stringBytes: number;
  /** Column data bytes after inflation (a change has no deflated columns). */
  readonly columnBytes: number;
  /** Each column's spec (id << 4 | deflate << 3 | type) and value count, in chunk order. */
  readonly columns: readonly { readonly spec: number; readonly rows: number }[];
  /** A change's other actors (hex), in order: actor index i + 1 (§11.1). Empty for a Snapshot. */
  readonly otherActors: readonly string[];
  /** A Snapshot's deepest object (§11.2); 0 for a change (its depths depend on the document). */
  readonly maxDepth: number;
}

const MAGIC = [0x85, 0x6f, 0x4a, 0x83];
const CHUNK_DOCUMENT = 0;
const CHUNK_CHANGE = 1;
const DEFLATE_BIT = 0x08;
const TYPE_GROUP = 0;
const TYPE_ACTOR = 1;
const TYPE_DELTA = 3;
const TYPE_BOOLEAN = 4;
const TYPE_STRING = 5;
const TYPE_RAW = 7;
/** Input fed to the inflater per push: each push yields at most ~1,032x its size. */
const INFLATE_SLICE = 1024;

const refuse = (why: string): never => {
  throw new ProfileInvalidError(
    "INVALID_AUTOMERGE_BYTES",
    `Automerge chunk refused (§11.1): ${why}`,
  );
};

class Cursor {
  pos = 0;
  constructor(
    readonly bytes: Uint8Array,
    readonly end = bytes.length,
  ) {}

  get done(): boolean {
    return this.pos >= this.end;
  }

  take(n: number): Uint8Array {
    if (n > this.end - this.pos) refuse("a length runs past the end");
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** Unsigned LEB128 as a number; values at or above 2^53 come back as Infinity (over every limit). */
  uleb(): number {
    let value = 0;
    let scale = 1;
    for (let i = 0; i < 10; i++) {
      if (this.pos >= this.end) refuse("a LEB128 number runs past the end");
      const b = this.bytes[this.pos++] as number;
      value += (b & 0x7f) * scale;
      if ((b & 0x80) === 0) return value >= 2 ** 53 ? Number.POSITIVE_INFINITY : value;
      scale *= 128;
    }
    return refuse("a LEB128 number is longer than 10 bytes");
  }

  /** Signed LEB128 as a number; magnitudes at or above 2^53 come back as +/-Infinity. */
  sleb(): number {
    let value = 0;
    let scale = 1;
    for (let i = 0; i < 10; i++) {
      if (this.pos >= this.end) refuse("a LEB128 number runs past the end");
      const b = this.bytes[this.pos++] as number;
      value += (b & 0x7f) * scale;
      scale *= 128;
      if ((b & 0x80) === 0) {
        if (b & 0x40) value -= scale;
        return Math.abs(value) >= 2 ** 53 ? Math.sign(value) * Number.POSITIVE_INFINITY : value;
      }
    }
    return refuse("a LEB128 number is longer than 10 bytes");
  }
}

interface Limits {
  readonly maxRows: number;
  readonly maxGroupSum: number;
  readonly maxStringBytes: number;
  readonly maxDeps: number;
  readonly maxActors: number;
}

class Tally {
  maxRows = 0;
  groupSum = 0;
  stringBytes = 0;
  columnBytes = 0;
  constructor(readonly limits: Limits) {}

  rows(column: number, limit: number): void {
    if (column > limit) refuse(`a column has more than ${limit} values`);
    if (column > this.maxRows) this.maxRows = column;
  }

  group(add: number): void {
    this.groupSum += add;
    if (!(this.groupSum <= this.limits.maxGroupSum))
      refuse(`group columns sum to more than ${this.limits.maxGroupSum}`);
  }

  strings(add: number): void {
    this.stringBytes += add;
    if (!(this.stringBytes <= this.limits.maxStringBytes))
      refuse(`strings expand to more than ${this.limits.maxStringBytes} bytes`);
  }
}

/** What one column's values may be: actor indices below `actors`, group values up to `group`, at most `rows` values. */
interface ValueBounds {
  readonly actors: number;
  readonly group: number;
  readonly rows: number;
}

/** Counts one column's values (and group sums, string bytes) from its run headers. */
function countColumn(type: number, data: Uint8Array, tally: Tally, bounds: ValueBounds): number {
  if (type === TYPE_RAW) return 0;
  const c = new Cursor(data);
  let rows = 0;
  const add = (n: number) => {
    rows += n;
    tally.rows(rows, bounds.rows);
  };
  if (type === TYPE_BOOLEAN) {
    while (!c.done) add(c.uleb());
    return rows;
  }
  // One value of an RLE column: its group count, its string length, or skipped.
  const value = (): number => {
    if (type === TYPE_STRING) {
      const len = c.uleb();
      c.take(len);
      return len;
    }
    if (type === TYPE_DELTA) return c.sleb();
    return c.uleb();
  };
  const account = (v: number, times: number) => {
    if (type === TYPE_GROUP) {
      if (v > bounds.group) refuse("an operation has more predecessors than the change has actors");
      tally.group(v * times);
    } else if (type === TYPE_STRING) tally.strings(v * times);
    else if (type === TYPE_ACTOR && !(v < bounds.actors)) refuse("an actor index is out of range");
  };
  while (!c.done) {
    const header = c.sleb();
    if (header > 0) {
      add(header);
      account(value(), header);
    } else if (header < 0) {
      const n = -header;
      add(n); // refuses before reading an oversized literal run
      for (let i = 0; i < n; i++) account(value(), 1);
    } else add(c.uleb());
  }
  return rows;
}

interface ColumnMeta {
  readonly spec: number;
  readonly length: number;
}

/** Column metadata. The count has no limit of its own (§11.1): each entry takes at least two bytes. */
function columnMetas(c: Cursor): ColumnMeta[] {
  const count = c.uleb();
  if (count > (c.end - c.pos) / 2) refuse("the column metadata runs past the end");
  const out: ColumnMeta[] = [];
  const specs = new Set<number>();
  for (let i = 0; i < count; i++) {
    const spec = c.uleb();
    if (specs.has(spec)) refuse("two columns share a specification");
    specs.add(spec);
    out.push({ spec, length: c.uleb() });
  }
  return out;
}

function lengthPrefixedList(
  c: Cursor,
  limit: number,
  what: string,
  fixed?: number,
): readonly Uint8Array[] {
  const count = c.uleb();
  if (count > limit) refuse(`more than ${limit} ${what}`);
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) out.push(c.take(fixed ?? c.uleb()));
  return out;
}

const toHexString = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * Each column's value limit: a column that shares its id with a group
 * column holds that group's entries (predecessors, successors, a change's
 * dependencies), so the group sum bounds it; every other column has the
 * row limit.
 */
function rowLimits(metas: readonly ColumnMeta[], limits: Limits): (spec: number) => number {
  const grouped = new Set(metas.filter((m) => (m.spec & 7) === TYPE_GROUP).map((m) => m.spec >> 4));
  return (spec) =>
    grouped.has(spec >> 4) && (spec & 7) !== TYPE_GROUP ? limits.maxGroupSum : limits.maxRows;
}

/** The chunk's single body: magic, checksum, type, length; nothing may follow it. */
function body(bytes: Uint8Array, want: number, what: string): Cursor {
  const c = new Cursor(bytes);
  const magic = c.take(4);
  if (!MAGIC.every((b, i) => magic[i] === b)) refuse(`${what} has no Automerge magic bytes`);
  c.take(4); // checksum: verified elsewhere (checkChange; the engine for a Snapshot)
  const type = c.take(1)[0] as number;
  if (type !== want) refuse(`${what} is chunk type ${type}, not ${want}`);
  const length = c.uleb();
  if (length !== bytes.length - c.pos)
    refuse(`${what} must be exactly one chunk with nothing after it`);
  return c;
}

/**
 * §11.1: checks an uncompressed change chunk (type 1) against the exact
 * change limits before the engine sees it. Throws PROFILE_INVALID /
 * INVALID_AUTOMERGE_BYTES; returns what it expands to.
 */
export function checkChangeExpansion(bytes: Uint8Array): ChunkExpansion {
  const c = body(bytes, CHUNK_CHANGE, "a change");
  const tally = new Tally(CHANGE_LIMITS);
  lengthPrefixedList(c, CHANGE_LIMITS.maxDeps, "dependencies", 32);
  c.take(c.uleb()); // actor
  c.uleb(); // seq
  c.uleb(); // start op
  c.sleb(); // time
  c.take(c.uleb()); // message
  const otherActors = lengthPrefixedList(c, CHANGE_LIMITS.maxActors, "other actors");
  const others = otherActors.length;
  const metas = columnMetas(c);
  const limitOf = rowLimits(metas, CHANGE_LIMITS);
  const columns: { spec: number; rows: number }[] = [];
  for (const m of metas) {
    if (m.spec & DEFLATE_BIT) refuse("a change column is deflated");
    const bounds = { actors: 1 + others, group: 1 + others, rows: limitOf(m.spec) };
    columns.push({ spec: m.spec, rows: countColumn(m.spec & 7, c.take(m.length), tally, bounds) });
    tally.columnBytes += m.length;
  }
  // The rest of the chunk is the change's extra bytes: kept, not expanded.
  return Object.freeze({
    maxRows: tally.maxRows,
    groupSum: tally.groupSum,
    stringBytes: tally.stringBytes,
    columnBytes: tally.columnBytes,
    columns: Object.freeze(columns),
    otherActors: Object.freeze(otherActors.map(toHexString)),
    maxDepth: 0,
  });
}

/** Inflates raw DEFLATE data, refusing as soon as the output passes `budget` bytes. */
function inflateCapped(input: Uint8Array, budget: number): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  let over = false;
  let failed: unknown;
  const inflater = new Inflate((chunk) => {
    total += chunk.length;
    if (total > budget) over = true;
    else parts.push(chunk);
  });
  try {
    for (let i = 0; i < input.length && !over; i += INFLATE_SLICE)
      inflater.push(input.subarray(i, i + INFLATE_SLICE), i + INFLATE_SLICE >= input.length);
    if (input.length === 0) inflater.push(new Uint8Array(0), true);
  } catch (e) {
    failed = e;
  }
  if (over) refuse(`Snapshot columns inflate to more than ${budget} more bytes`);
  if (failed !== undefined) refuse("a deflated Snapshot column is not valid DEFLATE");
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** The values of an actor (1), integer (2) or delta (3) column: null for a null row. */
function columnValues(type: number, data: Uint8Array): (number | null)[] {
  const c = new Cursor(data);
  const out: (number | null)[] = [];
  let acc = 0;
  const one = (): number => {
    if (type === TYPE_DELTA) {
      acc += c.sleb();
      return acc;
    }
    return c.uleb();
  };
  while (!c.done) {
    const header = c.sleb();
    if (header > 0) {
      if (type === TYPE_DELTA) {
        const delta = c.sleb();
        for (let i = 0; i < header; i++) {
          acc += delta;
          out.push(acc);
        }
      } else {
        const v = c.uleb();
        for (let i = 0; i < header; i++) out.push(v);
      }
    } else if (header < 0) for (let i = 0; i < -header; i++) out.push(one());
    else {
      const nulls = c.uleb();
      for (let i = 0; i < nulls; i++) out.push(null);
    }
  }
  return out;
}

/**
 * §11.2: the deepest object of a document chunk, from its operation
 * columns (object, operation ID, action), computed without recursion.
 * Refuses an object deeper than MAX_DOCUMENT_DEPTH, a cycle, or an object
 * written into one the document never created.
 */
function documentDepth(columns: ReadonlyMap<number, Uint8Array>): number {
  const col = (spec: number) => {
    const data = columns.get(spec);
    return data === undefined ? [] : columnValues(spec & 7, data);
  };
  const action = col((4 << 4) | 2);
  const objActor = col((0 << 4) | 1);
  const objCtr = col((0 << 4) | 2);
  const idActor = col((2 << 4) | 1);
  const idCtr = col((2 << 4) | 3);
  const ROOT = "_root";
  const parent = new Map<string, string>();
  action.forEach((a, i) => {
    if (a === null || !OBJECT_ACTIONS.has(a)) return;
    const id = `${idCtr[i]}@${idActor[i]}`;
    const oc = objCtr[i] ?? null;
    parent.set(id, oc === null ? ROOT : `${oc}@${objActor[i]}`);
  });
  const depth = new Map<string, number>([[ROOT, 0]]);
  let deepest = 0;
  for (const start of parent.keys()) {
    const path: string[] = [];
    let at = start;
    while (!depth.has(at)) {
      path.push(at);
      if (path.length > MAX_DOCUMENT_DEPTH)
        refuse(`an object is deeper than ${MAX_DOCUMENT_DEPTH} levels (§11.2)`);
      const up = parent.get(at);
      if (up === undefined)
        refuse("an object is written into one the document never created (§11.2)");
      at = up as string;
    }
    let d = depth.get(at) as number;
    for (let k = path.length - 1; k >= 0; k--) {
      d += 1;
      if (d > MAX_DOCUMENT_DEPTH)
        refuse(`an object is deeper than ${MAX_DOCUMENT_DEPTH} levels (§11.2)`);
      depth.set(path[k] as string, d);
    }
    if (d > deepest) deepest = d;
  }
  return deepest;
}

/**
 * §13.1: checks a Snapshot's save (exactly one document chunk) against
 * `limits` (at least SNAPSHOT_LIMITS_FLOOR) before the engine sees it,
 * inflating deflated columns under a running cap. Throws PROFILE_INVALID /
 * INVALID_AUTOMERGE_BYTES.
 */
export function checkSnapshotExpansion(
  bytes: Uint8Array,
  limits: SnapshotLimits = SNAPSHOT_LIMITS_FLOOR,
): ChunkExpansion {
  const c = body(bytes, CHUNK_DOCUMENT, "a Snapshot");
  const tally = new Tally(limits);
  const actors = lengthPrefixedList(c, limits.maxActors, "actors").length;
  lengthPrefixedList(c, limits.maxDeps, "heads", 32);
  const changeMetas = columnMetas(c);
  const opMetas = columnMetas(c);
  const changeLimit = rowLimits(changeMetas, limits);
  const opLimit = rowLimits(opMetas, limits);
  let inflated = 0;
  const columns: { spec: number; rows: number }[] = [];
  const opData = new Map<number, Uint8Array>();
  for (const [m, limitOf] of [
    ...changeMetas.map((m) => [m, changeLimit] as const),
    ...opMetas.map((m) => [m, opLimit] as const),
  ]) {
    let data = c.take(m.length);
    if (m.spec & DEFLATE_BIT) data = inflateCapped(data, limits.maxInflatedBytes - inflated);
    inflated += data.length;
    if (inflated > limits.maxInflatedBytes)
      refuse(`Snapshot columns hold more than ${limits.maxInflatedBytes} bytes`);
    const bounds = { actors, group: Number.POSITIVE_INFINITY, rows: limitOf(m.spec) };
    columns.push({ spec: m.spec, rows: countColumn(m.spec & 7, data, tally, bounds) });
    if (limitOf === opLimit) opData.set(m.spec & ~DEFLATE_BIT, data);
  }
  // §11.2: depths from the operation columns, once their sizes are known to be bounded.
  const maxDepth = documentDepth(opData);
  tally.columnBytes = inflated;
  // The rest is the document's head indices.
  return Object.freeze({
    maxRows: tally.maxRows,
    groupSum: tally.groupSum,
    stringBytes: tally.stringBytes,
    columnBytes: tally.columnBytes,
    columns: Object.freeze(columns),
    otherActors: Object.freeze([]),
    maxDepth,
  });
}
