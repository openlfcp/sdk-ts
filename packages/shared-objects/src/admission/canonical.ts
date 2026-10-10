// The canonical change encoding (SHARED-OBJECTS-PROFILE-01 §11.3,
// SPEC-PATCH-10, ADR 0010), checked by the properties of the change format
// version 1, before the Automerge engine decodes the change. An engine does
// not keep the bytes of a change it applies: it writes the change again
// when it saves or hands it out, so a change with any other encoding of the
// same operations gets a different hash there, and the document's save
// then fails to load. The walk also gives the change's operations, read
// without the engine, for the operation references of §11.4.
//
// Each run-length column is decoded strictly (shortest LEB128, 64-bit
// range) and encoded again by the one rule of §11.3 rule 5; the two must be
// the same bytes. Everything else is checked as stated: the header, the
// columns and their presence, row counts, value metadata and bytes,
// actions, IDs and counters below 2^32, sorted predecessors.

import { ProfileInvalidError } from "../profile-invalid.js";

/** An operation of a change, as the references of §11.4 read it. */
export interface ParsedOp {
  /** "_root", or the creating operation's ID "counter@actorhex". */
  readonly obj: string;
  /** A property name, the head of a sequence, or an element ID. */
  readonly key:
    | { readonly kind: "prop"; readonly name: string }
    | { readonly kind: "head" }
    | { readonly kind: "elem"; readonly id: string };
  readonly insert: boolean;
  /** 0 makeMap, 1 set, 2 makeList, 3 del, 4 makeText, 5 inc, 6 makeTable, 7 mark. */
  readonly action: number;
  /** Predecessor IDs "counter@actorhex", in order. */
  readonly pred: readonly string[];
  /** The value's type, the low 4 bits of its metadata (8: a counter). */
  readonly valueType: number;
}

/** A change read from its bytes (§11.3), without the engine. */
export interface ParsedChange {
  readonly actor: string;
  readonly seq: number;
  readonly startOp: number;
  /** Hex dependency hashes, ascending. */
  readonly deps: readonly string[];
  /** Hex other actors, ascending: actor index i is otherActors[i - 1]. */
  readonly otherActors: readonly string[];
  readonly ops: readonly ParsedOp[];
  /**
   * §14.1: the extra bytes after the columns (which rule 4 leaves free) begin
   * with an Automerge author — an unsigned LEB128 1, a length L, then at least
   * L bytes. automerge 0.12 reads it and asserts the change's sequence number
   * is 1, so a later change carrying one is refused (finding D5).
   */
  readonly beginsWithAuthor: boolean;
}

const refuse = (why: string): never => {
  throw new ProfileInvalidError(
    "INVALID_AUTOMERGE_BYTES",
    `the change is not in its canonical encoding (§11.3): ${why}`,
  );
};

const U64 = 1n << 64n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U32 = 2 ** 32;

// Every runtime this package supports has TextDecoder (browsers, workers, Node 11+).
declare const TextDecoder: new (
  label: string,
  options: { readonly fatal: boolean; readonly ignoreBOM: boolean },
) => { decode(bytes: Uint8Array): string };

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function utf8(bytes: Uint8Array, what: string): string {
  try {
    return UTF8.decode(bytes);
  } catch {
    return refuse(`${what} is not valid UTF-8`);
  }
}

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Byte-wise lexicographic order, a shorter prefix first. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  return a.length - b.length;
}

/** A strict reader: every LEB128 number in its shortest form and in range (rule 1). */
class Reader {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}

  get done(): boolean {
    return this.pos >= this.bytes.length;
  }

  take(n: number): Uint8Array {
    if (!(n <= this.bytes.length - this.pos)) refuse("a length runs past the end");
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  ubig(): bigint {
    let value = 0n;
    let shift = 0n;
    const start = this.pos;
    for (;;) {
      if (this.pos >= this.bytes.length) refuse("a LEB128 number runs past the end");
      if (this.pos - start >= 10) refuse("an unsigned number is 2^64 or more");
      const b = this.bytes[this.pos++] as number;
      value |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if ((b & 0x80) === 0) {
        if (b === 0 && this.pos - start > 1) refuse("a LEB128 number is not in its shortest form");
        if (value >= U64) refuse("an unsigned number is 2^64 or more");
        return value;
      }
    }
  }

  sbig(): bigint {
    let value = 0n;
    let shift = 0n;
    const start = this.pos;
    for (;;) {
      if (this.pos >= this.bytes.length) refuse("a LEB128 number runs past the end");
      if (this.pos - start >= 10) refuse("a signed number is outside the 64-bit range");
      const b = this.bytes[this.pos++] as number;
      value |= BigInt(b & 0x7f) << shift;
      shift += 7n;
      if ((b & 0x80) === 0) {
        if (b & 0x40) value -= 1n << shift;
        if (this.pos - start > 1) {
          const prev = this.bytes[this.pos - 2] as number;
          if ((b === 0x00 && (prev & 0x40) === 0) || (b === 0x7f && (prev & 0x40) !== 0))
            refuse("a LEB128 number is not in its shortest form");
        }
        if (value < I64_MIN || value > I64_MAX)
          refuse("a signed number is outside the 64-bit range");
        return value;
      }
    }
  }

  /** An unsigned count or length: a safe integer, else over every bound. */
  unum(): number {
    const v = this.ubig();
    return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.POSITIVE_INFINITY : Number(v);
  }
}

function uleb(v: bigint, out: number[]): void {
  let x = v;
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    out.push(b);
  } while (x !== 0n);
}

function sleb(v: bigint, out: number[]): void {
  let x = v;
  for (;;) {
    const b = Number(x & 0x7fn);
    x >>= 7n;
    const done = (x === 0n && (b & 0x40) === 0) || (x === -1n && (b & 0x40) !== 0);
    out.push(done ? b : b | 0x80);
    if (done) return;
  }
}

const TYPE_DELTA = 3;
const TYPE_BOOLEAN = 4;
const TYPE_STRING = 5;

/** A non-null row of a run-length column: a number, or a string's bytes. */
type Row = bigint | Uint8Array | null;

const same = (a: Row, b: Row): boolean => {
  if (a === null || b === null) return a === b;
  if (typeof a === "bigint" || typeof b === "bigint") return a === b;
  return a.length === b.length && compareBytes(a, b) === 0;
};

/**
 * No column of a change within the §11.1 limits has more rows (a group's
 * entries are bounded by the group sum); the walk refuses more on its own,
 * whether or not the limits ran first.
 */
const MAX_ROWS = 262_144;

const room = (have: number, add: bigint): void => {
  if (add > BigInt(MAX_ROWS - have)) refuse("a column has more rows than a change may");
};

/** Decodes a run-length column (types 0, 1, 2, 3, 5, 6) strictly; a delta column's rows are absolute. */
function decodeRle(type: number, data: Uint8Array): Row[] {
  const r = new Reader(data);
  const rows: Row[] = [];
  let acc = 0n;
  const one = (): bigint | Uint8Array => {
    if (type === TYPE_STRING) return r.take(r.unum());
    if (type === TYPE_DELTA) return r.sbig();
    return r.ubig();
  };
  const push = (v: bigint | Uint8Array) => {
    if (type === TYPE_DELTA) {
      acc += v as bigint;
      rows.push(acc);
    } else rows.push(v);
  };
  while (!r.done) {
    const n = r.sbig();
    room(rows.length, n < 0n ? -n : n);
    if (n > 0n) {
      const v = one();
      for (let i = 0n; i < n; i++) push(v);
    } else if (n < 0n) for (let i = 0n; i < -n; i++) push(one());
    else {
      const nulls = r.ubig();
      room(rows.length, nulls);
      for (let i = 0n; i < nulls; i++) rows.push(null);
    }
  }
  return rows;
}

/** The one encoding of §11.3 rule 5 of `rows` (a delta column's rows absolute). */
function encodeRle(type: number, rows: readonly Row[]): Uint8Array {
  let values = rows;
  if (type === TYPE_DELTA) {
    let prev = 0n;
    values = rows.map((v) => {
      if (v === null) return null;
      const d = (v as bigint) - prev;
      prev = v as bigint;
      return d;
    });
  }
  const out: number[] = [];
  const value = (v: Row) => {
    if (type === TYPE_STRING) {
      const b = v as Uint8Array;
      uleb(BigInt(b.length), out);
      for (const x of b) out.push(x);
    } else if (type === TYPE_DELTA) sleb(v as bigint, out);
    else uleb(v as bigint, out);
  };
  let i = 0;
  while (i < values.length) {
    const v = values[i] as Row;
    if (v === null) {
      let j = i;
      while (j < values.length && values[j] === null) j++;
      sleb(0n, out);
      uleb(BigInt(j - i), out);
      i = j;
      continue;
    }
    let j = i + 1;
    while (j < values.length && same(values[j] as Row, v)) j++;
    if (j - i >= 2) {
      sleb(BigInt(j - i), out);
      value(v);
      i = j;
      continue;
    }
    // A literal run: up to a null or the start of a repetition.
    let k = i;
    while (
      k < values.length &&
      values[k] !== null &&
      !(k + 1 < values.length && same(values[k + 1] as Row, values[k] as Row))
    )
      k++;
    sleb(BigInt(-(k - i)), out);
    for (let m = i; m < k; m++) value(values[m] as Row);
    i = k;
  }
  return Uint8Array.from(out);
}

function decodeBoolean(data: Uint8Array): boolean[] {
  const r = new Reader(data);
  const rows: boolean[] = [];
  let bit = false;
  while (!r.done) {
    const n = r.unum();
    room(rows.length, BigInt(Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER));
    for (let i = 0; i < n; i++) rows.push(bit);
    bit = !bit;
  }
  return rows;
}

function encodeBoolean(rows: readonly boolean[]): Uint8Array {
  const out: number[] = [];
  let bit = false;
  let i = 0;
  while (i < rows.length) {
    let j = i;
    while (j < rows.length && rows[j] === bit) j++;
    uleb(BigInt(j - i), out);
    bit = !bit;
    i = j;
  }
  return Uint8Array.from(out);
}

/** The columns of the change format (§11.3 rule 3), by specification. */
const OBJ_ACTOR = 0x01;
const OBJ_CTR = 0x02;
const KEY_ACTOR = 0x11;
const KEY_CTR = 0x13;
const KEY_STR = 0x15;
const INSERT = 0x34;
const ACTION = 0x42;
const VAL_META = 0x56;
const VAL_RAW = 0x57;
const PRED_GROUP = 0x70;
const PRED_ACTOR = 0x71;
const PRED_CTR = 0x73;
const EXPAND = 0x94;
const MARK_NAME = 0xa5;
const KNOWN = new Set([
  OBJ_ACTOR,
  OBJ_CTR,
  KEY_ACTOR,
  KEY_CTR,
  KEY_STR,
  INSERT,
  ACTION,
  VAL_META,
  VAL_RAW,
  PRED_GROUP,
  PRED_ACTOR,
  PRED_CTR,
  EXPAND,
  MARK_NAME,
]);

/** Decodes and checks one column; the rows must encode back to the same bytes (rule 5). */
function column(spec: number, data: Uint8Array): Row[] | boolean[] {
  const type = spec & 7;
  if (type === TYPE_BOOLEAN) {
    const rows = decodeBoolean(data);
    if (compareBytes(encodeBoolean(rows), data) !== 0)
      refuse(`column 0x${spec.toString(16)} is not in its one run encoding`);
    return rows;
  }
  const rows = decodeRle(type, data);
  if (compareBytes(encodeRle(type, rows), data) !== 0)
    refuse(`column 0x${spec.toString(16)} is not in its one run encoding`);
  return rows;
}

const num = (v: Row): number | null => (v === null ? null : Number(v as bigint));

/** Rule 6: a value's bytes for its metadata type. */
function checkValue(type: number, bytes: Uint8Array): void {
  if (type >= 10) refuse(`value type ${type} is reserved`);
  if (type <= 2) {
    if (bytes.length !== 0) refuse("a null or boolean value has bytes");
    return;
  }
  if (type === 3 || type === 4 || type === 8 || type === 9) {
    const r = new Reader(bytes);
    if (type === 3) r.ubig();
    else r.sbig();
    if (!r.done || bytes.length === 0) refuse("a number value is not exactly one shortest LEB128");
    return;
  }
  if (type === 5) {
    if (bytes.length !== 8) refuse("a float value is not 8 bytes");
    return;
  }
  if (type === 6) utf8(bytes, "a string value");
}

/**
 * §14.1: whether the extra bytes after a change's columns begin with an
 * Automerge author (finding D5). Rule 4 leaves these bytes free, but
 * automerge 0.12 reads an author there — an unsigned LEB128 1, a length L,
 * then L bytes — and asserts the change's sequence number is 1. The LEB128 is
 * read as automerge reads it: up to ten bytes, under 2^64, in any encoding
 * (not the shortest-form `Reader` the rest of the walk uses).
 */
function beginsWithAuthor(extra: Uint8Array): boolean {
  let pos = 0;
  const leb = (): bigint | null => {
    let value = 0n;
    let shift = 0n;
    for (;;) {
      if (pos >= extra.length) return null;
      const b = extra[pos++] as number;
      if (shift === 63n && b !== 0 && b !== 1) return null;
      value |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return value;
      shift += 7n;
    }
  };
  if (leb() !== 1n) return false;
  const length = leb();
  return length !== null && BigInt(extra.length - pos) >= length;
}

/**
 * §11.3: checks that `bytes` (one change chunk within the §11.1 limits) is
 * the canonical encoding of its change, and returns the change's operations
 * read from it. Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES.
 */
export function checkCanonicalChange(bytes: Uint8Array): ParsedChange {
  const r = new Reader(bytes);
  r.take(9); // magic, checksum, chunk type: checked by the framing
  const length = r.ubig();
  if (length !== BigInt(bytes.length - r.pos)) refuse("the chunk length is wrong");

  // Rule 2: the header.
  const depCount = r.unum();
  const deps: Uint8Array[] = [];
  for (let i = 0; i < depCount; i++) deps.push(r.take(32));
  for (let i = 1; i < deps.length; i++)
    if (compareBytes(deps[i - 1] as Uint8Array, deps[i] as Uint8Array) >= 0)
      refuse("the dependencies are not strictly ascending");
  const actor = r.take(r.unum());
  const seq = r.ubig();
  const startOp = r.ubig();
  if (seq < 1n || startOp < 1n) refuse("the sequence number or the start op is 0");
  r.sbig(); // time
  utf8(r.take(r.unum()), "the message");
  const otherCount = r.unum();
  const others: Uint8Array[] = [];
  for (let i = 0; i < otherCount; i++) others.push(r.take(r.unum()));
  for (let i = 0; i < others.length; i++) {
    const o = others[i] as Uint8Array;
    if (compareBytes(o, actor) === 0) refuse("the change's actor is among its other actors");
    if (i > 0 && compareBytes(others[i - 1] as Uint8Array, o) >= 0)
      refuse("the other actors are not strictly ascending");
  }

  // Rule 3: the columns, in specification order, each once, never empty or deflated.
  const columnCount = r.unum();
  const metas: { spec: number; length: number }[] = [];
  for (let i = 0; i < columnCount; i++) {
    const spec = r.unum();
    const len = r.unum();
    if (!KNOWN.has(spec)) refuse(`column 0x${spec.toString(16)} is not a change column`);
    if (metas.length > 0 && (metas.at(-1) as { spec: number }).spec >= spec)
      refuse("the columns are not in ascending specification order");
    if (len === 0) refuse(`column 0x${spec.toString(16)} is empty`);
    metas.push({ spec, length: len });
  }
  const data = new Map<number, Uint8Array>();
  for (const m of metas) data.set(m.spec, r.take(m.length));
  // What follows is the change's extra bytes (§11.3 rule 4), free except that
  // automerge reads an author from their start (§14.1, finding D5).
  const authored = beginsWithAuthor(bytes.subarray(r.pos));

  const rle = (spec: number): Row[] | undefined => {
    const d = data.get(spec);
    return d === undefined ? undefined : (column(spec, d) as Row[]);
  };
  const bools = (spec: number): boolean[] | undefined => {
    const d = data.get(spec);
    return d === undefined ? undefined : (column(spec, d) as boolean[]);
  };
  const action = rle(ACTION) ?? [];
  const N = action.length;
  const objActor = rle(OBJ_ACTOR);
  const objCtr = rle(OBJ_CTR);
  const keyActor = rle(KEY_ACTOR);
  const keyCtr = rle(KEY_CTR);
  const keyStr = rle(KEY_STR);
  const insert = bools(INSERT);
  const meta = rle(VAL_META);
  const predCount = rle(PRED_GROUP);
  const predActor = rle(PRED_ACTOR);
  const predCtr = rle(PRED_CTR);
  const expand = bools(EXPAND);
  const markName = rle(MARK_NAME);

  // Rule 4: row counts.
  for (const [spec, rows] of [
    [OBJ_ACTOR, objActor],
    [OBJ_CTR, objCtr],
    [KEY_ACTOR, keyActor],
    [KEY_CTR, keyCtr],
    [KEY_STR, keyStr],
    [INSERT, insert],
    [VAL_META, meta],
    [PRED_GROUP, predCount],
    [EXPAND, expand],
    [MARK_NAME, markName],
  ] as const)
    if (rows !== undefined && rows.length !== N)
      refuse(`column 0x${spec.toString(16)} has ${rows.length} rows, not ${N}`);
  let predRows = 0;
  for (const c of predCount ?? []) {
    if (c === null) refuse("a predecessor count is null");
    predRows += Number(c as bigint);
  }
  for (const [spec, rows] of [
    [PRED_ACTOR, predActor],
    [PRED_CTR, predCtr],
  ] as const)
    if (rows !== undefined && rows.length !== predRows)
      refuse(`column 0x${spec.toString(16)} has ${rows.length} rows, not ${predRows}`);

  const actorOf = (index: Row): string => {
    const i = num(index);
    if (i === null) return refuse("an actor index is null");
    if (i === 0) return hex(actor);
    const o = others[i - 1];
    if (o === undefined) return refuse("an actor index is out of range");
    return hex(o);
  };
  const named = new Set<number>();
  const counter = (v: Row, what: string): number => {
    const c = num(v);
    if (c === null || c < 1 || c >= U32)
      return refuse(`${what} is not a counter from 1 below 2^32`);
    return c;
  };

  // Values (rule 6) and the value bytes column (rule 4).
  const raw = data.get(VAL_RAW) ?? new Uint8Array(0);
  let rawAt = 0;
  const valueTypes: number[] = [];
  for (let i = 0; i < N; i++) {
    const m = meta?.[i] ?? null;
    if (m === null) refuse("a value metadata row is null");
    const mv = m as bigint;
    const type = Number(mv & 15n);
    const len = mv >> 4n;
    if (len > BigInt(raw.length - rawAt)) refuse("the value bytes are shorter than their metadata");
    checkValue(type, raw.subarray(rawAt, rawAt + Number(len)));
    rawAt += Number(len);
    valueTypes.push(type);
  }
  if (rawAt !== raw.length) refuse("the value bytes are longer than their metadata");

  if (startOp + BigInt(N) - 1n >= BigInt(U32)) refuse("the last operation counter is 2^32 or more");
  const start = Number(startOp);

  const ops: ParsedOp[] = [];
  let p = 0;
  let anyObj = false;
  let anyElem = false;
  let anyKeyCtr = false;
  let anyProp = false;
  let anyPred = false;
  let anyExpand = false;
  let anyMark = false;
  for (let i = 0; i < N; i++) {
    // Rule 7: actions.
    const a = num(action[i] as Row);
    if (a === null || a > 7) refuse("an action is not 0 to 7");
    const act = a as number;
    const ins = insert?.[i] ?? false;
    const exp = expand?.[i] ?? false;
    const mark = markName?.[i] ?? null;
    if ((act === 0 || act === 2 || act === 4 || act === 6 || act === 3) && valueTypes[i] !== 0)
      refuse("an operation that makes an object or deletes has a value");
    if (act === 5 && valueTypes[i] !== 3 && valueTypes[i] !== 4)
      refuse("an increment's value is not an integer");
    if (act === 7 && !ins) refuse("a mark does not insert");
    if (act !== 7 && (exp || mark !== null)) refuse("only a mark has a mark name or expands");
    if (mark !== null) {
      anyMark = true;
      utf8(mark as Uint8Array, "a mark name");
    }
    if (exp) anyExpand = true;

    // Rule 8: the object and the key.
    const oa = objActor?.[i] ?? null;
    const oc = objCtr?.[i] ?? null;
    let obj: string;
    if (oa === null && oc === null) obj = "_root";
    else if (oa !== null && oc !== null) {
      obj = `${counter(oc, "an object counter")}@${actorOf(oa)}`;
      named.add(num(oa) as number);
      anyObj = true;
    } else return refuse("an object is half null");
    const ka = keyActor?.[i] ?? null;
    const kc = keyCtr?.[i] ?? null;
    const ks = keyStr?.[i] ?? null;
    let key: ParsedOp["key"];
    if (ks !== null && ka === null && kc === null) {
      key = { kind: "prop", name: utf8(ks as Uint8Array, "a key") };
      anyProp = true;
    } else if (ks === null && ka === null && kc !== null && num(kc) === 0) {
      key = { kind: "head" };
      anyKeyCtr = true;
    } else if (ks === null && ka !== null && kc !== null) {
      key = { kind: "elem", id: `${counter(kc, "a key counter")}@${actorOf(ka)}` };
      named.add(num(ka) as number);
      anyElem = true;
      anyKeyCtr = true;
    } else return refuse("a key is neither a property, the head nor an element");

    // Rule 9: the predecessors, ascending by counter then actor.
    const count = Number(predCount?.[i] as bigint);
    const pred: string[] = [];
    let last: { ctr: number; actor: Uint8Array } | null = null;
    for (let k = 0; k < count; k++, p++) {
      const pa = predActor?.[p] ?? null;
      const ctr = counter(predCtr?.[p] ?? null, "a predecessor counter");
      const id = actorOf(pa);
      const idBytes = num(pa) === 0 ? actor : (others[(num(pa) as number) - 1] as Uint8Array);
      if (
        last !== null &&
        (ctr < last.ctr || (ctr === last.ctr && compareBytes(last.actor, idBytes) >= 0))
      )
        refuse("the predecessors are not strictly ascending");
      last = { ctr, actor: idBytes };
      named.add(num(pa) as number);
      pred.push(`${ctr}@${id}`);
      anyPred = true;
    }
    ops.push(
      Object.freeze({
        obj,
        key,
        insert: ins,
        action: act,
        pred: Object.freeze(pred),
        valueType: valueTypes[i] as number,
      }),
    );
  }

  // Rule 3: each column present exactly when the table says.
  const presence: [number, boolean][] = [
    [OBJ_ACTOR, anyObj],
    [OBJ_CTR, anyObj],
    [KEY_ACTOR, anyElem],
    [KEY_CTR, anyKeyCtr],
    [KEY_STR, anyProp],
    [INSERT, N > 0],
    [ACTION, N > 0],
    [VAL_META, N > 0],
    [VAL_RAW, raw.length > 0],
    [PRED_GROUP, N > 0],
    [PRED_ACTOR, anyPred],
    [PRED_CTR, anyPred],
    [EXPAND, anyExpand],
    [MARK_NAME, anyMark],
  ];
  for (const [spec, want] of presence)
    if (data.has(spec) !== want)
      refuse(`column 0x${spec.toString(16)} is ${want ? "missing" : "present without a use"}`);

  // Rule 2: the other actors are exactly those the operations name.
  named.delete(0);
  if (named.size !== others.length)
    refuse("the other actors are not exactly those the operations name");

  return Object.freeze({
    actor: hex(actor),
    seq: Number(seq),
    startOp: start,
    deps: Object.freeze(deps.map(hex)),
    otherActors: Object.freeze(others.map(hex)),
    ops: Object.freeze(ops),
    beginsWithAuthor: authored,
  });
}
