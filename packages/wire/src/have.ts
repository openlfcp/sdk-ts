import {
  compareCanonicalFrontierOrder,
  type PrincipalId,
  principalId,
  toHex,
} from "@openlfcp/core";
import { type CborValue, cborMap } from "./cbor/index.js";
import { Fields, invalid } from "./fields.js";

/** An inclusive range of actor sequence numbers (§28 `sequence-range`). */
export type SequenceRange = readonly [start: bigint, end: bigint];

/**
 * An Actor Have entry (LFCP-WIRE-01 §28): the actor's highest contiguous
 * sequence and the extra ranges received above it.
 */
export interface ActorHave {
  readonly principalId: PrincipalId;
  readonly contiguous: bigint;
  /** Empty when the CBOR omits key 2. */
  readonly extras: readonly SequenceRange[];
}

/**
 * Decodes a canonical `actor-have` (§28.1 rules 1–8), the form required
 * inside persistent objects and cryptographic inputs:
 *
 * - keys 0 and 1 present, key 2 only when there is at least one range;
 * - every range is a two-element array with start <= end;
 * - the first range starts strictly above `contiguous`;
 * - each later range starts more than one past the previous end, so the
 *   ranges are sorted, non-overlapping and non-adjacent.
 *
 * A violation is INVALID_STRUCTURE (MALFORMED_MESSAGE on the wire, §28.1, N6).
 * Live Haves in messages are decoded as received by message.ts and
 * normalized by LFCP-028; they are not covered here.
 */
export function actorHaveFromCbor(value: CborValue): ActorHave {
  const what = "actor-have";
  const f = new Fields(value, what, [0, 1], [2]);
  const id = principalId(f.bytes(0, 32));
  const contiguous = f.uint(1);
  const extras: SequenceRange[] = [];
  if (f.has(2)) {
    const list = f.array(2);
    if (list.length === 0) invalid(what, "key 2 must be omitted when there are no ranges (§28.1)");
    // §28.1 rule 5: "ranges MUST be strictly above contiguous; the first
    // range MUST start at or above contiguous + 2, because a range starting
    // at contiguous + 1 extends the contiguous prefix".
    let floor = contiguous + 1n; // the next range must start above this
    for (const item of list) {
      if (!Array.isArray(item) || item.length !== 2) invalid(what, "a range must be [start, end]");
      const [start, end] = (item as CborValue[]).map((n) => {
        if ((typeof n === "number" || typeof n === "bigint") && n >= 0) return BigInt(n);
        return invalid(what, "range bounds must be unsigned integers");
      }) as [bigint, bigint];
      if (start > end) invalid(what, "a range must have start <= end (§28.1)");
      if (start <= floor) {
        invalid(
          what,
          extras.length === 0
            ? "ranges must start above contiguous + 1 (§28.1 rule 5)"
            : "ranges must be sorted, non-overlapping and non-adjacent (§28.1)",
        );
      }
      extras.push(Object.freeze([start, end] as const));
      floor = end + 1n;
    }
  }
  return Object.freeze({ principalId: id, contiguous, extras: Object.freeze(extras) });
}

/**
 * Decodes a canonical frontier (§28.2): an array of canonical actor-have
 * entries in strictly ascending raw Principal ID order, which also rules
 * out two entries for one Principal (§28.1 rule 9). A violation is
 * INVALID_STRUCTURE (MALFORMED_MESSAGE on the wire, §28.2, N6).
 */
export function canonicalFrontierFromCbor(value: CborValue): readonly ActorHave[] {
  if (!Array.isArray(value)) invalid("canonical frontier", "not an array");
  const entries = (value as readonly CborValue[]).map(actorHaveFromCbor);
  for (let i = 1; i < entries.length; i++) {
    const order = compareCanonicalFrontierOrder(
      (entries[i - 1] as ActorHave).principalId,
      (entries[i] as ActorHave).principalId,
    );
    if (order === 0)
      invalid("canonical frontier", "two entries for the same Principal (§28.1 rule 9)");
    if (order > 0)
      invalid("canonical frontier", "entries must be sorted by raw Principal ID (§28.2)");
  }
  return Object.freeze(entries);
}

/** The canonical CBOR of an actor-have (§28.1): key 2 only when there are ranges. Checked like a received one. */
export function actorHaveToCbor(have: ActorHave): CborValue {
  const value = cborMap(
    have.extras.length === 0
      ? [
          [0, have.principalId],
          [1, have.contiguous],
        ]
      : [
          [0, have.principalId],
          [1, have.contiguous],
          [2, have.extras.map(([start, end]) => [start, end])],
        ],
  );
  actorHaveFromCbor(value);
  return value;
}

/** A canonical frontier (§28.2): entries sorted by raw Principal ID; duplicates are refused. */
export function canonicalFrontierToCbor(frontier: readonly ActorHave[]): CborValue {
  const sorted = [...frontier].sort((a, b) =>
    compareCanonicalFrontierOrder(a.principalId, b.principalId),
  );
  const value = sorted.map(actorHaveToCbor);
  canonicalFrontierFromCbor(value);
  return value;
}

// ---------------------------------------------------------------------------
// Have Vectors: normalization, insertion and difference (LFCP-028)
//
// A Have Vector is the set of Data Units a replica holds, as one normalized
// ActorHave per actor sorted by raw Principal ID (the canonical frontier
// form, §28, §28.2). Every operation here is pure and returns a normalized
// vector, so one set of holdings has exactly one representation.
//
// A Have Vector records ACCEPTED units only. A unit that the receive
// pipeline holds (§26.2, G-DP1: a gap or a broken previous link) is not yet
// accepted, so it is not counted: the peer may send it again, which is
// harmless (at-least-once delivery, §70), and it is added once accepted.

/** A Have Vector: normalized ActorHave entries, one per actor, by ascending raw Principal ID. */
export type HaveVector = readonly ActorHave[];

/** A live actor-have as received in a message (§48): any range order, possibly repeated actors. */
export interface LiveHaveEntry {
  readonly principalId: PrincipalId;
  readonly contiguous: bigint;
  readonly ranges?: readonly SequenceRange[];
}

/** An inclusive range of one actor's sequences, as in a §49 `data-range`. */
export interface ActorRange {
  readonly actor: PrincipalId;
  readonly start: bigint;
  readonly end: bigint;
}

/** §49: "A request SHOULD contain no more than 256 ranges." */
export const MAX_DATA_GET_RANGES = 256;

const UINT64_MAX = 2n ** 64n - 1n;

/** Merges intervals into sorted, non-overlapping, non-adjacent ones (lossless). */
function mergeIntervals(intervals: readonly SequenceRange[]): SequenceRange[] {
  const sorted = [...intervals].sort(([a, b], [c, d]) =>
    a !== c ? (a < c ? -1 : 1) : b < d ? -1 : b > d ? 1 : 0,
  );
  const out: [bigint, bigint][] = [];
  for (const [s, e] of sorted) {
    const last = out[out.length - 1];
    if (last !== undefined && s <= last[1] + 1n) {
      if (e > last[1]) last[1] = e;
    } else out.push([s, e]);
  }
  return out;
}

/** The normalized ActorHave holding exactly 1..contiguous plus `ranges` (§28). */
function haveFromIntervals(principal: PrincipalId, intervals: readonly SequenceRange[]): ActorHave {
  const merged = mergeIntervals(intervals);
  let contiguous = 0n;
  let i = 0;
  if (merged[0] !== undefined && merged[0][0] === 1n) {
    contiguous = merged[0][1];
    i = 1;
  }
  return Object.freeze({
    principalId: principal,
    contiguous,
    extras: Object.freeze(merged.slice(i).map(([s, e]) => Object.freeze([s, e] as const))),
  });
}

/** The holdings of one ActorHave as intervals. */
const intervalsOf = (have: ActorHave): SequenceRange[] => [
  ...(have.contiguous > 0n ? [[1n, have.contiguous] as const] : []),
  ...have.extras,
];

/**
 * §48 (G-HV1): a live range with start > end, or one that includes
 * sequence 0, is MALFORMED_MESSAGE (INVALID_STRUCTURE here); sequences
 * must fit in uint64. Use as DecodeOptions.liveHave; decodeMessage applies
 * it by default.
 */
export function checkLiveHave(entry: LiveHaveEntry): void {
  if (entry.contiguous < 0n || entry.contiguous > UINT64_MAX)
    invalid("actor-have", "contiguous must be a uint64");
  for (const [start, end] of entry.ranges ?? []) {
    if (start > end) invalid("actor-have", "a range has start > end (§48)");
    if (start === 0n) invalid("actor-have", "a range includes sequence 0 (§48)");
    if (end > UINT64_MAX) invalid("actor-have", "a range end must be a uint64");
  }
}

/**
 * Normalizes live actor-haves losslessly (§48, G-MSG6): unsorted,
 * overlapping or adjacent ranges, ranges touching `contiguous`, and several
 * entries for one actor are merged into one normalized entry per actor,
 * sorted by raw Principal ID. Reversed ranges and sequence 0 are refused
 * (checkLiveHave). An actor entry holding nothing stays as contiguous 0
 * with no ranges.
 */
export function normalizeLiveHaves(entries: readonly LiveHaveEntry[]): HaveVector {
  const byActor = new Map<string, { id: PrincipalId; intervals: SequenceRange[] }>();
  for (const e of entries) {
    checkLiveHave(e);
    const key = toKey(e.principalId);
    const slot = byActor.get(key) ?? { id: principalId(e.principalId), intervals: [] };
    if (e.contiguous > 0n) slot.intervals.push([1n, e.contiguous]);
    slot.intervals.push(...(e.ranges ?? []));
    byActor.set(key, slot);
  }
  return sortVector([...byActor.values()].map((a) => haveFromIntervals(a.id, a.intervals)));
}

/** A normalized vector as live entries for DATA_HAVE and friends: our encoder always sends normalized form. */
export const liveHavesOf = (vector: HaveVector): LiveHaveEntry[] =>
  vector.map((h) =>
    Object.freeze({
      principalId: h.principalId,
      contiguous: h.contiguous,
      ...(h.extras.length > 0 ? { ranges: h.extras } : {}),
    }),
  );

const toKey = (id: Uint8Array): string => toHex(id);

function sortVector(entries: ActorHave[]): HaveVector {
  return Object.freeze(
    [...entries].sort((a, b) => compareCanonicalFrontierOrder(a.principalId, b.principalId)),
  );
}

const find = (vector: HaveVector, actor: Uint8Array): ActorHave | undefined => {
  const key = toKey(actor);
  return vector.find((h) => toKey(h.principalId) === key);
};

/** Whether the vector holds `seq` of `actor`. */
export function hasSequence(vector: HaveVector, actor: PrincipalId, seq: bigint): boolean {
  const h = find(vector, actor);
  if (h === undefined || seq < 1n) return false;
  return seq <= h.contiguous || h.extras.some(([s, e]) => s <= seq && seq <= e);
}

/**
 * Adds `start..end` of `actor` (sequences of accepted units only; see the
 * module note on held units). Extends the contiguous prefix, fills holes
 * and merges extras; adding what is already held changes nothing.
 */
export function addRange(
  vector: HaveVector,
  actor: PrincipalId,
  start: bigint,
  end: bigint,
): HaveVector {
  checkLiveHave({ principalId: actor, contiguous: 0n, ranges: [[start, end]] });
  const current = find(vector, actor);
  const next = haveFromIntervals(principalId(actor), [
    ...(current ? intervalsOf(current) : []),
    [start, end],
  ]);
  return sortVector([...vector.filter((h) => h !== current), next]);
}

/** Adds one sequence of `actor` (see addRange). */
export const addSequence = (vector: HaveVector, actor: PrincipalId, seq: bigint): HaveVector =>
  addRange(vector, actor, seq, seq);

/** The union of two vectors (normalized). */
export function unionHaves(a: HaveVector, b: HaveVector): HaveVector {
  return normalizeLiveHaves([...liveHavesOf(a), ...liveHavesOf(b)]);
}

/**
 * Subtracts sorted, merged `have` from sorted, merged `want` in one pass:
 * linear in the number of intervals, whatever their span.
 */
function subtract(want: readonly SequenceRange[], have: readonly SequenceRange[]): SequenceRange[] {
  const out: SequenceRange[] = [];
  let j = 0;
  for (const [ws, we] of want) {
    let s = ws;
    while (j < have.length && have[j]![1] < s) j++;
    for (let k = j; k < have.length && have[k]![0] <= we; k++) {
      const [hs, he] = have[k]!;
      if (hs > s) out.push([s, hs - 1n]);
      s = he + 1n;
      j = k;
      if (s > we) break;
    }
    if (s <= we) out.push([s, we]);
  }
  return out;
}

/**
 * The units `remote` holds that `local` does not (§68), as the fewest
 * possible ranges: per actor, maximal intervals, by ascending raw Principal
 * ID and then sequence. Covers actors absent locally, a missing contiguous
 * tail, holes, and remote extras; never requests what local already holds.
 */
export function missingFrom(local: HaveVector, remote: HaveVector): ActorRange[] {
  const out: ActorRange[] = [];
  const mine = new Map(local.map((h) => [toKey(h.principalId), h]));
  for (const r of sortVector([...remote])) {
    const l = mine.get(toKey(r.principalId));
    const gaps = subtract(mergeIntervals(intervalsOf(r)), l ? mergeIntervals(intervalsOf(l)) : []);
    for (const [start, end] of gaps) out.push(Object.freeze({ actor: r.principalId, start, end }));
  }
  return out;
}

/**
 * Catch-up after loading a Snapshot (§29, §66 step 4): what `theirs` holds
 * that is neither in `ours` nor covered by the Snapshot's frontier.
 */
export const missingAfter = (
  snapshotFrontier: HaveVector,
  ours: HaveVector,
  theirs: HaveVector,
): ActorRange[] => missingFrom(unionHaves(ours, snapshotFrontier), theirs);

/** Splits ranges into DATA_GET-sized batches (§49: at most 256 ranges per request). */
export function batchDataRanges(
  ranges: readonly ActorRange[],
  max: number = MAX_DATA_GET_RANGES,
): ActorRange[][] {
  if (!Number.isInteger(max) || max < 1)
    throw new RangeError("the batch size must be a positive integer");
  const out: ActorRange[][] = [];
  for (let i = 0; i < ranges.length; i += max) out.push(ranges.slice(i, i + max));
  return out;
}
