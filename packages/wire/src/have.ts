import { compareCanonicalFrontierOrder, type PrincipalId, principalId } from "@openlfcp/core";
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
 * Live DATA_HAVE messages (LFCP-026, LFCP-028) are not covered here.
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
    // PROVISIONAL (W3, approved for baseline.3): the first extra range starts
    // at contiguous + 2 or later. A range starting at contiguous + 1 would
    // extend the contiguous run, so contiguous would not be the highest
    // contiguous sequence (§28).
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
            ? "ranges must start above contiguous + 1 (§28.1; W3)"
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
