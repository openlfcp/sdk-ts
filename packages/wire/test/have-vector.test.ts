import { type PrincipalId, principalId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  type ActorRange,
  actorHaveToCbor,
  addRange,
  addSequence,
  batchDataRanges,
  canonicalFrontierFromCbor,
  canonicalFrontierToCbor,
  type HaveVector,
  hasSequence,
  type LiveHaveEntry,
  liveHavesOf,
  MAX_DATA_GET_RANGES,
  missingAfter,
  missingFrom,
  normalizeLiveHaves,
  unionHaves,
} from "../src/index.js";
import { seq32 } from "./synthetic.js";

// Synthetic Have Vectors; the published canonical-frontier and have_*
// vectors run in the conformance runner.

const A = principalId(seq32(10));
const B = principalId(seq32(20));
const C = principalId(seq32(30));
const EMPTY: HaveVector = [];

/** One actor's holdings as [contiguous, extras]. */
const shape = (v: HaveVector, actor: PrincipalId) => {
  const h = v.find((x) => toHex(x.principalId) === toHex(actor));
  return h === undefined ? undefined : [h.contiguous, h.extras.map(([s, e]) => [s, e])];
};
const live = (
  actor: PrincipalId,
  contiguous: bigint,
  ranges?: [bigint, bigint][],
): LiveHaveEntry => ({
  principalId: actor,
  contiguous,
  ...(ranges ? { ranges } : {}),
});
const codeOf = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? String(e);
  }
  return undefined;
};

describe("insertion and normalization (§28)", () => {
  it("1, 2, 3. empty, first sequence, contiguous growth", () => {
    expect(EMPTY).toEqual([]);
    let v = addSequence(EMPTY, A, 1n);
    expect(shape(v, A)).toEqual([1n, []]);
    v = addSequence(v, A, 2n);
    v = addRange(v, A, 3n, 5n);
    expect(shape(v, A)).toEqual([5n, []]);
  });

  it("4, 5. a hole is kept as an extra and collapses when filled", () => {
    let v = addRange(EMPTY, A, 1n, 5n);
    v = addRange(v, A, 8n, 10n);
    expect(shape(v, A)).toEqual([5n, [[8n, 10n]]]);
    v = addSequence(v, A, 6n);
    expect(shape(v, A)).toEqual([6n, [[8n, 10n]]]);
    v = addSequence(v, A, 7n);
    expect(shape(v, A)).toEqual([10n, []]);
  });

  it("6, 7, 8. several extras, an overlapping insert and an adjacent insert merge", () => {
    let v = addRange(EMPTY, A, 1n, 2n);
    v = addRange(v, A, 10n, 12n);
    v = addRange(v, A, 20n, 22n);
    v = addRange(v, A, 30n, 31n);
    expect(shape(v, A)).toEqual([
      2n,
      [
        [10n, 12n],
        [20n, 22n],
        [30n, 31n],
      ],
    ]);
    v = addRange(v, A, 11n, 21n); // overlaps two extras
    expect(shape(v, A)).toEqual([
      2n,
      [
        [10n, 22n],
        [30n, 31n],
      ],
    ]);
    v = addRange(v, A, 23n, 29n); // adjacent on both sides
    expect(shape(v, A)).toEqual([2n, [[10n, 31n]]]);
  });

  it("9. a duplicate insert changes nothing", () => {
    const v = addRange(addRange(EMPTY, A, 1n, 4n), A, 7n, 9n);
    expect(addRange(v, A, 2n, 3n)).toEqual(v);
    expect(addSequence(v, A, 8n)).toEqual(v);
  });

  it("10. a reversed range or one containing sequence 0 is refused (§48, G-HV1)", () => {
    expect(codeOf(() => addRange(EMPTY, A, 5n, 4n))).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => addSequence(EMPTY, A, 0n))).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => normalizeLiveHaves([live(A, 3n, [[9n, 7n]])]))).toBe("INVALID_STRUCTURE");
    expect(codeOf(() => normalizeLiveHaves([live(A, 3n, [[0n, 7n]])]))).toBe("INVALID_STRUCTURE");
  });

  it("11, 12, 13. live ranges at or below contiguous, overlapping, adjacent or split are normalized losslessly", () => {
    const v = normalizeLiveHaves([
      live(A, 5n, [
        [3n, 6n],
        [9n, 10n],
        [8n, 8n],
        [12n, 14n],
        [13n, 13n],
      ]),
      live(A, 0n, [[16n, 16n]]),
      live(B, 7n, []),
    ]);
    expect(shape(v, A)).toEqual([
      6n,
      [
        [8n, 10n],
        [12n, 14n],
        [16n, 16n],
      ],
    ]); // 7 was never held
    // 13. key 2 is omitted when there are no extras, so the canonical encoder accepts it.
    expect(shape(v, B)).toEqual([7n, []]);
    expect(() => canonicalFrontierToCbor(v)).not.toThrow();
    // An adjacent extra is absorbed into contiguous.
    expect(shape(normalizeLiveHaves([live(A, 5n, [[6n, 6n]])]), A)).toEqual([6n, []]);
  });

  it("14, 15. the canonical frontier refuses duplicate actors and orders by raw Principal ID", () => {
    const v = normalizeLiveHaves([live(C, 1n), live(A, 1n), live(B, 1n)]);
    expect(v.map((h) => toHex(h.principalId))).toEqual([A, B, C].map(toHex));
    const cbor = canonicalFrontierToCbor(v);
    expect(canonicalFrontierFromCbor(cbor)).toHaveLength(3);
    const a = actorHaveToCbor(v[0] as never);
    expect(codeOf(() => canonicalFrontierFromCbor([a, a]))).toBe("INVALID_STRUCTURE");
    // Raw byte order, not text order: 0x0a.. < 0x14.. < 0x1e...
    const high = principalId(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 0xff : 0)));
    const low = principalId(Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 0xff : 0)));
    expect(
      normalizeLiveHaves([live(high, 1n), live(low, 1n)]).map((h) => toHex(h.principalId)),
    ).toEqual([toHex(low), toHex(high)]);
  });

  it("liveHavesOf emits the normalized form (key 2 only with ranges)", () => {
    const v = normalizeLiveHaves([live(A, 3n, [[6n, 7n]]), live(B, 2n)]);
    expect(liveHavesOf(v)).toEqual([live(A, 3n, [[6n, 7n]]), { principalId: B, contiguous: 2n }]);
    expect(normalizeLiveHaves(liveHavesOf(v))).toEqual(v);
  });
});

describe("difference (§68)", () => {
  const local = normalizeLiveHaves([live(A, 100n), live(B, 40n)]);
  const remote = normalizeLiveHaves([live(A, 104n), live(B, 40n), live(C, 8n)]);

  it("the §68 example: request A 101..104 and C 1..8", () => {
    expect(missingFrom(local, remote)).toEqual([
      { actor: A, start: 101n, end: 104n },
      { actor: C, start: 1n, end: 8n },
    ]);
  });

  it("16-20. absent actors, a missing tail, a hole, remote extras we own, and up to date", () => {
    expect(missingFrom(EMPTY, normalizeLiveHaves([live(A, 3n)]))).toEqual([
      { actor: A, start: 1n, end: 3n },
    ]); // 16
    expect(missingFrom(remote, remote)).toEqual([]); // 17
    expect(
      missingFrom(normalizeLiveHaves([live(A, 10n)]), normalizeLiveHaves([live(A, 15n)])),
    ).toEqual([{ actor: A, start: 11n, end: 15n }]); // 18
    expect(
      missingFrom(
        normalizeLiveHaves([live(A, 5n, [[8n, 10n]])]),
        normalizeLiveHaves([live(A, 10n)]),
      ),
    ).toEqual([{ actor: A, start: 6n, end: 7n }]); // 19
    expect(
      missingFrom(
        normalizeLiveHaves([live(A, 20n)]),
        normalizeLiveHaves([live(A, 5n, [[8n, 10n]])]),
      ),
    ).toEqual([]); // 20
    // The local side's extras are never requested again.
    expect(
      missingFrom(normalizeLiveHaves([live(A, 2n, [[5n, 6n]])]), normalizeLiveHaves([live(A, 8n)])),
    ).toEqual([
      { actor: A, start: 3n, end: 4n },
      { actor: A, start: 7n, end: 8n },
    ]);
  });

  it("21. DATA_GET requests are split at 256 ranges (§49)", () => {
    let remoteHoles: HaveVector = EMPTY;
    for (let i = 0n; i < 600n; i++) remoteHoles = addSequence(remoteHoles, A, 2n * i + 1n);
    const ranges = missingFrom(EMPTY, remoteHoles);
    expect(ranges).toHaveLength(600);
    const batches = batchDataRanges(ranges);
    expect(batches.map((b) => b.length)).toEqual([256, 256, 88]);
    expect(MAX_DATA_GET_RANGES).toBe(256);
    expect(batches.flat()).toEqual(ranges);
  });

  it("22. after one exchange the vectors agree and repeated rounds request nothing", () => {
    const [a, b] = exchange(local, remote);
    expect(a).toEqual(b);
    expect(missingFrom(a, b)).toEqual([]);
    expect(exchange(a, b)).toEqual([a, b]);
  });

  it("missingAfter: catch-up after a Snapshot skips what the frontier covers (§66 step 4)", () => {
    const frontier = normalizeLiveHaves([live(A, 90n), live(C, 5n)]);
    const ours = normalizeLiveHaves([live(B, 40n)]);
    expect(missingAfter(frontier, ours, remote)).toEqual([
      { actor: A, start: 91n, end: 104n },
      { actor: C, start: 6n, end: 8n },
    ]);
  });

  it("held units are not counted: the peer's copy is requested again until it is accepted (G-DP1)", () => {
    // seq 1 and 3 accepted; seq 2's unit arrived but is held (its previous unit was missing).
    let accepted = addSequence(addSequence(EMPTY, A, 1n), A, 3n);
    const peer = normalizeLiveHaves([live(A, 3n)]);
    expect(missingFrom(accepted, peer)).toEqual([{ actor: A, start: 2n, end: 2n }]);
    accepted = addSequence(accepted, A, 2n); // accepted after the gap closed
    expect(missingFrom(accepted, peer)).toEqual([]);
  });
});

/** One anti-entropy round: each side requests what it misses and adds it. */
function exchange(a: HaveVector, b: HaveVector): [HaveVector, HaveVector] {
  const apply = (v: HaveVector, ranges: readonly ActorRange[]) =>
    ranges.reduce((acc, r) => addRange(acc, r.actor, r.start, r.end), v);
  return [apply(a, missingFrom(a, b)), apply(b, missingFrom(b, a))];
}

// ---------------------------------------------------------------------------
// Property tests against a brute-force set model.

function mulberry32(seed: number) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}
const ACTORS = [A, B, C];
const MAX = 40;

/** The set model: actor hex → held sequences. */
type Model = Map<string, Set<number>>;
const modelOf = (v: HaveVector): Model => {
  const m: Model = new Map();
  for (const h of v) {
    const s = new Set<number>();
    for (let q = 1; q <= Number(h.contiguous); q++) s.add(q);
    for (const [a, b] of h.extras) for (let q = Number(a); q <= Number(b); q++) s.add(q);
    if (s.size > 0) m.set(toHex(h.principalId), s);
  }
  return m;
};
const flat = (m: Model) =>
  [...m.entries()].flatMap(([k, s]) => [...s].map((q) => `${k}:${q}`)).sort();
const rangesModel = (rs: readonly ActorRange[]) => {
  const m: Model = new Map();
  for (const r of rs) {
    const s = m.get(toHex(r.actor)) ?? new Set<number>();
    for (let q = Number(r.start); q <= Number(r.end); q++) s.add(q);
    m.set(toHex(r.actor), s);
  }
  return m;
};

function randomLive(rand: () => number): LiveHaveEntry[] {
  const n = Math.floor(rand() * 5);
  return Array.from({ length: n }, () => {
    const actor = ACTORS[Math.floor(rand() * ACTORS.length)] as PrincipalId;
    const ranges = Array.from({ length: Math.floor(rand() * 4) }, () => {
      const s = 1 + Math.floor(rand() * MAX);
      return [BigInt(s), BigInt(s + Math.floor(rand() * 6))] as [bigint, bigint];
    });
    return live(actor, BigInt(Math.floor(rand() * 8)), ranges);
  });
}
const liveModel = (entries: readonly LiveHaveEntry[]): Model => {
  const m: Model = new Map();
  for (const e of entries) {
    const s = m.get(toHex(e.principalId)) ?? new Set<number>();
    for (let q = 1; q <= Number(e.contiguous); q++) s.add(q);
    for (const [a, b] of e.ranges ?? []) for (let q = Number(a); q <= Number(b); q++) s.add(q);
    if (s.size > 0) m.set(toHex(e.principalId), s);
  }
  return m;
};

describe("properties (seeded, brute-force set model)", () => {
  const RUNS = 300;

  it("normalization is lossless, idempotent and canonical", () => {
    const rand = mulberry32(0x0280);
    for (let i = 0; i < RUNS; i++) {
      const entries = randomLive(rand);
      const v = normalizeLiveHaves(entries);
      expect(flat(modelOf(v))).toEqual(flat(liveModel(entries)));
      expect(normalizeLiveHaves(liveHavesOf(v))).toEqual(v);
      expect(canonicalFrontierFromCbor(canonicalFrontierToCbor(v))).toEqual(v);
    }
  });

  it("insert is exact: the vector holds exactly the model's set", () => {
    const rand = mulberry32(0x0281);
    for (let i = 0; i < RUNS; i++) {
      let v: HaveVector = EMPTY;
      const m: Model = new Map();
      for (let k = 0; k < 12; k++) {
        const actor = ACTORS[Math.floor(rand() * 3)] as PrincipalId;
        const s = 1 + Math.floor(rand() * MAX);
        const e = s + Math.floor(rand() * 4);
        v = addRange(v, actor, BigInt(s), BigInt(e));
        const set = m.get(toHex(actor)) ?? new Set<number>();
        for (let q = s; q <= e; q++) set.add(q);
        m.set(toHex(actor), set);
      }
      expect(flat(modelOf(v))).toEqual(flat(m));
      for (const actor of ACTORS)
        for (let q = 1; q <= MAX + 4; q++)
          expect(hasSequence(v, actor, BigInt(q))).toBe(m.get(toHex(actor))?.has(q) ?? false);
    }
  });

  it("difference is exact and minimal", () => {
    const rand = mulberry32(0x0282);
    for (let i = 0; i < RUNS; i++) {
      const l = normalizeLiveHaves(randomLive(rand));
      const r = normalizeLiveHaves(randomLive(rand));
      const d = missingFrom(l, r);
      const expected = flat(modelOf(r)).filter((x) => !flat(modelOf(l)).includes(x));
      expect(flat(rangesModel(d))).toEqual(expected);
      // Minimal: no empty range, and no two ranges of one actor touch or overlap.
      for (let k = 0; k < d.length; k++) {
        const x = d[k] as ActorRange;
        expect(x.start <= x.end).toBe(true);
        const y = d[k + 1];
        if (y && toHex(y.actor) === toHex(x.actor)) expect(y.start > x.end + 1n).toBe(true);
      }
    }
  });

  it("an exchange converges in one round, and repeated rounds are no-ops", () => {
    const rand = mulberry32(0x0283);
    for (let i = 0; i < RUNS; i++) {
      const a = normalizeLiveHaves(randomLive(rand));
      const b = normalizeLiveHaves(randomLive(rand));
      const [a1, b1] = exchange(a, b);
      expect(flat(modelOf(a1))).toEqual(flat(modelOf(unionHaves(a, b))));
      expect(flat(modelOf(b1))).toEqual(flat(modelOf(a1)));
      expect(missingFrom(a1, b1)).toEqual([]);
      expect(missingFrom(b1, a1)).toEqual([]);
      const [a2, b2] = exchange(a1, b1);
      expect([a2, b2]).toEqual([a1, b1]);
    }
  });
});
