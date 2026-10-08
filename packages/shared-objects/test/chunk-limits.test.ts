import * as A from "@automerge/automerge";
import { deflateSync } from "fflate";
import { describe, expect, it } from "vitest";
import {
  CHANGE_LIMITS,
  checkChangeExpansion,
  checkSnapshotExpansion,
  SNAPSHOT_LIMITS_FLOOR,
} from "../src/admission/limits.js";
import { ProfileInvalidError } from "../src/profile-invalid.js";

// SHARED-OBJECTS-PROFILE-01 §11.1 and §13.1 (SPEC-PATCH-07): the expansion
// walker, checked against Automerge itself (differential), against bombs
// at and past every limit, and against mutated bytes (fuzz).

const ACTOR = "aa".repeat(32);
const ACTION = 4; // the change and document op column whose values are the ops
const PRED = 7;

type Doc = A.Doc<Record<string, unknown>>;

/** A deterministic pseudo-random generator (test data only). */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

/** Documents with maps, lists, text, counters, deletes and concurrent edits. */
function documents(count: number): Doc[] {
  const out: Doc[] = [];
  for (let n = 0; n < count; n++) {
    const r = rng(n + 1);
    let a: Doc = A.init({ actor: ACTOR });
    a = A.change(a, (d) => {
      d.objects = {};
      d.list = [];
      d.text = "hello";
      d.count = new A.Counter(0);
    });
    let b: Doc = A.clone(a, { actor: "bb".repeat(32) });
    for (let i = 0; i < 20 + Math.floor(r() * 60); i++) {
      const which = r() < 0.5;
      const edit = (d: Record<string, unknown>) => {
        const k = `k${Math.floor(r() * 30)}`;
        const op = r();
        if (op < 0.3)
          (d.objects as Record<string, unknown>)[k] = {
            title: "x".repeat(Math.floor(r() * 50)),
            n: i,
          };
        else if (op < 0.5) (d.list as unknown[]).push(i, `s${i}`);
        else if (op < 0.6 && (d.list as unknown[]).length > 0) (d.list as unknown[]).splice(0, 1);
        else if (op < 0.7) (d.count as A.Counter).increment(i);
        else if (op < 0.8) A.splice(d as never, ["text"], 0, 0, `t${i}`);
        else if (k in (d.objects as object)) delete (d.objects as Record<string, unknown>)[k];
        else d[k] = r() < 0.5 ? null : i;
      };
      if (which) a = A.change(a, edit);
      else b = A.change(b, edit);
      if (r() < 0.2) {
        a = A.merge(a, A.clone(b));
        b = A.merge(b, A.clone(a));
      }
    }
    out.push(A.merge(a, b));
  }
  return out;
}

const refused = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(ProfileInvalidError);
    expect(e).toMatchObject({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" });
    return;
  }
  throw new Error("not refused");
};

type Column = [number, Uint8Array];
const uleb = (n: number) => {
  const out: number[] = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return out;
};
/** A change chunk with its operation columns replaced (no checksum fix: the walker does not check it). */
function rebuildColumns(change: Uint8Array, mutate: (cols: Column[]) => Column[]): Uint8Array {
  let pos = 9;
  const u = () => {
    let v = 0;
    let scale = 1;
    for (;;) {
      const b = change[pos++] as number;
      v += (b & 0x7f) * scale;
      if ((b & 0x80) === 0) return v;
      scale *= 128;
    }
  };
  const skip = (n: number) => {
    pos += n;
  };
  u();
  const start = pos;
  skip(u() * 32);
  skip(u());
  u();
  u();
  u(); // time is a signed LEB128; skipping its bytes is the same
  skip(u());
  const others = u();
  for (let i = 0; i < others; i++) skip(u());
  const headerEnd = pos;
  const metas = Array.from({ length: u() }, () => [u(), u()] as const);
  const cols: Column[] = metas.map(([spec, length]) => {
    const data = change.subarray(pos, pos + length);
    pos += length;
    return [spec, data];
  });
  const next = mutate(cols);
  const body = [
    ...change.subarray(start, headerEnd),
    ...uleb(next.length),
    ...next.flatMap(([spec, data]) => [...uleb(spec), ...uleb(data.length)]),
    ...next.flatMap(([, data]) => [...data]),
    ...change.subarray(pos),
  ];
  return Uint8Array.from([...change.subarray(0, 9), ...uleb(body.length), ...body]);
}

const cols = (change: Uint8Array) => checkChangeExpansion(change).columns.length;

/** A change of `n` ops `root[key] = null` (every column run-length collapses). */
function nullSets(n: number, key = "k", preds: string[] = []): Uint8Array {
  const base = A.decodeChange(
    A.getLastLocalChange(
      A.change(A.init({ actor: ACTOR }), (d: Record<string, unknown>) => {
        d.a = 0;
      }),
    ) as Uint8Array,
  );
  const ops = Array.from({ length: n }, () => ({
    action: "set",
    obj: "_root",
    key,
    value: null,
    pred: preds,
  }));
  return A.encodeChange({
    actor: ACTOR,
    seq: 2,
    startOp: base.startOp + base.ops.length,
    time: 0,
    message: null,
    deps: [base.hash],
    ops,
  } as never);
}

describe("the expansion walker agrees with Automerge", () => {
  const docs = documents(40);

  it("counts every change's ops and pred entries exactly", () => {
    let changes = 0;
    for (const d of docs)
      for (const c of A.getAllChanges(d)) {
        const decoded = A.decodeChange(c);
        const e = checkChangeExpansion(c);
        const action = e.columns.find((x) => x.spec >> 4 === ACTION && (x.spec & 7) === 2);
        expect(action?.rows ?? 0).toBe(decoded.ops.length);
        const preds = decoded.ops.reduce((n, o) => n + o.pred.length, 0);
        const group = e.columns.find((x) => x.spec >> 4 === PRED && (x.spec & 7) === 0);
        expect(group?.rows ?? 0).toBe(group === undefined ? 0 : decoded.ops.length);
        expect(e.groupSum).toBe(preds);
        changes++;
      }
    expect(changes).toBeGreaterThan(1000);
  });

  it("counts every save's changes and ops exactly, inflating deflated columns", () => {
    let deflated = 0;
    for (const d of docs) {
      const save = A.save(d);
      const e = checkSnapshotExpansion(save);
      const changes = A.getAllChanges(d);
      // A document stores no row for a delete: the deleted op records it as a successor.
      const ops = changes.reduce(
        (n, c) => n + A.decodeChange(c).ops.filter((o) => o.action !== "del").length,
        0,
      );
      expect(e.columns[0]?.rows).toBe(changes.length); // the change actor column
      const action = e.columns.find((x) => x.spec >> 4 === ACTION && (x.spec & 7) === 2);
      expect(action?.rows).toBe(ops);
      deflated += e.columns.filter((x) => x.spec & 0x08).length;
    }
    expect(deflated).toBeGreaterThan(0);
  });
});

describe("changes: the exact limits (§11.1)", () => {
  it("accepts exactly the op limit and refuses one more", () => {
    expect(checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows)).maxRows).toBe(
      CHANGE_LIMITS.maxRows,
    );
    refused(() => checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows + 1)));
  });

  it("refuses the measured RLE bomb (1,000,000 ops in about 112 bytes) at once", () => {
    const bomb = nullSets(1_000_000);
    expect(bomb.length).toBeLessThan(200);
    const t = performance.now();
    refused(() => checkChangeExpansion(bomb));
    expect(performance.now() - t).toBeLessThan(50);
  });

  it("bounds predecessors per operation and in total", () => {
    const actor = (j: number) => j.toString(16).padStart(2, "0").repeat(32);
    const preds = (n: number) =>
      Array.from({ length: n }, (_, j) => `1@${j === 0 ? ACTOR : actor(j + 0x10)}`);
    // Per operation: at most one plus the number of other actors.
    expect(checkChangeExpansion(nullSets(1, "k", preds(2))).groupSum).toBe(2);
    refused(() => checkChangeExpansion(nullSets(1, "k", [`1@${ACTOR}`, `2@${ACTOR}`])));
    refused(() =>
      checkChangeExpansion(
        nullSets(
          1,
          "k",
          Array.from({ length: 16_385 }, (_, i) => `${i + 1}@${ACTOR}`),
        ),
      ),
    );
    // In total: 16,384 operations of 16 predecessors is the limit; of 17, past it.
    expect(checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows, "k", preds(16))).groupSum).toBe(
      CHANGE_LIMITS.maxGroupSum,
    );
    refused(() => checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows, "k", preds(17))));
  });

  it("refuses a repeated-string bomb", () => {
    // 16,384 rows of a 300-byte key: 4.9 MB of strings > 4 MiB.
    refused(() => checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows, "x".repeat(300))));
    expect(checkChangeExpansion(nullSets(CHANGE_LIMITS.maxRows, "x".repeat(256))).stringBytes).toBe(
      CHANGE_LIMITS.maxRows * 256,
    );
  });

  it("refuses duplicate columns and out-of-range actor indices", () => {
    const change = nullSets(3);
    const e = checkChangeExpansion(change);
    expect(e.columns.length).toBeGreaterThan(1);
    // The column metadata and data, rebuilt with the first column listed twice.
    const rebuilt = rebuildColumns(change, (cols) => [cols[0] as Column, ...cols]);
    refused(() => checkChangeExpansion(rebuilt));
    // Any number of distinct columns is fine (§11.1 has no column limit): 70 more unknown raw ones.
    const wide = rebuildColumns(change, (cols) => [
      ...cols,
      ...Array.from({ length: 70 }, (_, i): Column => [((20 + i) << 4) | 7, new Uint8Array(0)]),
    ]);
    expect(checkChangeExpansion(wide).columns).toHaveLength(cols(change) + 70);
    // An actor column naming index 1 in a change with no other actors.
    const nested = A.getLastLocalChange(
      A.change(
        A.change(A.init({ actor: ACTOR }), (d: Record<string, unknown>) => {
          d.m = {};
        }),
        (d: Record<string, unknown>) => {
          (d.m as Record<string, unknown>).x = 1;
        },
      ),
    ) as Uint8Array;
    expect(checkChangeExpansion(nested).columns.some((c) => c.spec === 1)).toBe(true);
    refused(() =>
      checkChangeExpansion(
        rebuildColumns(nested, (cols) =>
          cols.map(([spec, data]) => (spec === 1 ? [spec, Uint8Array.from([1, 1])] : [spec, data])),
        ),
      ),
    );
  });

  it("refuses a compressed change, a document chunk, and anything after the chunk", () => {
    const change = nullSets(3);
    const compressed = Uint8Array.from(change);
    compressed[8] = 2;
    refused(() => checkChangeExpansion(compressed));
    refused(() => checkChangeExpansion(A.save(A.init())));
    refused(() => checkChangeExpansion(Uint8Array.from([...change, 0])));
    refused(() => checkChangeExpansion(Uint8Array.from([...change, ...change])));
  });
});

describe("Snapshots: local limits at least the floor (§13.1)", () => {
  /** A document chunk with one deflated op column of `zeros` zero bytes. */
  function deflatedDocument(zeros: number): Uint8Array {
    const data = deflateSync(new Uint8Array(zeros), { level: 9 });
    const leb = (n: number) => {
      const out: number[] = [];
      do {
        let b = n & 0x7f;
        n = Math.floor(n / 128);
        if (n > 0) b |= 0x80;
        out.push(b);
      } while (n > 0);
      return out;
    };
    // actors 0, heads 0, change columns 0, op columns 1: (raw type 7, deflated)
    const body = [0, 0, 0, 1, ...leb((ACTION << 4) | 0x08 | 7), ...leb(data.length), ...data];
    return Uint8Array.from([0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 0, ...leb(body.length), ...body]);
  }

  it("refuses a deflate bomb as soon as inflation passes the cap, (memory: conformance/shared-objects/automerge-corpus.test.ts)", () => {
    const bomb = deflatedDocument(256 * 1024 * 1024);
    expect(bomb.length).toBeLessThan(300 * 1024);
    const t = performance.now();
    refused(() => checkSnapshotExpansion(bomb));
    expect(performance.now() - t).toBeLessThan(2_000);
  });

  it("accepts inflated data up to the cap and applies a higher local cap", () => {
    const ok = deflatedDocument(SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes);
    expect(checkSnapshotExpansion(ok).columnBytes).toBe(SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes);
    const more = deflatedDocument(SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes + 1);
    refused(() => checkSnapshotExpansion(more));
    expect(
      checkSnapshotExpansion(more, {
        ...SNAPSHOT_LIMITS_FLOOR,
        maxInflatedBytes: SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes + 1,
      }).columnBytes,
    ).toBe(SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes + 1);
  });

  it("refuses a change chunk, trailing chunks and anything after the save", () => {
    const save = A.save(
      A.change(A.init({ actor: ACTOR }), (d: Record<string, unknown>) => {
        d.a = 1;
      }),
    );
    expect(checkSnapshotExpansion(save).columnBytes).toBeGreaterThan(0);
    refused(() => checkSnapshotExpansion(nullSets(2)));
    refused(() => checkSnapshotExpansion(Uint8Array.from([...save, ...nullSets(2)])));
    refused(() => checkSnapshotExpansion(Uint8Array.from([...save, 0])));
  });
});

describe("fuzz: mutated chunks", () => {
  it("only ever return or throw the typed refusal, quickly", () => {
    const r = rng(71);
    const docs = documents(6);
    const inputs: { bytes: Uint8Array; snapshot: boolean }[] = [
      ...docs.flatMap((d) =>
        A.getAllChanges(d)
          .slice(0, 15)
          .map((bytes) => ({ bytes, snapshot: false })),
      ),
      ...docs.map((d) => ({ bytes: A.save(d), snapshot: true })),
      { bytes: nullSets(500), snapshot: false },
    ];
    let accepted = 0;
    let refusedCount = 0;
    for (let i = 0; i < 6_000; i++) {
      const src = inputs[Math.floor(r() * inputs.length)] as {
        bytes: Uint8Array;
        snapshot: boolean;
      };
      const b = Uint8Array.from(src.bytes);
      const kind = r();
      let mutated: Uint8Array = b;
      if (kind < 0.6)
        for (let k = 0; k < 1 + Math.floor(r() * 4); k++)
          b[Math.floor(r() * b.length)] = Math.floor(r() * 256);
      else if (kind < 0.8) mutated = b.subarray(0, Math.floor(r() * b.length));
      else {
        const at = Math.floor(r() * b.length);
        mutated = Uint8Array.from([...b.subarray(0, at), Math.floor(r() * 256), ...b.subarray(at)]);
      }
      const t = performance.now();
      try {
        if (src.snapshot) checkSnapshotExpansion(mutated);
        else checkChangeExpansion(mutated);
        accepted++;
      } catch (e) {
        if (!(e instanceof ProfileInvalidError)) throw e;
        refusedCount++;
      }
      expect(performance.now() - t).toBeLessThan(250);
    }
    expect(accepted).toBeGreaterThan(0);
    expect(refusedCount).toBeGreaterThan(0);
  });
});
