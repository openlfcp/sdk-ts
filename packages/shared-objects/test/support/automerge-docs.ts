// Automerge documents for the admission tests (test data only): two actors
// editing maps, lists, text with marks, counters and every value type,
// concurrently.

import * as A from "@automerge/automerge";

export type Doc = A.Doc<Record<string, unknown>>;
export const ACTOR = "aa".repeat(32);
export const OTHER = "bb".repeat(32);

/** A deterministic pseudo-random generator. */
export function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

/**
 * `count` merged documents, each from a different seed. Without `marks`,
 * the mark edits are skipped (the seeds draw the same edits otherwise):
 * SHARED-OBJECTS-PROFILE-01 §11.4 R9 refuses marks, which a writer of the
 * profile never makes.
 */
export function documents(count: number, options: { readonly marks?: boolean } = {}): Doc[] {
  const marks = options.marks ?? true;
  const out: Doc[] = [];
  for (let n = 0; n < count; n++) {
    const r = rng(n + 7);
    let a: Doc = A.init({ actor: ACTOR });
    a = A.change(a, (d) => {
      d.objects = {};
      d.list = [];
      d.text = "hello world";
      d.count = new A.Counter(0);
    });
    let b: Doc = A.clone(a, { actor: OTHER });
    for (let i = 0; i < 15 + Math.floor(r() * 40); i++) {
      const edit = (d: Record<string, unknown>) => {
        const k = `k${Math.floor(r() * 12)}`;
        const op = r();
        const objects = d.objects as Record<string, unknown>;
        if (op < 0.2)
          objects[k] = { title: "é".repeat(Math.floor(r() * 9)), n: i, deep: { x: [i] } };
        else if (op < 0.3) (d.list as unknown[]).push(i, `s${i}`, -(i + 1) * 1e6, 1.5, true, null);
        else if (op < 0.4 && (d.list as unknown[]).length > 0) (d.list as unknown[]).splice(0, 1);
        else if (op < 0.45 && (d.list as unknown[]).length > 1)
          (d.list as unknown[])[1] = `set${i}`;
        else if (op < 0.55) (d.count as A.Counter).increment(i - 5);
        else if (op < 0.65) A.splice(d as never, ["text"], 0, 0, `t${i}`);
        else if (op < 0.7) {
          if (marks)
            A.mark(d as never, ["text"], { start: 0, end: 2, expand: "both" }, "bold", true);
        } else if (op < 0.75) d[k] = new Uint8Array([i, 0, 255]);
        else if (op < 0.8) d[k] = new Date(1_700_000_000_000 + i);
        else if (op < 0.85) d[k] = new A.Uint(2 ** 40 + i);
        else if (k in objects) delete objects[k];
        else d[k] = r() < 0.5 ? null : i;
      };
      if (r() < 0.5) a = A.change(a, edit);
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
