// SOP §45 (mvp-0.2-baseline.12): concurrent equal values of a scalar
// register agree. Equal means the same Automerge scalar type and value; a
// map, a list or Text equals no other value.

import * as A from "@automerge/automerge";
import { describe, expect, it } from "vitest";
import { distinctValues, isConflicted } from "../src/concurrent.js";

type Doc = { o: Record<string, unknown> };

/** Two concurrent writes of `key` (each by `write`), merged. */
function both(write: (o: Record<string, unknown>, side: 0 | 1) => void): A.Doc<Doc> {
  const base = A.from<Doc>({ o: {} });
  const x = A.change(A.clone(base, { actor: "aa" }), (d) => write(d.o, 0));
  const y = A.change(A.clone(base, { actor: "bb" }), (d) => write(d.o, 1));
  return A.merge(x, y);
}

describe("distinctValues", () => {
  it("equal scalar strings, numbers and booleans agree", () => {
    const d = both((o) => {
      o.s = new A.ImmutableString("done");
      o.n = 3;
      o.b = true;
    });
    for (const k of ["s", "n", "b"]) {
      expect(distinctValues(d, d.o, k)).toHaveLength(1);
      expect(isConflicted(d, d.o, k)).toBe(false);
    }
  });

  it("different values, or the same value of another type, conflict", () => {
    const d = both((o, side) => {
      o.s = new A.ImmutableString(side === 0 ? "done" : "cancelled");
      o.t = side === 0 ? 3 : new A.ImmutableString("3");
    });
    expect(distinctValues(d, d.o, "s")).toHaveLength(2);
    expect(isConflicted(d, d.o, "t")).toBe(true);
  });

  it("a map, a list or Text equals no other value, even an identical one", () => {
    const d = both((o) => {
      o.m = { a: 1 };
      o.l = [1];
      o.x = "text";
    });
    for (const k of ["m", "l", "x"]) expect(distinctValues(d, d.o, k)).toHaveLength(2);
  });

  it("no value, or one, is no conflict", () => {
    const d = A.from<Doc>({ o: { s: new A.ImmutableString("a") } });
    expect(distinctValues(d, d.o, "missing")).toEqual([]);
    expect(distinctValues(d, d.o, "s")).toHaveLength(1);
  });
});
