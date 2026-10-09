import * as A from "@automerge/automerge";
import { fromHex, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/automerge-bytes.js";
import { checkCanonicalChange, type ParsedChange } from "../src/canonical.js";
import { ReferenceHistory } from "../src/references.js";
import { SharedObjectsReplica } from "../src/replica.js";
import { ACTOR, type Doc, documents, OTHER } from "./support/automerge-docs.js";

// SHARED-OBJECTS-PROFILE-01 §11.4 (SPEC-PATCH-10, ADR 0010): the operation
// reference rules R1-R7 against a change's causal history, on Automerge's
// own changes (no false refusal) and on crafted ones. The spec's corpus
// (references, SS57, SS58) runs in conformance/.

/** A history holding every change of a document. */
function historyOf(doc: Doc): ReferenceHistory {
  const h = new ReferenceHistory();
  for (const bytes of A.getAllChanges(doc))
    h.add(A.decodeChange(bytes).hash, checkCanonicalChange(bytes));
  return h;
}

/** A change edited at the decoded level, then encoded canonically. */
function edited(bytes: Uint8Array, fn: (d: A.DecodedChange) => void): ParsedChange {
  const d = A.decodeChange(bytes);
  fn(d);
  return checkCanonicalChange(A.encodeChange(d));
}

/** The change one more edit of `doc` makes (on a copy: `doc` stays usable). */
const next = (doc: Doc, fn: (d: Record<string, unknown>) => void): Uint8Array =>
  A.getLastLocalChange(A.change(A.clone(doc), fn)) as Uint8Array;

function base(): Doc {
  return A.change(A.init({ actor: ACTOR }), (d: Record<string, unknown>) => {
    d.title = "a";
    d.other = "b";
    d.list = ["x", "y"];
    d.map = {};
  });
}

describe("§11.4 operation references", () => {
  it("every change of a document refers only to its history (no false refusal)", () => {
    for (const doc of documents(6)) {
      const h = new ReferenceHistory();
      // getAllChanges is in causal order.
      for (const bytes of A.getAllChanges(doc)) {
        const parsed = checkCanonicalChange(bytes);
        expect(h.check(parsed)).toBeNull();
        h.add(A.decodeChange(bytes).hash, parsed);
      }
    }
  });

  it("R2, R6, R7: a wrong start op, a predecessor on another key, a deletion without one", () => {
    const a = base();
    const h = historyOf(a);
    const put = next(a, (d) => {
      d.title = "c";
    });
    expect(h.check(checkCanonicalChange(put))).toBeNull();
    expect(
      h.check(
        edited(put, (d) => {
          d.startOp += 1;
        }),
      ),
    ).toBe("R2");
    const otherKey = A.decodeChange(A.getAllChanges(a)[0] as Uint8Array).ops.findIndex(
      (o) => (o as { key?: string }).key === "other",
    );
    expect(
      h.check(
        edited(put, (d) => {
          (d.ops[0] as { pred: string[] }).pred = [`${1 + otherKey}@${ACTOR}`];
        }),
      ),
    ).toBe("R6");
    const del = next(a, (d) => {
      delete d.title;
    });
    expect(h.check(checkCanonicalChange(del))).toBeNull();
    expect(
      h.check(
        edited(del, (d) => {
          (d.ops[0] as { pred: string[] }).pred = [];
        }),
      ),
    ).toBe("R7");
  });

  it("R3, R4, R5: an object that is none, an insertion into a map, a put on the head", () => {
    const a = base();
    const h = historyOf(a);
    const put = next(a, (d) => {
      (d.map as Record<string, unknown>).k = 1;
    });
    expect(h.check(checkCanonicalChange(put))).toBeNull();
    // The title's operation made no object.
    expect(
      h.check(
        edited(put, (d) => {
          (d.ops[0] as { obj: string }).obj = `1@${ACTOR}`;
        }),
      ),
    ).toBe("R3");
    const insertIntoMap = edited(put, (d) => {
      const op = d.ops[0] as { insert?: boolean; key?: string; elemId?: string };
      op.insert = true;
      delete op.key;
      op.elemId = "_head";
    });
    expect(h.check(insertIntoMap)).toBe("R4");
    const listPut = next(a, (d) => {
      (d.list as string[])[0] = "z";
    });
    expect(h.check(checkCanonicalChange(listPut))).toBeNull();
    expect(
      h.check(
        edited(listPut, (d) => {
          const op = d.ops[0] as { elemId?: string; pred: string[] };
          op.elemId = "_head";
          op.pred = [];
        }),
      ),
    ).toBe("R5");
  });

  it("R1 and a concurrent predecessor: decided against the history, not the receiver's document", () => {
    const a = base();
    const concurrent = next(A.clone(a, { actor: OTHER }), (d) => {
      d.title = "b";
    });
    const mine = next(a, (d) => {
      d.title = "a2";
    });
    const h = historyOf(a);
    h.add(A.decodeChange(concurrent).hash, checkCanonicalChange(concurrent));
    // The receiver holds the other actor's change, but it is not in the history of `mine`.
    const theirs = `${A.decodeChange(concurrent).startOp}@${OTHER}`;
    expect(
      h.check(
        edited(mine, (d) => {
          (d.ops[0] as { pred: string[] }).pred = [theirs];
        }),
      ),
    ).toBe("R6");
    expect(
      h.check(
        edited(mine, (d) => {
          d.seq += 1;
        }),
      ),
    ).toBe("R1");
  });

  it("a replica refuses such a change before the engine, and still saves and loads", () => {
    const R = resourceId(fromHex("11".repeat(32)));
    const opts = { resource: R, principal: principalId(new Uint8Array(32).fill(0xf1)) };
    const a = base();
    const replica = SharedObjectsReplica.empty(opts);
    replica.receiveChanges(A.getAllChanges(a).map((c) => checkChange(c)));
    const heads = replica.heads().join();
    const d = A.decodeChange(
      next(a, (x) => {
        delete x.title;
      }),
    );
    (d.ops[0] as { pred: string[] }).pred = [];
    const bad = checkChange(A.encodeChange(d));
    const out = replica.receiveChanges([bad]);
    expect(out.applied).toEqual([]);
    expect(out.refused[0]?.error.message).toMatch(/§11\.4 R7/);
    expect(replica.heads().join()).toBe(heads);
    expect(SharedObjectsReplica.fromSave(replica.save(), opts).heads().join()).toBe(heads);
    expect(() => replica.receiveChange(bad.bytes)).toThrow(/§11\.4 R7/);
  });
});
