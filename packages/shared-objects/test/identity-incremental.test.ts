import * as A from "@automerge/automerge";
import { describe, expect, it, vi } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import { IdentityReplica, type IdentityUnit } from "../src/identity/index.js";
import {
  actor,
  type Doc,
  initial,
  options,
  resourceRef,
  rootWriter,
  S,
  unit,
} from "./support/identity.js";

// Count history work instead of relying on wall-clock limits on slow CI machines.
// The injected abort happens AFTER the engine mutates its document, as in D1.
const engine = vi.hoisted(() => ({ scans: 0, clones: 0, decodes: 0, applies: 0, abort: false }));
vi.mock("@automerge/automerge", async () => {
  const actual = await vi.importActual<typeof A>("@automerge/automerge");
  return {
    ...actual,
    getAllChanges: (...args: Parameters<typeof A.getAllChanges>) => {
      engine.scans++;
      return actual.getAllChanges(...args);
    },
    clone: (...args: Parameters<typeof A.clone>) => {
      engine.clones++;
      return actual.clone(...args);
    },
    decodeChange: (...args: Parameters<typeof A.decodeChange>) => {
      engine.decodes++;
      return actual.decodeChange(...args);
    },
    applyChanges: (...args: Parameters<typeof A.applyChanges>) => {
      engine.applies++;
      const next = actual.applyChanges(...args);
      if (engine.abort) {
        engine.abort = false;
        throw new RangeError("injected engine abort after mutation");
      }
      return next;
    },
  };
});
const reset = () =>
  Object.assign(engine, { scans: 0, clones: 0, decodes: 0, applies: 0, abort: false });

function history(count: number): IdentityUnit[] {
  let doc = initial();
  const units = [unit(doc)];
  for (let i = 1; i < count; i++) {
    doc = A.change(doc, { time: 0 }, (d) => {
      if (i === 1)
        d.roster[resourceRef] = { profile: S("org.example"), endpoints: [], coordinator: S("") };
      d.roster[resourceRef].name = S(String(i));
    });
    units.push(unit(doc, { ...rootWriter, actorSeq: i + 1 }));
  }
  A.free(doc);
  return units;
}

describe("incremental identity admission (P2)", () => {
  it("2000 changes: replay clones once, idle receives do no history work, write checks only its candidate", () => {
    const units = history(2000);
    reset();
    const { replica, result } = IdentityReplica.fromChanges(units, options);
    expect(result.admitted).toHaveLength(units.length);
    expect(result.refused).toEqual([]);
    expect(engine.scans).toBe(1);
    expect(engine.clones).toBe(1);
    reset();
    for (let i = 0; i < 10; i++)
      expect(replica.receiveChanges([])).toEqual({
        admitted: [],
        duplicates: [],
        waiting: [],
        refused: [],
      });
    expect(engine).toEqual({ scans: 0, clones: 0, decodes: 0, applies: 0, abort: false });
    const change = replica.write(
      { ...rootWriter, actorSeq: 2001 },
      {
        intent: "roster.put",
        key: resourceRef,
        entry: { profile: "org.example", endpoints: [], coordinator: "", name: "next" },
      },
    );
    expect(engine.scans).toBe(0);
    expect(engine.clones).toBe(1);
    expect(engine.decodes).toBe(2);
    expect(engine.applies).toBe(1);
    expect(change.seq).toBe(2001);
    expect(replica.roster()[resourceRef]?.name).toBe("next");
    // The internal rollback log cannot be changed through the writer's receipt.
    change.bytes.fill(0);
    expect(replica.rebuildWithout([]).replica.roster()[resourceRef]?.name).toBe("next");
  }, 60_000);

  it("retains checked waiting bytes without reparsing them on retries", () => {
    const units = history(3);
    const last = units[2] as IdentityUnit;
    const hash = checkChange(last.bytes).hash;
    const { replica, result } = IdentityReplica.fromChanges([last], options);
    expect(result.waiting).toEqual([hash]);
    last.bytes.fill(0);
    reset();
    expect(replica.receiveChanges([]).waiting).toEqual([hash]);
    expect(engine).toEqual({ scans: 0, clones: 0, decodes: 0, applies: 0, abort: false });
    expect(replica.receiveChanges(units.slice(0, 2)).admitted).toHaveLength(3);
    expect(replica.roster()[resourceRef]?.name).toBe("2");
  });

  it("an engine abort restores state and indexes; a new candidate can reuse the refused sequence", () => {
    const { replica } = IdentityReplica.fromChanges(history(3), options);
    const before = replica.heads();
    const base = A.load<Doc>(replica.save(), { actor: actor(rootWriter) });
    const failedDoc = A.change(A.clone(base, { actor: actor(rootWriter) }), { time: 0 }, (d) => {
      d.future = { bad: true };
    });
    const failed = {
      ...rootWriter,
      bytes: A.getLastLocalChange(failedDoc) as Uint8Array,
      actorSeq: 4,
    };
    engine.abort = true;
    expect(replica.receiveChanges([failed]).refused).toMatchObject([
      { diagnostic: "INVALID_AUTOMERGE_BYTES", held: false },
    ]);
    expect(replica.heads()).toEqual(before);
    expect(replica.hasChange(checkChange(failed.bytes).hash)).toBe(false);
    engine.abort = true;
    expect(() =>
      replica.write(
        { ...rootWriter, actorSeq: 4 },
        {
          intent: "roster.put",
          key: resourceRef,
          entry: {
            profile: "org.example",
            endpoints: [],
            coordinator: "",
            name: "failed local write",
          },
        },
      ),
    ).toThrow(expect.objectContaining({ diagnostic: "INVALID_AUTOMERGE_BYTES" }));
    expect(replica.heads()).toEqual(before);
    expect(replica.receiveChanges([])).toEqual({
      admitted: [],
      duplicates: [],
      waiting: [],
      refused: [],
    });
    const accepted = replica.write(
      { ...rootWriter, actorSeq: 4 },
      {
        intent: "roster.put",
        key: resourceRef,
        entry: { profile: "org.example", endpoints: [], coordinator: "", name: "after abort" },
      },
    );
    expect(accepted.seq).toBe(4);
    expect(replica.roster()[resourceRef]?.name).toBe("after abort");
    expect(replica.rebuildWithout([]).replica.heads()).toEqual(replica.heads());
    A.free(base);
    A.free(failedDoc);
  });
});
