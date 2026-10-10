// A change the Automerge engine aborts on (LFCP-02-117, differential
// fuzzing D1): a change that makes a table (action 6) and writes into it.
// Automerge JS 3.5.0 cannot write a table back out and panics applying one
// ("Obj … Missing from Index"), not as a wasm trap. Before the fix this
// left the change as the document's head: heads() returned its hash, the
// replica could not take the actor's next change ("duplicate seq"), and a
// reload failed ("could not be restored").
//
// Two layers:
//   (1) the engine apply is rolled back — on any engine error the document
//       is rebuilt from the changes it held BEFORE the apply, so a change it
//       aborts on never becomes the document's state (applyChecked,
//       applyBatchChecked);
//   (2) admission refuses the change before the engine (SHARED-OBJECTS-PROFILE-01
//       §11.4 R10: no operation makes a table, action 6).
//
// The change below is the D1 Data Unit's change; it is a well-formed,
// canonical change, so checkChange accepts it and it reaches the engine when
// R10 is not applied.

import * as A from "@automerge/automerge";
import { principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  applyBatchChecked,
  applyChecked,
  checkChange,
  SharedObjectsReplica,
} from "../src/index.js";

const D1 =
  "856f4a831c852d2201c8020020aea259a20d3594e3f94429f322a05704e773952af34e817fbe4092" +
  "7b8fe290ab0101000f67656e657369732d70726f66696c65000801060206155d3401420a560f577c" +
  "7002000205000004000205020004750770726f66696c650773656374696f6e086368696c6472656e" +
  "0a637265617465645f62790a657874656e73696f6e73026964057469746c65076f626a6563747305" +
  "6e6f6465730a706c6163656d656e74730a657874656e73696f6e730b7b01060201000201040" +
  "07ff60302007cd60500c604c60104006f72672e6f70656e6c6663702e7368617265642d7365637469" +
  "6f6e732e7631703a4f754d3550425551417068766842555672536d634736475836636541444d786e" +
  "44474658514543784f775532363861313636662d343839312d373234332d383430652d6537666561" +
  "3966653633393" +
  "04a6f696e74206c61756e63680b00";
const d1 = Uint8Array.from(D1.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
const heads = (doc: A.Doc<unknown>) => [...A.getHeads(doc)].sort().join(",");

describe("engine rollback and admission for the D1 makeTable change", () => {
  it("is a well-formed change the byte checks accept (refused only by R10)", () => {
    expect(() => checkChange(d1)).not.toThrow();
  });

  it("the engine aborts applying it", () => {
    // Guards the fixture: if a newer engine no longer panics, this test
    // (and the backstop it covers) must be revisited.
    expect(() => A.applyChanges(A.clone(A.init()), [d1])).toThrow();
  });

  describe("layer 1: the engine apply does not corrupt the document", () => {
    it("applyChecked keeps the document's heads and reports the error", () => {
      const doc = A.init();
      const before = heads(doc);
      const r = applyChecked(doc, d1);
      expect("restored" in r).toBe(true);
      if ("restored" in r) {
        expect(heads(r.restored)).toBe(before);
        expect(r.error).toBeInstanceOf(Error);
      }
    });

    it("leaves the original document usable after the aborted apply", () => {
      const doc = A.init();
      applyChecked(doc, d1);
      const next = A.change(doc, (d: Record<string, unknown>) => {
        d.ok = 1;
      });
      expect((next as Record<string, unknown>).ok).toBe(1);
    });

    it("applyBatchChecked keeps the document's heads and reports the error", () => {
      const doc = A.init();
      const before = heads(doc);
      const r = applyBatchChecked(doc, [checkChange(d1)]);
      expect("restored" in r).toBe(true);
      if ("restored" in r) {
        expect(heads(r.restored)).toBe(before);
        expect(r.error).toBeInstanceOf(Error);
      }
    });
  });

  describe("layer 2: the replica refuses it (R10) and is never poisoned", () => {
    it("SharedObjectsReplica refuses it, keeps its heads, and reloads without it", () => {
      const opts = () => ({
        resource: resourceId(new Uint8Array(32).fill(9)),
        principal: principalId(new Uint8Array(32).fill(1)),
      });
      const r = SharedObjectsReplica.empty(opts());
      const before = r.heads().join();
      expect(() => r.receiveChange(d1)).toThrow(
        expect.objectContaining({ diagnostic: "INVALID_AUTOMERGE_BYTES" }),
      );
      expect(r.heads().join()).toBe(before);
      // The change's actor sequence 1 was not taken: receiving it again is one
      // refusal, nothing applied — not the "duplicate seq" of the poisoned replica.
      const batch = r.receiveChanges([checkChange(d1)]);
      expect(batch.applied).toHaveLength(0);
      expect(batch.refused).toHaveLength(1);
      expect(r.heads().join()).toBe(before);
      // Persistence holds no bad change: the replica reloads at the same heads.
      expect(SharedObjectsReplica.fromSave(r.save(), opts()).heads().join()).toBe(before);
    });
  });
});
