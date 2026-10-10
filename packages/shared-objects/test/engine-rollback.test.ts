// A change the Automerge engine aborts on (LFCP-02-117, differential
// fuzzing D1): a change that makes a table (action 6) and writes into it.
// Automerge JS 3.5.0 cannot write a table back out and panics applying one
// ("Obj … Missing from Index"), not as a wasm trap. Before the fix this
// left the change as the document's head: revision() returned its hash, the
// replica could not take the actor's next change ("duplicate seq"), and a
// reload failed ("could not be restored").
//
// Two layers:
//   (1) the engine apply runs on a clone, so a change it aborts on corrupts
//       the clone, never the document (applyChecked, applyBatchChecked);
//   (2) admission refuses the change before the engine (SHARED-OBJECTS-PROFILE-01
//       §11.4 R10). The published vectors REF-R10-* and SS64 cover R10 in
//       the corpus run; this pins the actual engine-panic reproducer.
//
// The change below is the D1 Data Unit's change, the section exploit c2
// reported; it is a well-formed, canonical change, so checkChange accepts
// it and it reaches the engine when R10 is not applied.

import * as A from "@automerge/automerge";
import { principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  applyBatchChecked,
  applyChecked,
  checkChange,
  createTask,
  SharedObjectsReplica,
} from "../src/index.js";
import {
  SECTIONS_PROFILE_ID,
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "../src/sections/index.js";

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

  describe("layer 2: both replicas refuse it (R10) and are never poisoned", () => {
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

    it("SectionReplica refuses it, keeps its revision, reloads, and keeps editing", () => {
      const resource = resourceId(new Uint8Array(32).fill(7));
      const principal = principalId(new Uint8Array(32).fill(1));
      const uid = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
      const r = SectionReplica.empty({ resource, principal });
      const setup: SectionIntent[] = [
        { intent: "section.create", sectionId: uid(1), title: "S", createdBy: principal },
        {
          intent: "task.create_in_section",
          task: createTask({ id: uid(2) as never, title: "T", createdBy: principal }).task,
          parent: uid(1),
          after: null,
        },
      ];
      for (const i of setup) r.commit([i]);
      const before = r.revision();

      const out = r.receiveChanges([d1]);
      expect(out.admitted).toEqual([]);
      expect(out.refused).toMatchObject([{ diagnostic: "INVALID_AUTOMERGE_BYTES" }]);
      expect(r.revision()).toBe(before);

      // Restart: the saved document reloads and holds no bad change.
      const reloaded = SharedSectionsDataProfile.restore(
        {
          resourceId: resource,
          dataProfile: SECTIONS_PROFILE_ID,
          state: r.save(),
          actorSeq: 0,
          units: [],
        },
        { resource, principal },
      ).replica;
      expect(reloaded.revision()).toBe(before);

      // The replica still accepts an honest edit.
      expect(r.commit([{ intent: "section.set_title", title: "S2" }])).not.toBeNull();
      expect(r.snapshot().title.value).toBe("S2");
    });
  });
});
