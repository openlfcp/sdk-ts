import * as A from "@automerge/automerge";
import { dataEpoch, principalId, resourceId, UINT64_MAX } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange, decodedOf, frameChange } from "../src/admission/framing.js";
import { SharedObjectsReplica } from "../src/replica.js";
import { SectionReplica } from "../src/sections/replica.js";

const options = {
  resource: resourceId(new Uint8Array(32).fill(7)),
  principal: principalId(new Uint8Array(32).fill(1)),
};
const sectionId = "0192e4a0-0000-7000-8000-000000000001";
const nodeId = "0192e4a0-0000-7000-8000-000000000002";

function largeChange(save: Uint8Array) {
  const doc = A.load<Record<string, unknown>>(save, { actor: "aa" });
  const large = A.change(doc, { time: 0 }, (d) => {
    d.future = {};
    A.getBackend(d).put(A.getObjectId(d.future) as string, "epoch", dataEpoch(UINT64_MAX), "uint");
  });
  const change = checkChange(A.getLastLocalChange(large) as Uint8Array);
  const next = A.change(large, { time: 0 }, (d) => {
    d.continuation = true;
  });
  const continuation = checkChange(A.getLastLocalChange(next) as Uint8Array);
  A.free(next);
  return { change, continuation };
}

describe("uint64 through the existing profiles (PR #9 F1/F2)", () => {
  it("shared sections receive, derive the tree, reload, continue and rebuild", () => {
    const replica = SectionReplica.empty(options);
    replica.commit([
      { intent: "section.create", sectionId, title: "Section", createdBy: options.principal },
      {
        intent: "paragraph.create",
        id: nodeId,
        parent: sectionId,
        after: null,
        text: "Text",
        createdBy: options.principal,
      },
    ]);
    const before = replica.snapshot();
    const { change, continuation } = largeChange(replica.save());
    expect(replica.receiveChanges([change.bytes]).admitted).toEqual([change.hash]);
    expect(replica.snapshot().order).toEqual(before.order);
    expect(replica.rebuildWithout([]).replica.revision()).toBe(replica.revision());

    const restored = SectionReplica.fromSave(replica.save(), options);
    expect(restored.receiveChanges([continuation.bytes]).admitted).toEqual([continuation.hash]);
    expect(restored.receiveChanges([change.bytes]).duplicates).toEqual([change.hash]);
    expect(restored.snapshot().order).toEqual(before.order);
    const rebuilt = restored.rebuildWithout([change.hash]);
    expect(rebuilt.unapplied).toEqual([continuation.hash]);
    expect(rebuilt.replica.snapshot().order).toEqual(before.order);
    expect(restored.commit([{ intent: "section.set_title", title: "Continued" }])).not.toBeNull();
    const revision = restored.revision();
    const staged = restored.stage([{ intent: "section.set_title", title: "Temporary" }]);
    expect(staged).not.toBeNull();
    staged?.apply();
    staged?.revert();
    expect(restored.revision()).toBe(revision);
    expect(restored.snapshot().title.value).toBe("Continued");
  });

  it("shared objects accept legal extension values through both receive APIs without RangeError", () => {
    const { replica } = SharedObjectsReplica.create(options);
    const saved = replica.save();
    const { change, continuation } = largeChange(saved);
    expect(replica.receive(frameChange(change.bytes)).status).toBe("applied");
    const batch = SharedObjectsReplica.fromSave(saved, options);
    // A structural CheckedChange copy has no WeakMap decode cache.
    expect(decodedOf({ ...change })).toEqual(decodedOf(change));
    expect(batch.receiveChanges([{ ...change }]).applied.map((c) => c.hash)).toEqual([change.hash]);
    expect(batch.heads()).toEqual(replica.heads());
    expect(batch.rebuildWithout([]).replica.heads()).toEqual(replica.heads());

    const restored = SharedObjectsReplica.fromSave(replica.save(), options);
    expect(restored.receive(frameChange(continuation.bytes)).status).toBe("applied");
    expect(restored.receiveChanges([change]).duplicates).toEqual([change]);
    expect(restored.validate().valid).toBe(true);
    const rebuilt = restored.rebuildWithout([change.hash]);
    expect(rebuilt.unapplied.map((c) => c.hash)).toEqual([continuation.hash]);
    expect(rebuilt.replica.heads()).toEqual(SharedObjectsReplica.fromSave(saved, options).heads());
    const corrupt = change.bytes.slice();
    corrupt[4] = (corrupt[4] as number) ^ 1;
    expect(() => restored.receiveChange(corrupt)).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" }),
    );
  });
});
