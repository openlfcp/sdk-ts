// A.§3.5 (E-030): when the engine refuses a batch admission accepted on the shadow model, the
// replica admits the history before it again and judges the batch on the engine path, so its
// decisions are the engine's: here an engine that refuses one change, whatever else holds.

import * as A from "@automerge/automerge";
import { describe, expect, it, vi } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import { ServiceControlReplica } from "../src/service-control/index.js";
import { ShadowDoc, ShadowUnsupported } from "../src/service-control/shadow.js";
import { syntheticYear } from "./support/service-control-year.js";

const engine = vi.hoisted(() => ({ refuse: undefined as string | undefined }));

vi.mock("@automerge/automerge", async (actual) => {
  const real = await actual<typeof import("@automerge/automerge")>();
  return {
    ...real,
    applyChanges: (...args: Parameters<typeof real.applyChanges>) => {
      if (args[1].some((c) => real.decodeChange(c).hash === engine.refuse))
        throw new Error("the engine refuses this change");
      return real.applyChanges(...args);
    },
  };
});

describe("a batch the engine refuses", () => {
  it("is judged again on the engine path: the change it refuses is refused, its dependants wait", () => {
    const year = syntheticYear({ days: 2, seed: 4 });
    const split = Math.floor(year.units.length / 2);
    const replica = ServiceControlReplica.fromChanges(
      year.units.slice(0, split),
      year.options,
    ).replica;
    const batch = year.units.slice(split);
    const target = checkChange((batch[3] as { bytes: Uint8Array }).bytes);
    engine.refuse = target.hash;
    try {
      const result = replica.receiveChanges(batch);
      expect(result.refused).toEqual([
        expect.objectContaining({ hash: target.hash, diagnostic: "INVALID_AUTOMERGE_BYTES" }),
      ]);
      expect(result.admitted).not.toContain(target.hash);
      expect(result.admitted.length + result.waiting.length + 1).toBe(batch.length);
      expect(result.waiting.length).toBeGreaterThan(0);
      expect(replica.hasChange(target.hash)).toBe(false);
      expect(A.getHeads(A.load(replica.save())).sort()).toEqual(replica.heads());
    } finally {
      engine.refuse = undefined;
    }
    // The engine back to normal: the held change and its dependants are admitted with the next batch.
    const again = replica.receiveChanges([batch[3] as (typeof batch)[number]]);
    expect(again.refused).toEqual([]);
    const whole = ServiceControlReplica.fromChanges(year.units, year.options).replica;
    expect(replica.heads()).toEqual(whole.heads());
    expect(replica.validate()).toEqual(whole.validate());
  });

  it("is judged again when admission flushes it before the engine path, not only at the end", () => {
    const year = syntheticYear({ days: 2, seed: 4 });
    const split = Math.floor(year.units.length / 2);
    const replica = ServiceControlReplica.fromChanges(
      year.units.slice(0, split),
      year.options,
    ).replica;
    const batch = year.units.slice(split);
    const target = checkChange((batch[3] as { bytes: Uint8Array }).bytes).hash;
    // A later change the shadow cannot model sends admission to the engine path, which flushes first.
    const trigger = checkChange((batch[8] as { bytes: Uint8Array }).bytes).hash;
    const apply = ShadowDoc.prototype.apply;
    const spy = vi.spyOn(ShadowDoc.prototype, "apply").mockImplementation(function (
      this: ShadowDoc,
      c,
    ) {
      if (c.hash === trigger) throw new ShadowUnsupported("the engine path for this change");
      return apply.call(this, c);
    });
    engine.refuse = target;
    try {
      const result = replica.receiveChanges(batch);
      expect(result.refused).toEqual([
        expect.objectContaining({ hash: target, diagnostic: "INVALID_AUTOMERGE_BYTES" }),
      ]);
      expect(result.admitted).not.toContain(target);
      expect(result.admitted).toContain(
        checkChange((batch[2] as { bytes: Uint8Array }).bytes).hash,
      );
      expect(result.admitted.length + result.waiting.length + 1).toBe(batch.length);
      expect(replica.hasChange(target)).toBe(false);
      expect(A.getHeads(A.load(replica.save())).sort()).toEqual(replica.heads());
    } finally {
      spy.mockRestore();
      engine.refuse = undefined;
    }
  });
});
