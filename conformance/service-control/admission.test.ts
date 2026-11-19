// SERVICE-CONTROL-TEST-VECTORS-01, its validation cases (admission SC0 to
// SC7, §12) at the spec commit pinned in spec.lock. The behavioral cases
// need the replica and run with the whole suite.

import { describe, expect, it } from "vitest";
import type { VectorCase, VectorSuite } from "../runner.js";
import { openSpec } from "../spec.mjs";
import { profileChange } from "./handlers.js";

const suite = openSpec().readJson(
  "test-vectors/service-control-01/SERVICE-CONTROL-TEST-VECTORS-01.json",
) as VectorSuite;
const byId = new Map(suite.cases.map((c) => [c.id, c]));
const context = { suite, caseById: (id: string): VectorCase | undefined => byId.get(id) };
const validation = suite.cases.filter((c) => c.type === "validation");

describe("SERVICE-CONTROL-TEST-VECTORS-01 validation cases", () => {
  it("has the 156 admission cases of the corpus", () => {
    expect(validation.length).toBe(156);
  });
  for (const c of validation)
    it(c.id, async () => {
      const result = await profileChange(c, context);
      expect(result.checks.filter((x) => !x.ok)).toEqual([]);
    });
});
