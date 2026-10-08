// The sdk-ts adapter (adapter.mjs) against every case of the shared
// sections corpus at the baseline in spec.lock, as the reference verifier
// compares it (LFCP-02-018): every expected field but the internal error
// strings. The adapter reads no expected value. The same holds when every
// change arrives twice in reverse order, and from the base Snapshot plus
// the branches' changes.

import { describe, expect, it } from "vitest";
import { openSpec } from "../spec.mjs";
import { runCase } from "./adapter.mjs";

const CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

interface Case {
  readonly id: string;
  readonly base_snapshot: unknown;
  readonly base_changes: readonly unknown[];
  readonly branches: { readonly A: readonly unknown[]; readonly B: readonly unknown[] };
  readonly after_merge: readonly unknown[];
  readonly expected: Readonly<Record<string, unknown>>;
}
const suite = openSpec().readJson(CORPUS) as {
  readonly profile: string;
  readonly identities: unknown;
  readonly cases: readonly Case[];
};

describe("sdk-ts adapter for SHARED-SECTIONS-TEST-VECTORS-01", () => {
  for (const delivery of ["normal", "reverse", "checkpoint"] as const)
    for (const c of suite.cases)
      it(`${c.id} (${delivery}): the production SDK reaches every expected field`, async () => {
        const result = await runCase({
          id: c.id,
          profile: suite.profile,
          identities: suite.identities,
          base_snapshot: c.base_snapshot,
          base_changes: c.base_changes,
          branches: c.branches,
          after_merge: c.after_merge,
          delivery,
        });
        // A refused change's place in the list differs by delivery; the set is what counts.
        const keys = Object.keys(c.expected).filter((k) => k !== "errors");
        for (const key of keys)
          expect(result[key], `${c.id} ${delivery} ${key}`).toEqual(c.expected[key]);
      }, 30_000);
});
