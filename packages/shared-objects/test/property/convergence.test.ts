// LFCP-037: randomized multi-replica convergence of the Shared Objects
// profile on Automerge. See harness.ts for the model and the oracle.
//
// Each run builds 3-5 replicas from one base, applies generated
// profile-valid intents at random replicas with partial, shuffled,
// duplicated and delayed delivery in between, then delivers everything
// everywhere in a random order and checks:
//   (a) every replica has the same logical state and conflict sets, equal
//       to the oracle's (multi-value registers, add-wins collections);
//   (b) every replica's validate() is clean: a concurrent scalar conflict
//       never turns into Text or becomes invalid;
//   (c) after the merge, a further intent succeeds on every object;
//   (d) re-applying already-seen changes changes nothing (Automerge
//       idempotency, not LFCP Data Unit ID deduplication).
// and (G-EP7) that rebuilding without a subset of changes equals a fresh
// replica of the remaining set, and the oracle over it.
//
// PR suite: a few seconds. Extended: LFCP_PROPERTY_EXTENDED=1 (pnpm
// --filter @openlfcp/shared-objects test:property:extended). Reproduce a
// failure with the seed and path it prints:
//   LFCP_SEED=<seed> LFCP_PATH=<path> pnpm --filter @openlfcp/shared-objects test property

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { checkConverged, rebuildCheck } from "./harness.js";
import { converge, EXTENDED, parameters, program, TIMEOUT } from "./program.js";

describe(`LFCP-037 convergence properties (${EXTENDED ? "extended" : "PR"} scale)`, () => {
  it(
    "replicas converge to the oracle's state, stay valid and writable, and ignore re-applied changes",
    () => {
      fc.assert(
        fc.property(program, (p) => {
          const world = converge(p);
          const failures = checkConverged(world);
          if (failures.length > 0) throw new Error(world.report("invariants failed:", failures));
        }),
        parameters({ pr: 40, extended: 400 }),
      );
    },
    TIMEOUT,
  );

  it(
    "state is a function of the accepted change set: rebuilding without a subset (G-EP7)",
    () => {
      fc.assert(
        fc.property(
          program,
          fc.array(fc.nat(), { maxLength: 4 }),
          fc.integer(),
          (p, picks, seed) => {
            const world = converge(p);
            // Never the Resource's first change: without it nothing applies.
            const candidates = [...world.bytes.keys()].slice(1);
            const exclude = new Set(picks.map((i) => candidates[i % candidates.length] as string));
            const failures = rebuildCheck(world, exclude, seed);
            if (failures.length > 0)
              throw new Error(
                world.report(`rebuild without ${[...exclude].join(", ")} failed:`, failures),
              );
          },
        ),
        parameters({ pr: 15, extended: 150 }),
      );
    },
    TIMEOUT,
  );

  it(
    "the generated programs exercise conflicts, collections and tombstones",
    () => {
      // A guard against a generator that stops producing what the
      // properties are about.
      const seen = { conflict: 0, tag: 0, deleted: 0, waited: 0 };
      fc.assert(
        fc.property(program, (p) => {
          const world = converge(p);
          const root = world.nodes[0]?.replica;
          if (root === undefined) return;
          if (Object.keys(root.conflicts()).length > 0) seen.conflict++;
          for (const { id } of world.objects) {
            const view = root.task(id);
            if ((view?.tags.length ?? 0) > 0) seen.tag++;
            if (view?.fields.lifecycle.values.includes("deleted")) seen.deleted++;
          }
          if (world.log.some((l) => /[1-9]\d* waiting/.test(l))) seen.waited++;
        }),
        { numRuns: 40, seed: 0x037 },
      );
      expect(seen.conflict).toBeGreaterThan(5);
      expect(seen.tag).toBeGreaterThan(5);
      expect(seen.deleted).toBeGreaterThan(2);
      expect(seen.waited).toBeGreaterThan(2);
    },
    TIMEOUT,
  );
});
