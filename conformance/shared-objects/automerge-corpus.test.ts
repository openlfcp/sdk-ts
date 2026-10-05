// The Automerge reference corpus (SHARED-OBJECTS-AUTOMERGE-REFERENCE-01)
// through the sdk-ts binding (LFCP-031). For every scenario:
//
// - every change passes the §11 byte checks, decodes to the recorded hash,
//   actor, sequence and dependencies, and applies in the recorded order;
// - the same change set in reverse order converges to the same state (the
//   binding buffers nothing: a change waits until its dependencies apply);
// - the state, heads and scalar conflict sets match the corpus;
// - the full-save image loads (§13) to the same state and conflicts, and
//   as a Snapshot accepts the changes beyond it (S14).
//
// Behavioral interop only (SHARED-OBJECTS-PROFILE-01 §14, AGENT-OPERATING-
// GUIDE §13): byte equality of a re-save is checked as informative below.

import { fromHex, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  checkChange,
  frameChange,
  frameSnapshot,
  SharedObjectsReplica as Replica,
  type SharedObjectsReplica,
  unframeChange,
} from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import type { HandlerContext, VectorCase, VectorSuite } from "../runner.js";
import { log, openSpec } from "../spec.mjs";
import { CORPUS_PATH, CORPUS_SPEC_COMMIT, readCorpus } from "./corpus.js";
import { runScenario } from "./scenarios.js";

const corpus = readCorpus();
const suite = openSpec().readJson(
  "test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json",
) as VectorSuite & {
  fixtures: { resource_a_hex: string; principals: Record<string, { id_hex: string }> };
};
const context: HandlerContext = { suite, caseById: (id) => suite.cases.find((c) => c.id === id) };
const options = {
  resource: resourceId(fromHex(suite.fixtures.resource_a_hex)),
  principal: principalId(fromHex(suite.fixtures.principals.andrey?.id_hex as string)),
};

log(
  `LFCP Shared Objects Automerge corpus: ${CORPUS_PATH} at spec ${CORPUS_SPEC_COMMIT} ` +
    `(Automerge ${corpus.automerge_version}), ${corpus.scenarios.length} scenarios`,
);

/** Conflicts in the corpus convention: per object, field -> values, and "" -> the number of collided objects. */
function conflictsOf(replica: SharedObjectsReplica): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = replica.conflicts();
  for (const id of replica.collisions()) out[id] = { "": 2 };
  return out;
}

describe(`Automerge reference corpus at spec ${CORPUS_SPEC_COMMIT.slice(0, 7)}`, () => {
  it("targets the binding's Automerge version and the fixture Resource", () => {
    expect(corpus.automerge_version).toBe("3.5.0");
    expect(corpus.resource_hex).toBe(suite.fixtures.resource_a_hex);
  });

  for (const scenario of corpus.scenarios) {
    describe(`${scenario.id}: ${scenario.description}`, () => {
      const bytes = scenario.changes.map((c) => fromHex(c.change_hex));

      it("checks, frames and applies every change in order", () => {
        const replica = Replica.empty(options);
        scenario.changes.forEach((c, i) => {
          const change = bytes[i] as Uint8Array;
          const checked = checkChange(change);
          expect([checked.hash, checked.actor, checked.seq, [...checked.deps].sort()]).toEqual([
            c.hash,
            c.actor_hex,
            c.seq,
            c.deps,
          ]);
          expect(unframeChange(frameChange(change)).hash).toBe(c.hash);
          expect(replica.receive(frameChange(change)).status).toBe("applied");
        });
        expect(replica.heads()).toEqual(scenario.heads);
        expect(replica.root()).toEqual(scenario.state);
        expect(conflictsOf(replica)).toEqual(scenario.conflicts);
      });

      it("converges from the reverse order", () => {
        const { replica, unapplied } = Replica.fromChanges([...bytes].reverse(), options);
        expect(unapplied).toEqual([]);
        expect(replica.heads()).toEqual(scenario.heads);
        expect(replica.root()).toEqual(scenario.state);
        expect(conflictsOf(replica)).toEqual(scenario.conflicts);
      });

      it("loads the full-save image as a Snapshot (§13)", () => {
        const save = fromHex(scenario.save_hex);
        const replica = Replica.fromSnapshot(frameSnapshot(save), options);
        expect(replica.heads()).toEqual(scenario.heads);
        expect(replica.root()).toEqual(scenario.state);
        expect(conflictsOf(replica)).toEqual(scenario.conflicts);
        // Informative only: §14 does not require byte-identical saves, even
        // from the same Automerge version. Same-version re-saves of a loaded
        // image are identical today; a mismatch here is a signal, not a
        // conformance failure, and may be relaxed when Automerge changes.
        expect(toHex(replica.save())).toBe(scenario.save_hex);
      });

      it("matches the outcome of the binding's own run of the scenario", () => {
        // Different change bytes (messages, actors' histories), same logical outcome.
        const { replica } = runScenario(context.caseById(scenario.id) as VectorCase, context);
        expect(replica.root()).toEqual(scenario.state);
        expect(conflictsOf(replica)).toEqual(scenario.conflicts);
      });

      if (scenario.snapshot !== undefined) {
        const snapshot = scenario.snapshot;
        it("applies the changes beyond the Snapshot frontier", () => {
          const replica = Replica.fromSnapshot(frameSnapshot(fromHex(snapshot.save_hex)), options);
          expect(replica.heads()).toEqual(snapshot.heads);
          const later = bytes.filter((b) => !replica.hasChange(checkChange(b).hash));
          expect(later.length).toBeGreaterThan(0);
          for (const b of later) expect(replica.receiveChange(b).status).toBe("applied");
          expect(replica.root()).toEqual(scenario.state);
        });
      }
    });
  }
});
