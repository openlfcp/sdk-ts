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
// Every negative is a Data Unit plaintext on top of a scenario's state that
// the signer-bound profile codec rejects with the expected code and §74.1
// diagnostic, and that is never merged (SO-SEC1: §8, §11).
//
// Every validation is a save image (Text cannot be written in JSON) whose
// profile validation reports exactly the expected problems, at the Text
// value's own pointer (SO-STRINGS: §30, §74.1).
//
// Behavioral interop only (SHARED-OBJECTS-PROFILE-01 §14, AGENT-OPERATING-
// GUIDE §13): byte equality of a re-save is checked as informative below.

import { fromHex, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  CHANGE_LIMITS,
  checkChange,
  checkChangeExpansion,
  checkSnapshotExpansion,
  deriveActorId,
  frameChange,
  frameSnapshot,
  MAX_DOCUMENT_DEPTH,
  SharedObjectsReplica as Replica,
  SharedObjectsDataProfile,
  type SharedObjectsReplica,
  SNAPSHOT_LIMITS_FLOOR,
  unframeChange,
} from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import type { HandlerContext, VectorCase, VectorSuite } from "../runner.js";
import { log, openSpec } from "../spec.mjs";
import { CORPUS_PATH, corpusScenario, readCorpus } from "./corpus.js";
import { runScenario } from "./scenarios.js";

const spec = openSpec();
const corpus = readCorpus();
const suite = spec.readJson(
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
  `LFCP Shared Objects Automerge corpus: ${CORPUS_PATH} from ${spec.lock.repository} ` +
    `${spec.lock.tag} (${spec.lock.commit}), Automerge ${corpus.automerge_version}, ` +
    `${corpus.scenarios.length} scenarios, ${corpus.negatives.length} negatives`,
);

/** Conflicts in the corpus convention: per object, field -> values, and "" -> the number of collided objects. */
function conflictsOf(replica: SharedObjectsReplica): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = replica.conflicts();
  for (const id of replica.collisions()) out[id] = { "": 2 };
  return out;
}

describe(`Automerge reference corpus at ${spec.lock.tag}`, () => {
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

describe(`Automerge reference corpus negatives at ${spec.lock.tag}`, () => {
  it("has a negative", () => {
    expect(corpus.negatives.length).toBeGreaterThan(0);
  });

  for (const negative of corpus.negatives) {
    const { code, diagnostic } = negative.expected.error;
    it(`${negative.id}: ${code}${diagnostic !== undefined ? ` / ${diagnostic}` : ""}`, () => {
      const id = (name: string) =>
        principalId(fromHex(suite.fixtures.principals[name]?.id_hex as string));
      const signer = id(negative.signer);
      expect(toHex(deriveActorId(options.resource, signer))).toBe(negative.signer_actor_hex);
      const plaintext = fromHex(negative.plaintext_hex);
      const base = corpusScenario(negative.base_scenario).changes.map((c) => fromHex(c.change_hex));
      const profile = new SharedObjectsDataProfile(Replica.fromChanges(base, options).replica);
      const before = profile.replica.root();
      // Where the plaintext frames the negative's change exactly (SO-SEC1), the change itself
      // is valid: its own actor's codec decodes it. The SO-BYTES negatives frame corrupted
      // bytes (change is the original before corruption) or no change at all.
      const change = negative.change;
      if (
        change !== undefined &&
        toHex(frameChange(fromHex(change.change_hex))) === negative.plaintext_hex
      ) {
        const author = Object.entries(corpus.actors).find(
          ([, hex]) => hex === change.actor_hex,
        )?.[0];
        expect(author).toBe(change.actor);
        const own = profile.codecFor({ resourceId: options.resource, actor: id(author as string) });
        expect(own.decode(plaintext).hash).toBe(change.hash);
      }
      // Refused when the signer's codec decodes it (§11) or, for a rule that needs the
      // document (§11.1: an actor it does not know), when the replica receives it.
      const codec = profile.codecFor({ resourceId: options.resource, actor: signer });
      expect(() => profile.replica.receiveChange(codec.decode(plaintext).bytes)).toThrow(
        expect.objectContaining({ code, ...(diagnostic !== undefined ? { diagnostic } : {}) }),
      );
      if (change !== undefined) expect(profile.replica.hasChange(change.hash)).toBe(false);
      expect(profile.replica.root()).toEqual(before);
    });
  }
});

describe(`Automerge reference corpus validations at ${spec.lock.tag}`, () => {
  it("has a validation", () => {
    expect(corpus.validations.length).toBeGreaterThan(0);
  });

  for (const validation of corpus.validations) {
    it(`${validation.id}: ${validation.expected_problems.map((p) => p.diagnostic).join(", ")}`, () => {
      // Text cannot be written in a JSON fixture, so the case is a save image.
      const replica = Replica.fromSave(fromHex(validation.save_hex), options);
      const problems = replica
        .validate()
        .problems.map((p) => ({ pointer: p.pointer, code: p.code, diagnostic: p.diagnostic }))
        .sort((a, b) => (a.pointer < b.pointer ? -1 : a.pointer > b.pointer ? 1 : 0));
      expect(problems).toEqual(validation.expected_problems);
    });
  }
});

describe(`Automerge reference corpus expansion limits at ${spec.lock.tag}`, () => {
  it("has the cases", () => {
    expect(corpus.expansion.cases.length).toBeGreaterThan(0);
    expect(corpus.expansion.limits.change.max_rows).toBe(CHANGE_LIMITS.maxRows);
    expect(corpus.expansion.limits.change.max_group_sum).toBe(CHANGE_LIMITS.maxGroupSum);
    expect(corpus.expansion.limits.change.max_string_bytes).toBe(CHANGE_LIMITS.maxStringBytes);
    expect(corpus.expansion.limits.snapshot_floor.max_rows).toBe(SNAPSHOT_LIMITS_FLOOR.maxRows);
    expect(corpus.expansion.limits.snapshot_floor.max_inflated_bytes).toBe(
      SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes,
    );
  });

  for (const x of corpus.expansion.cases) {
    it(`${x.id}: ${x.expected.within_limits ? "within the limits" : "refused"}`, () => {
      // The expansion check alone (§11.1 for a change; §13.1 at the floor for a Snapshot).
      const bytes = fromHex(x.bytes_hex);
      const check = () =>
        x.kind === "change" ? checkChangeExpansion(bytes) : checkSnapshotExpansion(bytes);
      if (x.expected.within_limits) expect(check).not.toThrow();
      else
        expect(check).toThrow(
          expect.objectContaining({
            code: "PROFILE_INVALID",
            diagnostic: "INVALID_AUTOMERGE_BYTES",
          }),
        );
      // The measured bombs (security review H1): refused fast, in bounded memory.
      if (x.id === "EXP-change-rle-bomb" || x.id === "EXP-snapshot-inflated-over-floor") {
        const memory = process.memoryUsage();
        const t = performance.now();
        expect(check).toThrow();
        expect(performance.now() - t).toBeLessThan(2_000);
        const grown =
          process.memoryUsage().heapUsed +
          process.memoryUsage().arrayBuffers -
          (memory.heapUsed + memory.arrayBuffers);
        expect(grown).toBeLessThan(2 * SNAPSHOT_LIMITS_FLOOR.maxInflatedBytes);
      }
      // A refused change never reaches Automerge through the public paths either.
      if (x.kind === "change" && !x.expected.within_limits)
        expect(() => checkChange(bytes)).toThrow(
          expect.objectContaining({ diagnostic: "INVALID_AUTOMERGE_BYTES" }),
        );
    });
  }
});

describe(`Automerge reference corpus depth bound at ${spec.lock.tag}`, () => {
  it("states the SDK's bound", () => {
    expect(corpus.depth.limit).toBe(MAX_DOCUMENT_DEPTH);
  });

  for (const x of corpus.depth.cases) {
    for (const path of ["one by one", "in one batch"] as const) {
      it(`${x.id} (${path}): ${x.changes.map((c) => c.expected).join(", ")}`, () => {
        // §11.2: each change in order on an empty replica, as a receiver would.
        const replica = Replica.empty(options);
        const bytes = x.changes.map((c) => fromHex(c.change_hex));
        let got: string[];
        if (path === "one by one")
          got = bytes.map((b) => {
            try {
              const r = replica.receiveChange(b);
              return r.status === "applied"
                ? "accept"
                : r.status === "missing_dependencies"
                  ? "held"
                  : r.status;
            } catch (e) {
              expect(e).toMatchObject({
                code: "PROFILE_INVALID",
                diagnostic: "INVALID_AUTOMERGE_BYTES",
              });
              return "reject";
            }
          });
        else {
          const r = replica.receiveChanges(bytes);
          got = bytes.map((b) => {
            const hash = checkChange(b).hash;
            if (r.refused.some((f) => f.change.hash === hash)) return "reject";
            return r.waiting.some((w) => w.hash === hash) ? "held" : "accept";
          });
        }
        expect(got).toEqual(x.changes.map((c) => c.expected));
      });
    }
  }

  for (const s of corpus.depth.snapshots) {
    it(`${s.id}: ${s.expected}`, () => {
      const load = () => Replica.fromSnapshot(frameSnapshot(fromHex(s.save_hex)), options);
      if (s.expected === "accept") expect(load).not.toThrow();
      else
        expect(load).toThrow(
          expect.objectContaining({
            code: "PROFILE_INVALID",
            diagnostic: "INVALID_AUTOMERGE_BYTES",
          }),
        );
    });
  }
});
