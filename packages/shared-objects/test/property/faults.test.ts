// LFCP-037 tests of testing: the convergence property must detect a faulty
// implementation. Each fault rewrites what the checker observes of a
// replica, as a broken binding would show it, and the property run with
// the fault must fail (deterministic seed), while the same run without it
// passes. A last test feeds the oracle hand-made histories.

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  checkConverged,
  differences,
  expectedObservation,
  type Fault,
  type Observation,
  type ObservedTask,
  Oracle,
  World,
} from "./harness.js";
import { converge, program, TIMEOUT } from "./program.js";

const map = (obs: Observation, f: (id: string, t: ObservedTask) => ObservedTask | undefined) =>
  Object.fromEntries(
    Object.entries(obs).flatMap(([id, t]) => {
      const next = f(id, t);
      return next === undefined ? [] : [[id, next]];
    }),
  ) as Observation;

/** A lost conflict: a conflicted register keeps only one of its values. */
const lostConflict: Fault = (obs) =>
  map(obs, (_, t) => ({
    ...t,
    fields: Object.fromEntries(
      Object.entries(t.fields).map(([f, values]) => [
        f,
        values.length > 1 ? values.slice(1) : values,
      ]),
    ),
  }));

/**
 * Remove-wins instead of add-wins: a member that any replica ever removed
 * is gone, even when an add was concurrent with (or after) the remove.
 */
const removeWins: Fault = (obs, world) => {
  const removed = new Set(
    world.log
      .filter((l) => l.includes('"task.remove_tag"') && !l.endsWith("no change"))
      .map(
        (l) => (JSON.parse(l.slice(l.indexOf("{"), l.lastIndexOf("}") + 1)) as { tag: string }).tag,
      ),
  );
  return map(obs, (_, t) => ({ ...t, tags: t.tags.filter((tag) => !removed.has(tag)) }));
};

/** A physically removed tombstone: an object whose lifecycle is only "deleted" disappears. */
const tombstoneRemoved: Fault = (obs) =>
  map(obs, (_, t) => {
    const lifecycle = t.fields.lifecycle ?? [];
    return lifecycle.length > 0 && lifecycle.every((v) => v === "deleted") ? undefined : t;
  });

const property = (fault: Fault | undefined) =>
  fc.property(program, (p) => checkConverged(converge(p), fault).length === 0);

const detects = (fault: Fault | undefined): boolean =>
  fc.check(property(fault), { numRuns: 40, seed: 0x037 }).failed;

// Each test runs a 40-run property: about 2 s here, nearly 6 s on a GitHub
// runner, so the suite takes the property timeout, not vitest's 5 s.
describe("LFCP-037 tests of testing", { timeout: TIMEOUT }, () => {
  it("the property passes without a fault", () => {
    expect(detects(undefined)).toBe(false);
  });

  it("detects a lost conflict value", () => {
    expect(detects(lostConflict)).toBe(true);
  });

  it("detects remove-wins collection semantics", () => {
    // Deterministic: r0 removes "api" while r1 concurrently adds it again.
    const world = new World(3, 1);
    world.op(0, 0, 9, 0); // add_tag api
    world.converge(1);
    world.op(0, 0, 10, 0); // remove_tag api
    world.op(1, 0, 9, 0); // add_tag api, concurrent: add-wins keeps it
    world.converge(2);
    expect(checkConverged(world)).toEqual([]);
    const failures = checkConverged(world, removeWins);
    expect(failures.length).toBeGreaterThan(0);
    expect(failures[0]).toContain('.tags: actual [], expected ["api"]');
  });

  it("detects a physically removed tombstone", () => {
    expect(detects(tombstoneRemoved)).toBe(true);
  });

  it("a printed seed and path replay the same counterexample", () => {
    // What LFCP_SEED and LFCP_PATH do (program.ts parameters()).
    const first = fc.check(property(lostConflict), { numRuns: 40, seed: 0x1234 });
    expect(first.failed).toBe(true);
    const again = fc.check(property(lostConflict), {
      numRuns: 40,
      seed: first.seed,
      ...(first.counterexamplePath !== null ? { path: first.counterexamplePath } : {}),
    });
    expect(again.failed).toBe(true);
    expect(again.counterexample).toEqual(first.counterexample);
  });

  it("the oracle keeps concurrent values and lets a concurrent add win", () => {
    const oracle = new Oracle();
    const id = "0190a5c0-0000-7000-8000-000000000000";
    const w = (register: string, put: boolean, value: unknown = true) => ({
      object: id,
      register,
      put,
      value: value as never,
    });
    const change = (hash: string, past: string[], writes: ReturnType<typeof w>[]) =>
      oracle.record({ hash, past: new Set(past), writes, label: hash, replica: "r" });
    change(
      "base",
      [],
      [w("status", true, "todo"), w("lifecycle", true, "active"), w("tags/a", true)],
    );
    change("x", ["base"], [w("status", true, "done"), w("tags/a", false)]); // complete, untag
    change("y", ["base"], [w("status", true, "cancelled"), w("tags/a", true)]); // cancel, re-tag
    change("z", ["base", "x"], [w("lifecycle", true, "deleted")]);
    const expected = expectedObservation(oracle.expected(new Set(["base", "x", "y", "z"])));
    expect(expected[id]).toEqual({
      fields: { lifecycle: ["deleted"], status: ["cancelled", "done"] },
      tags: ["a"],
      assignees: [],
    });
    // Resolving the conflict after seeing both supersedes both (§69).
    change("r", ["base", "x", "y", "z"], [w("status", true, "done")]);
    const resolved = expectedObservation(oracle.expected(new Set(["base", "x", "y", "z", "r"])));
    expect(resolved[id]?.fields.status).toEqual(["done"]);
    // And the checker reports each kind of difference.
    const actual = expectedObservation(oracle.expected(new Set(["base", "x"])));
    expect(differences(actual, expected)).toEqual([
      `${id}.lifecycle: actual ["active"], expected ["deleted"]`,
      `${id}.status: actual ["done"], expected ["cancelled","done"]`,
      `${id}.tags: actual [], expected ["a"]`,
    ]);
  });
});
