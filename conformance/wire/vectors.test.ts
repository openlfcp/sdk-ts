// LFCP-TEST-VECTORS-01 conformance run (LFCP-017): the official suite at the
// spec commit pinned in spec.lock, through the sdk-ts handlers. Passing
// cases are tests; pending cases and pending parts are todos, never passes.

import { describe, expect, it } from "vitest";
import { describeFailure, type PendingFile, runSuite, type VectorSuite } from "../runner.js";
import { log, openSpec, writeSummary } from "../spec.mjs";
import { WIRE_HANDLERS } from "./handlers.js";
import pending from "./pending.json" with { type: "json" };

const SUITE_PATH = "test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json";

const spec = openSpec();
const suite = spec.readJson(SUITE_PATH) as VectorSuite;
const { cases, summary } = runSuite(suite, WIRE_HANDLERS, pending as PendingFile);

const header =
  `${suite.suite.id} version ${suite.suite.version} (${suite.format}) from ` +
  `${spec.lock.repository} ${spec.lock.tag} (${spec.lock.commit})`;
const report = {
  baseline: spec.lock.tag,
  commit: spec.lock.commit,
  suite: `${suite.suite.id}/${suite.suite.version}`,
  total: summary.total,
  passed: summary.passed,
  failed: summary.failed,
  pending: summary.pending,
  partial: summary.partial,
  checks: summary.checks,
};
log(`LFCP conformance: ${header}`);
log(
  `  ${summary.total} cases: ${summary.passed} passed, ${summary.partial} partial ` +
    `(checks pass, parts pending), ${summary.pending} pending, ${summary.failed} failed; ` +
    `${summary.checks.passed}/${summary.checks.total} checks pass`,
);
log(`  summary: ${JSON.stringify(report)}`);
log(`  written to ${writeSummary("lfcp-test-vectors-01", report)}`);

describe(header, () => {
  for (const c of cases) {
    const tasks = [...new Set(c.pending.map((p) => p.task))].join(", ");
    if (c.status === "failed") {
      it(`${c.id}: FAILED`, () => {
        throw new Error(describeFailure(c));
      });
    } else if (c.status === "pending") {
      it.todo(`${c.id}: pending -> ${tasks}`);
    } else {
      it(`${c.id}: ${c.checks.length} checks pass`, () => {
        expect(c.checks.every((x) => x.ok)).toBe(true);
      });
      if (c.status === "partial")
        it.todo(
          `${c.id}: parts pending -> ${c.pending.map((p) => `${p.part} (${p.task})`).join(", ")}`,
        );
    }
  }

  it("has no suite-level problems (pending entries match the suite)", () => {
    expect(summary.problems).toEqual([]);
  });

  it("has no failed case", () => {
    expect(cases.filter((c) => c.status === "failed").map((c) => c.id)).toEqual([]);
  });
});
