// The official run of one lfcp-vector-format/1 suite as vitest tests
// (LFCP-017): passing cases are tests; pending cases and pending parts are
// todos, never passes. The header names the suite, baseline tag and commit;
// a JSON summary is printed and written under conformance/.results/.

import { describe, expect, it } from "vitest";
import {
  describeFailure,
  type Handler,
  type PendingFile,
  runSuite,
  type VectorSuite,
} from "./runner.js";
import { log, openSpec, writeSummary } from "./spec.mjs";

export async function defineSuiteRun(
  suitePath: string,
  summaryName: string,
  handlers: Readonly<Record<string, Handler>>,
  pending: PendingFile,
): Promise<void> {
  const spec = openSpec();
  const suite = spec.readJson(suitePath) as VectorSuite;
  const { cases, summary } = await runSuite(suite, handlers, pending);

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
  log(`  written to ${writeSummary(summaryName, report)}`);

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
}
