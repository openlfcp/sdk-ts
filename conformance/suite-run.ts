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
import { log, openSpec, writeOutcomes, writeSummary } from "./spec.mjs";

/**
 * An outcome export of the run (lfcp-identity-outcomes/1): every case's
 * handler report, keyed by case ID, written to `file` under
 * $LFCP_IDENTITY_REPORT_DIR when that is set. A case without a report fails.
 */
export interface OutcomeExport {
  readonly file: string;
}

export async function defineSuiteRun(
  suitePath: string,
  summaryName: string,
  handlers: Readonly<Record<string, Handler>>,
  pending: PendingFile,
  outcomes?: OutcomeExport,
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
    incomplete: summary.incomplete,
    failed: summary.failed,
    pending: summary.pending,
    partial: summary.partial,
    checks: summary.checks,
    not_applicable: cases.flatMap((c) =>
      Object.keys(c.notApplicable ?? {}).map((p) => `${c.id} ${p}`),
    ),
    not_verified: cases.flatMap((c) => Object.keys(c.notVerified ?? {}).map((p) => `${c.id} ${p}`)),
  };
  log(`LFCP conformance: ${header}`);
  log(
    `  ${summary.total} cases: ${summary.passed} passed, ${summary.incomplete} incomplete ` +
      `(checks pass, parts not verified), ${summary.partial} partial ` +
      `(checks pass, parts pending), ${summary.pending} pending, ${summary.failed} failed; ` +
      `${summary.checks.passed}/${summary.checks.total} checks pass`,
  );
  for (const c of cases) {
    for (const [part, why] of Object.entries(c.notApplicable ?? {}))
      log(`  not applicable: ${c.id} ${part}: ${why}`);
    for (const [part, why] of Object.entries(c.notVerified ?? {}))
      log(`  not verified: ${c.id} ${part}: ${why}`);
  }
  log(`  summary: ${JSON.stringify(report)}`);
  log(`  written to ${writeSummary(summaryName, report)}`);
  const reported = Object.fromEntries(
    cases.filter((c) => c.report !== undefined).map((c) => [c.id, c.report]),
  );
  if (outcomes !== undefined) {
    const path = writeOutcomes(outcomes.file, spec.lock, reported);
    if (path !== undefined) log(`  outcomes written to ${path}`);
  }

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
        // An incomplete case says what it does not verify in its title: checks pass, it is not a full pass.
        const unverified = Object.keys(c.notVerified ?? {});
        it(`${c.id}: ${c.checks.length} checks pass${unverified.length === 0 ? "" : `; not verified: ${unverified.join(", ")}`}`, () => {
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

    if (outcomes !== undefined)
      it("reports an outcome for every case", () => {
        expect(cases.filter((c) => c.report === undefined).map((c) => c.id)).toEqual([]);
      });

    it("has no failed case", () => {
      expect(cases.filter((c) => c.status === "failed").map((c) => c.id)).toEqual([]);
    });
  });
}
