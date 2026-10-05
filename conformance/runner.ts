// Generic runner for lfcp-vector-format/1 suites (LFCP-017).
//
// Every case resolves to exactly one of:
// - a handler, keyed by "<type>/<kind>", whose checks must all pass;
// - a pending entry (pending.json) naming the task that will implement it;
// - nothing: the case fails as an unclassified vector.
//
// A handler can also run part of a case and name the parts it cannot run
// yet. Those parts must be listed in the case's pending entry, and every
// listed part must still be one the handler names: a pending entry that a
// handler no longer needs fails as stale. Every field of a bytes case's
// `expected` must be checked or pending, so a new field in the suite cannot
// go unnoticed. Pending is never counted as passed.
//
// The runner is pure: no I/O, clock, randomness or locale. Results keep the
// suite's case order.

export interface VectorCase {
  readonly id: string;
  readonly type: string;
  readonly kind: string;
  readonly inputs?: Readonly<Record<string, unknown>>;
  readonly expected: Readonly<Record<string, unknown>>;
  readonly [field: string]: unknown;
}

export interface VectorSuite {
  readonly format: string;
  readonly suite: { readonly id: string; readonly version: string };
  readonly fixtures?: unknown;
  readonly cases: readonly VectorCase[];
}

export type Check =
  | { readonly name: string; readonly ok: true }
  | { readonly name: string; readonly ok: false; readonly message: string };

/** What a handler did with one case: the checks it ran and the parts it cannot run yet. */
export interface HandlerResult {
  readonly checks: readonly Check[];
  readonly pending?: readonly string[];
}

export interface HandlerContext {
  readonly suite: VectorSuite;
  /** Case lookup by ID, for cases that build on other cases (signers, referenced records). */
  readonly caseById: (id: string) => VectorCase | undefined;
}

export type Handler = (vector: VectorCase, context: HandlerContext) => HandlerResult;

/**
 * A pending case. Either the whole case is pending (`task`), or a handler
 * runs part of it and `parts` maps each part it cannot run yet to its
 * owning task. A task is an LFCP task ID such as "LFCP-025", or a scope
 * reference for a feature deferred from the milestone.
 */
export interface PendingEntry {
  readonly reason: string;
  readonly task?: string;
  readonly parts?: Readonly<Record<string, string>>;
}

export interface PendingFile {
  readonly suite: string;
  readonly cases: Readonly<Record<string, PendingEntry>>;
}

export type CaseStatus = "passed" | "partial" | "pending" | "failed";

export interface CaseResult {
  readonly id: string;
  readonly type: string;
  readonly kind: string;
  readonly status: CaseStatus;
  readonly checks: readonly Check[];
  /** Parts not run, with their owning task (the whole case when status is "pending"). */
  readonly pending: readonly { readonly part: string; readonly task: string }[];
  /** Classification problems (unclassified, stale pending, uncovered field, handler error). */
  readonly problems: readonly string[];
}

export interface Summary {
  readonly suite: string;
  readonly version: string;
  /** Cases in the suite. */
  readonly total: number;
  /** Every part checked and passing. */
  readonly passed: number;
  readonly failed: number;
  /** Whole case pending. */
  readonly pending: number;
  /** Implemented checks pass, some parts pending. Not a pass. */
  readonly partial: number;
  readonly checks: { readonly total: number; readonly passed: number; readonly failed: number };
  /** Problems that belong to no case (pending entries for unknown cases, suite mismatch). */
  readonly problems: readonly string[];
}

export interface RunResult {
  readonly cases: readonly CaseResult[];
  readonly summary: Summary;
}

const WHOLE_CASE = "(whole case)";

/** The parts of a case that must be checked or pending: every expected field, or "outcome" for a validation case. */
export function requiredParts(vector: VectorCase): readonly string[] {
  return vector.type === "validation" ? ["outcome"] : Object.keys(vector.expected ?? {}).sort();
}

const fieldOf = (part: string): string => part.split("/")[0] as string;

export function runSuite(
  suite: VectorSuite,
  handlers: Readonly<Record<string, Handler>>,
  pendingFile: PendingFile,
): RunResult {
  const byId = new Map(suite.cases.map((c) => [c.id, c]));
  const context: HandlerContext = { suite, caseById: (id) => byId.get(id) };
  const globalProblems: string[] = [];
  if (pendingFile.suite !== suite.suite.id) {
    globalProblems.push(
      `pending file is for suite ${pendingFile.suite}, but the suite is ${suite.suite.id}`,
    );
  }
  for (const id of Object.keys(pendingFile.cases).sort()) {
    if (!byId.has(id)) globalProblems.push(`pending entry for ${id}, which is not in the suite`);
  }

  const cases = suite.cases.map((vector): CaseResult => {
    const key = `${vector.type}/${vector.kind}`;
    const handler = Object.hasOwn(handlers, key) ? handlers[key] : undefined;
    const entry = Object.hasOwn(pendingFile.cases, vector.id)
      ? pendingFile.cases[vector.id]
      : undefined;
    const base = { id: vector.id, type: vector.type, kind: vector.kind };

    if (handler === undefined) {
      if (entry === undefined) {
        return {
          ...base,
          status: "failed",
          checks: [],
          pending: [],
          problems: [`unclassified vector: no handler for ${key} and no pending entry`],
        };
      }
      if (entry.parts !== undefined || entry.task === undefined) {
        return {
          ...base,
          status: "failed",
          checks: [],
          pending: [],
          problems: [
            entry.parts !== undefined
              ? `pending entry lists parts, but no handler for ${key} runs the rest`
              : "pending entry names no task",
          ],
        };
      }
      return {
        ...base,
        status: "pending",
        checks: [],
        pending: [{ part: WHOLE_CASE, task: entry.task }],
        problems: [],
      };
    }

    const problems: string[] = [];
    let result: HandlerResult;
    try {
      result = handler(vector, context);
    } catch (e) {
      result = { checks: [] };
      problems.push(`handler ${key} threw: ${e instanceof Error ? e.message : String(e)}`);
    }
    const handlerPending = [...new Set(result.pending ?? [])].sort();

    if (entry !== undefined && entry.parts === undefined) {
      problems.push(
        `pending but now handled by ${key}: remove ${vector.id} from pending, or list only the parts still pending`,
      );
    }
    const parts: Readonly<Record<string, string>> = entry?.parts ?? {};
    const listed = new Set(Object.keys(parts));
    for (const part of handlerPending) {
      if (!listed.has(part))
        problems.push(
          `unclassified part "${part}": the handler cannot run it and it is not pending`,
        );
    }
    for (const part of [...listed].sort()) {
      if (!handlerPending.includes(part))
        problems.push(`stale pending part "${part}": now handled, remove it from pending`);
    }
    const covered = new Set([...result.checks.map((c) => c.name), ...handlerPending].map(fieldOf));
    for (const part of requiredParts(vector)) {
      if (!covered.has(part))
        problems.push(`expected field "${part}" is neither checked nor pending`);
    }

    const failedCheck = result.checks.some((c) => !c.ok);
    const pending = handlerPending.map((part) => ({
      part,
      task: Object.hasOwn(parts, part) ? (parts[part] as string) : "unclassified",
    }));
    let status: CaseStatus;
    if (failedCheck || problems.length > 0) status = "failed";
    else if (pending.length === 0) status = "passed";
    else status = result.checks.length === 0 ? "pending" : "partial";
    return { ...base, status, checks: result.checks, pending, problems };
  });

  const count = (s: CaseStatus) => cases.filter((c) => c.status === s).length;
  const allChecks = cases.flatMap((c) => c.checks);
  return {
    cases,
    summary: {
      suite: suite.suite.id,
      version: suite.suite.version,
      total: cases.length,
      passed: count("passed"),
      failed: count("failed"),
      pending: count("pending"),
      partial: count("partial"),
      checks: {
        total: allChecks.length,
        passed: allChecks.filter((c) => c.ok).length,
        failed: allChecks.filter((c) => !c.ok).length,
      },
      problems: globalProblems,
    },
  };
}

/** A human-readable failure report for one case; every line names the vector ID. */
export function describeFailure(result: CaseResult): string {
  const lines = [`${result.id} (${result.type}/${result.kind}) FAILED`];
  for (const p of result.problems) lines.push(`  ${result.id}: ${p}`);
  for (const c of result.checks) if (!c.ok) lines.push(`  ${result.id} ${c.name}: ${c.message}`);
  return lines.join("\n");
}
