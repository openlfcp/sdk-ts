// LFCP-037: generated programs for the property suite, and the scale.
//
// PR scale by default, with a fixed seed so CI is deterministic;
// LFCP_PROPERTY_EXTENDED=1 for the extended scale, with a fresh seed each
// run. LFCP_SEED (and LFCP_PATH) reproduce one printed failure.

import fc from "fast-check";
import { type Program, type Step, World } from "./harness.js";

// The package is portable (scripts/check-boundaries.mjs: no Node global),
// so the environment is an optional lookup of the host's process object:
// empty in a browser, where the suite runs at PR scale.
const HOST_PROCESS = "process";
type Env = Record<string, string | undefined>;
const env: Env =
  (globalThis as unknown as Record<string, { env?: Env } | undefined>)[HOST_PROCESS]?.env ?? {};
export const EXTENDED = env.LFCP_PROPERTY_EXTENDED === "1";
const SEED = env.LFCP_SEED === undefined ? undefined : Number(env.LFCP_SEED);
const PATH = env.LFCP_PATH;

/**
 * fast-check parameters at PR or extended scale. A fixed default seed keeps
 * the PR suite deterministic; the extended suite explores a fresh seed each
 * run. LFCP_SEED replays a run (same scale), and LFCP_PATH with it replays
 * the shrunk counterexample directly; both are printed on failure.
 */
export function parameters<T extends unknown[] = [Program]>(runs: {
  pr: number;
  extended: number;
}): fc.Parameters<T> {
  const seed = SEED ?? (EXTENDED ? undefined : 0x037);
  return {
    numRuns: EXTENDED ? runs.extended : runs.pr,
    ...(seed !== undefined ? { seed } : {}),
    ...(SEED !== undefined && PATH !== undefined ? { path: PATH } : {}),
  };
}

const MAX_STEPS = EXTENDED ? 150 : 40;
/** Per test: generous for the PR suite, unbounded in practice for the extended one. */
export const TIMEOUT = EXTENDED ? 1_800_000 : 60_000;

const step: fc.Arbitrary<Step> = fc.oneof(
  {
    weight: 6,
    arbitrary: fc.record({
      t: fc.constant("op" as const),
      r: fc.nat(4),
      o: fc.nat(7),
      k: fc.nat(1023),
      v: fc.nat(11),
    }),
  },
  {
    weight: 1,
    arbitrary: fc.record({ t: fc.constant("create" as const), r: fc.nat(4), v: fc.nat(11) }),
  },
  {
    weight: 3,
    arbitrary: fc.record({
      t: fc.constant("sync" as const),
      from: fc.nat(4),
      to: fc.nat(4),
      take: fc.nat(31),
      seed: fc.integer(),
      dup: fc.boolean(),
    }),
  },
);

export const program: fc.Arbitrary<Program> = fc.record({
  replicas: fc.integer({ min: 3, max: 5 }),
  objects: fc.integer({ min: 1, max: 3 }),
  steps: fc.array(step, { minLength: 5, maxLength: MAX_STEPS }),
  finalSeed: fc.integer(),
});

/** Run a program to convergence; throws a full report when an invariant fails. */
export function converge(p: Program): World {
  const world = new World(p.replicas, p.objects);
  try {
    world.run(p);
    world.converge(p.finalSeed);
  } catch (e) {
    throw new Error(world.report(`the run failed: ${(e as Error).message}`, []));
  }
  return world;
}
