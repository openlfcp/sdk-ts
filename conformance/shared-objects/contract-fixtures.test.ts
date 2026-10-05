// The spec's Shared Objects structural-contract fixtures at the pinned
// commit (profiles/shared-objects-01/schema/fixtures/, LFCP-006; not
// normative vectors). sdk-ts's validator is an independent implementation
// of the same contract:
//
// - every valid-*.json state has no problem;
// - every invalid-*.json state fails at exactly the pointers expected.json
//   lists, each with the §74.1 diagnostic it names (PROFILE_INVALID).
//
// A fixture in neither form, or an invalid one missing from expected.json,
// fails the run.

import { type Json, validateRoot } from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import { log, openSpec } from "../spec.mjs";

const DIR = "profiles/shared-objects-01/schema/fixtures";
const spec = openSpec();
const files = spec.list(DIR).filter((f) => f !== "expected.json");
const expected = (
  spec.readJson(`${DIR}/expected.json`) as {
    cases: Record<string, { pointers: string[]; diagnostic: string }>;
  }
).cases;

log(
  `LFCP Shared Objects contract fixtures: ${DIR} from ${spec.lock.repository} ${spec.lock.tag} (${spec.lock.commit}), ${files.length} fixtures`,
);

describe(`Shared Objects contract fixtures at ${spec.lock.tag}`, () => {
  for (const file of files) {
    const state = spec.readJson(`${DIR}/${file}`) as Json;
    if (file.startsWith("valid-")) {
      it(`${file} is valid`, () => {
        expect(validateRoot(state).problems).toEqual([]);
      });
    } else if (file.startsWith("invalid-") && file in expected) {
      const want = expected[file] as { pointers: string[]; diagnostic: string };
      it(`${file} fails at ${want.pointers.join(", ")} with ${want.diagnostic}`, () => {
        const problems = validateRoot(state).problems;
        expect([...new Set(problems.map((p) => p.pointer))].sort()).toEqual(
          [...want.pointers].sort(),
        );
        expect([...new Set(problems.map((p) => `${p.code}/${p.diagnostic}`))]).toEqual([
          `PROFILE_INVALID/${want.diagnostic}`,
        ]);
      });
    } else {
      it(`${file}: unclassified fixture`, () => {
        throw new Error(`${file} is neither valid-* nor an invalid-* listed in expected.json`);
      });
    }
  }

  it("expected.json lists no fixture that does not exist", () => {
    expect(Object.keys(expected).filter((f) => !files.includes(f))).toEqual([]);
  });
});
