// §9.2 phase classification against every phase_input of
// IDENTITY-FLOW-FIXTURES-01: the same chain and intent give the
// same phase state on every installation.

import {
  classifyConsume,
  classifyRegister,
  classifyRevoke,
  classifyRotate,
  recordSeq,
} from "@openlfcp/client";
import { fromHex, hash32 } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, test } from "vitest";
import { chainAt, chainOfCert, expectedStep, flows, idOf, recordOf } from "./corpus.js";

const cases = flows.flatMap((f) =>
  f.inputs.steps
    .filter((s) => s.phase_input !== undefined)
    .map((s) => ({ flow: f, step: s, expected: expectedStep(f, s.n).phase as string })),
);

describe("IDENTITY-FLOW-FIXTURES-01: §9.2 phase states", () => {
  test("covers the fixtures' phase inputs", () => {
    expect(cases.length).toBeGreaterThanOrEqual(15);
  });
  test.each(
    cases.map((c) => [`${c.flow.id} step ${c.step.n} (${c.step.phase_input.phase})`, c] as const),
  )("%s", (_, { step, expected }) => {
    const p = step.phase_input;
    const chain = chainAt(p.state);
    let state: string;
    switch (p.phase) {
      case "consume":
        state = classifyConsume(
          chain.state,
          idOf(p.root),
          idOf(p.device),
          hash32(fromHex(p.digest)),
        );
        break;
      case "register": {
        const own = p.own === true;
        state = classifyRegister(chain, {
          root: idOf(p.root),
          chain: chainOfCert(p.certificate),
          isOwnRecord: () => own,
        });
        break;
      }
      case "revoke":
        state = classifyRevoke(chain.state, idOf(p.root), idOf(p.device));
        break;
      case "rotate": {
        const at = recordSeq(chain, sha256(recordOf(p.revoked_at)));
        if (at === undefined) throw new Error("the revocation is not on the chain");
        state = classifyRotate(chain, at, true);
        break;
      }
      default:
        throw new Error(`unknown phase ${p.phase}`);
    }
    expect(state).toBe(expected);
  });
});
