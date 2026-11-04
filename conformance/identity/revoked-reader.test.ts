// W §41 revoked-reader prefix against the session_read vectors of
// LFCP-IDENTITY-TEST-VECTORS-01 (spec#3).
import { toHex } from "@openlfcp/core";
import { revokedReaderPrefix } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { chainOf, contextOf, idOf, recordOf, wire } from "./corpus.js";

const cases = wire.cases.filter(
  (c) => c.kind === "session_read" && c.inputs.request === "CONTROL_GET",
);

describe("LFCP-IDENTITY-TEST-VECTORS-01: control read for a revoked reader (W §41)", () => {
  test("covers the corpus", () => expect(cases.length).toBeGreaterThanOrEqual(5));
  test.each(cases.map((c) => [c.id, c] as const))("%s", (_, c) => {
    const chain = chainOf(contextOf(c.id));
    const prefix = revokedReaderPrefix(chain, idOf(c.inputs.session));
    if (c.expected.valid === true && c.expected.post_state.read === "prefix") {
      expect(prefix).toBeDefined();
      expect(toHex(prefix?.recordId as Uint8Array)).toBe(
        toHex(
          chainOf([
            ...contextOf(c.expected.post_state.control_head),
            recordOf(c.expected.post_state.control_head),
          ]).state.head,
        ),
      );
      expect(chain.records.slice(0, (prefix?.index ?? 0) + 1).length).toBe(
        c.expected.post_state.records.length,
      );
    } else expect(prefix).toBeUndefined();
  });
});
