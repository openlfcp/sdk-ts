// W §17.5 Exposure against every accepted DEVICE_REVOKE of
// LFCP-IDENTITY-TEST-VECTORS-01 that states it.
import { exposedReaders, isExposingRevocation } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { chainOf, contextOf, recordOf, wire } from "./corpus.js";

const cases = wire.cases.filter(
  (c) =>
    c.kind === "control_record" &&
    c.expected?.valid === true &&
    c.inputs?.control_type_name === "DEVICE_REVOKE" &&
    (c.expected?.post_state?.exposing ?? c.expected?.exposing) !== undefined,
);

describe("LFCP-IDENTITY-TEST-VECTORS-01: exposure of DEVICE_REVOKE (W §17.5)", () => {
  test("covers the corpus", () => expect(cases.length).toBeGreaterThanOrEqual(20));
  test.each(cases.map((c) => [c.id, c] as const))("%s", (_, c) => {
    const before = chainOf(contextOf(c.id));
    const after = chainOf([...contextOf(c.id), recordOf(c.id)]);
    const expected = c.expected.post_state?.exposing ?? c.expected.exposing;
    expect(isExposingRevocation(before.state, after.state)).toBe(expected);
    expect(exposedReaders(before.state, after.state).length > 0).toBe(expected);
  });
});
