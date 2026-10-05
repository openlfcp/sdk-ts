// Self-tests for the diagnostic-notation reader (LFCP-017).

import { describe, expect, it } from "vitest";
import { parseDiag } from "./diag.js";

describe("diagnostic-notation reader", () => {
  it("reads the subset used by the CDDL fixtures", () => {
    const v = parseDiag("/ comment / {0: h'0a0B', 1: -2, 2: [\"x\", true, null]}");
    expect(v).toEqual({
      kind: "cbor-map",
      entries: [
        [0, Uint8Array.of(0x0a, 0x0b)],
        [1, -2],
        [2, ["x", true, null]],
      ],
    });
  });

  it.each(["{0: 1.5}", "{0: 1", "[1] 2", "h'0'", '"a\\"b"', "undefined"])("rejects %s", (text) => {
    expect(() => parseDiag(text)).toThrow("diagnostic notation");
  });
});
