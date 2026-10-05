import { describe, expect, it } from "vitest";
import { PACKAGE } from "../src/index.js";

describe("@openlfcp/client", () => {
  it("exports its package name", () => {
    expect(PACKAGE).toBe("@openlfcp/client");
  });
});
