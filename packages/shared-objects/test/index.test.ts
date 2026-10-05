import { describe, expect, it } from "vitest";
import { PACKAGE } from "../src/index.js";

describe("@openlfcp/shared-objects", () => {
  it("exports its package name", () => {
    expect(PACKAGE).toBe("@openlfcp/shared-objects");
  });
});
