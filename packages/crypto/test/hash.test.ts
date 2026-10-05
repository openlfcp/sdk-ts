import { fromHex, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { PACKAGE, sha256 } from "../src/index.js";

describe("@openlfcp/crypto", () => {
  it("exports its package name", () => {
    expect(PACKAGE).toBe("@openlfcp/crypto");
  });
});

describe("sha256", () => {
  it.each([
    // FIPS 180-4 / NIST example values
    ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ])("hashes %j", (input, digest) => {
    expect(toHex(sha256(fromHex(input)))).toBe(digest);
  });
});
