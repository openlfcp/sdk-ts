import * as A from "@automerge/automerge";
import { toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { refusedChangeHash } from "../src/admission/index.js";
import { ACTOR } from "./support/automerge-docs.js";

// SHARED-SECTIONS-PROFILE-01 §14.1 (baseline.7, finding C1): a refused change
// is named — by the SHA-256 of its chunk from the type byte on — only when the
// bytes are one type 1 change chunk of exact length AND its checksum matches.
// The checksum (bytes 4 to 8) is the first four bytes of that same hash, so a
// chunk with a wrong checksum would be named by its intact copy's hash; it is
// left unnamed instead, so a name stands for exactly one sequence of bytes.

const CHANGE = (() => {
  let d: A.Doc<Record<string, unknown>> = A.init({ actor: ACTOR });
  d = A.change(d, (x) => {
    x.a = 1;
  });
  return A.getAllChanges(d)[0] as Uint8Array;
})();
const refused = new Error("refused for some §14.1 reason");

describe("§14.1 a refused change is named only when its checksum matches (C1)", () => {
  it("names a type 1 chunk of exact length whose checksum matches", () => {
    expect(refusedChangeHash(CHANGE, refused)).toBe(toHex(sha256(CHANGE.subarray(8))));
  });

  it("does not name a chunk whose checksum is wrong (SS45): its hash is the intact copy's", () => {
    const broken = Uint8Array.from(CHANGE);
    broken[4] = (broken[4] as number) ^ 0x01; // flip a checksum byte, as SS45 does
    expect(refusedChangeHash(broken, refused)).toBeUndefined();
    // The intact copy is still named, by that same hash.
    expect(refusedChangeHash(CHANGE, refused)).toBe(toHex(sha256(CHANGE.subarray(8))));
  });

  it("still does not name a compressed chunk (type 2) or truncated bytes", () => {
    const compressed = Uint8Array.from(CHANGE);
    compressed[8] = 2;
    expect(refusedChangeHash(compressed, refused)).toBeUndefined();
    expect(refusedChangeHash(CHANGE.subarray(0, CHANGE.length - 1), refused)).toBeUndefined();
  });
});
