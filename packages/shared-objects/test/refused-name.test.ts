import * as A from "@automerge/automerge";
import { toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { describe, expect, it } from "vitest";
import { checkChange, refusedChangeHash } from "../src/admission/index.js";
import { ACTOR } from "./support/automerge-docs.js";

// SHARED-SECTIONS-PROFILE-01 §14.1: a refused change is named — by the SHA-256
// of its chunk from the type byte on — whenever the bytes are one type 1 change
// chunk whose length field covers them exactly and whose checksum matches. The
// inner header is never read. Two findings shape it:
//  - C1: the checksum (bytes 4 to 8) is the first four bytes of that same hash,
//    so a wrong-checksum copy would be named by its intact copy's hash; it is
//    left unnamed, so a name stands for exactly one sequence of bytes.
//  - C3: a chunk whose header holds a length running past its end is still
//    named — the name needs no decoding, and checkChange refuses the chunk.

const CHANGE = (() => {
  let d: A.Doc<Record<string, unknown>> = A.init({ actor: ACTOR });
  d = A.change(d, (x) => {
    x.a = 1;
  });
  return A.getAllChanges(d)[0] as Uint8Array;
})();

/** Bytes 4 to 8 set to the first four bytes of the chunk's hash (a valid checksum). */
function reChecksum(b: Uint8Array): Uint8Array {
  b.set(sha256(b.subarray(8)).subarray(0, 4), 4);
  return b;
}

describe("§14.1 naming a refused change by its hash", () => {
  it("names a type 1 chunk of exact length whose checksum matches", () => {
    expect(refusedChangeHash(CHANGE)).toBe(toHex(sha256(CHANGE.subarray(8))));
  });

  it("does not name a chunk whose checksum is wrong (C1, SS45): its hash is the intact copy's", () => {
    const broken = Uint8Array.from(CHANGE);
    broken[4] = (broken[4] as number) ^ 0x01; // flip a checksum byte, as SS45 does
    expect(refusedChangeHash(broken)).toBeUndefined();
    // The intact copy is still named, by that same hash.
    expect(refusedChangeHash(CHANGE)).toBe(toHex(sha256(CHANGE.subarray(8))));
  });

  it("names a chunk whose inner header length runs past its end (C3), and checkChange refuses it", () => {
    const b = Uint8Array.from(CHANGE);
    // Skip magic (4), checksum (4), type (1), then the outer length LEB128 and
    // the dependency count (0 here): the next LEB128 is the actor length, 32 in
    // one byte. Make it run past the chunk's end, staying one byte (<= 127) so
    // the outer length field still covers the chunk exactly.
    let p = 9;
    while (((b[p++] as number) & 0x80) !== 0);
    while (((b[p++] as number) & 0x80) !== 0);
    expect(b[p]).toBe(0x20); // the actor length, 32
    b[p] = 0x7f; // 127 > the bytes that remain: the inner header runs past the end
    reChecksum(b);
    // checkChange refuses it (the header cannot be read), but it is still named:
    // §14.1 names it from the type byte, the exact outer length and the checksum.
    expect(() => checkChange(b)).toThrow();
    expect(refusedChangeHash(b)).toBe(toHex(sha256(b.subarray(8))));
  });

  it("does not name a compressed chunk (type 2) or truncated bytes", () => {
    const compressed = reChecksum(Uint8Array.from(CHANGE));
    compressed[8] = 2;
    expect(refusedChangeHash(compressed)).toBeUndefined();
    expect(refusedChangeHash(CHANGE.subarray(0, CHANGE.length - 1))).toBeUndefined();
  });
});
