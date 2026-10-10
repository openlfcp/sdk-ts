// LFCP-02-085: the admission module both profiles share
// (@openlfcp/shared-objects/admission) carries the §§7–18 rules unchanged
// and takes the actor domain as a parameter.

import { principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  admitBatch,
  admitChange,
  type CheckedChange,
  checkChangeActor,
  deriveDomainActorId,
} from "../src/admission/index.js";
import { deriveActorId } from "../src/index.js";

const R = resourceId(Uint8Array.from({ length: 32 }, (_, i) => i));
const P = principalId(Uint8Array.from({ length: 32 }, (_, i) => 100 + i));
const change = (actor: string, seq: number, hash: string, deps: string[] = []): CheckedChange =>
  Object.freeze({
    bytes: new Uint8Array(),
    hash,
    actor,
    seq,
    deps,
    otherActors: [],
    beginsWithAuthor: false,
  });

describe("the shared admission module (LFCP-02-085)", () => {
  it("binds actors per domain; the Shared Objects domain gives deriveActorId", () => {
    const so = deriveDomainActorId("OPENLFCP-SHARED-OBJECTS-ACTOR-v1", R, P);
    expect(toHex(so)).toBe(toHex(deriveActorId(R, P)));
    const sections = deriveDomainActorId("OPENLFCP-SHARED-SECTIONS-ACTOR-v1", R, P);
    expect(toHex(sections)).not.toBe(toHex(so));
    expect(() => checkChangeActor(change("aa", 1, "h1"), "bb")).toThrow(
      expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "CHANGE_ACTOR_MISMATCH" }),
    );
  });

  it("orders, holds and refuses as §14.1 says, and asks the profile last", () => {
    const doc = {
      hasChange: (h: string) => h === "h1",
      latestSeq: (a: string) => (a === "aa" ? 1 : 0),
    };
    const asked: string[] = [];
    const r = admitBatch(
      [
        change("aa", 3, "h3", ["h2"]), // after h2, in the batch
        change("aa", 2, "h2", ["h1"]),
        change("aa", 1, "hx"), // a different change at a taken sequence: held
        change("bb", 2, "hb"), // skips sequence 1 of bb: invalid
        change("aa", 9, "hw", ["missing"]), // waits for a dependency
        change("cc", 1, "h1"), // the document holds it
      ],
      doc,
      (c) => {
        asked.push(c.hash);
      },
    );
    expect(r.admitted.map((c) => c.hash)).toEqual(["h2", "h3"]);
    expect(asked).toEqual(["h2", "h3"]);
    expect(r.duplicates.map((c) => c.hash)).toEqual(["h1"]);
    expect(r.waiting.map((c) => c.hash)).toEqual(["hw"]);
    expect(r.refused.map((x) => [x.change.hash, x.held, x.error.code])).toEqual([
      ["hx", true, "ACTOR_EQUIVOCATION"],
      ["hb", false, "PROFILE_INVALID"],
    ]);
    expect(admitChange(change("aa", 1, "hx"), doc).kind).toBe("held");
    expect(admitChange(change("aa", 2, "h2", ["h1"]), doc).kind).toBe("next");
  });
});
