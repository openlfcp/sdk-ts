import { actorSequence, LfcpError, principalId, resourceId, UINT64_MAX } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  InMemoryActorSequenceReservation,
  nextActorSequence,
  SequenceReuseGuard,
} from "../src/index.js";

const codeOf = async (fn: () => unknown): Promise<string | undefined> => {
  try {
    await fn();
  } catch (e) {
    return e instanceof LfcpError ? e.code : `not-an-LfcpError: ${String(e)}`;
  }
  return undefined;
};
const id = (b: number) => new Uint8Array(32).fill(b);
const R = resourceId(id(1));
const R2 = resourceId(id(2));
const A = principalId(id(10));
const B = principalId(id(11));

describe("nextActorSequence", () => {
  it("starts at 1 and counts up", () => {
    expect(nextActorSequence(undefined)).toBe(1n);
    expect(nextActorSequence(actorSequence(41n))).toBe(42n);
    expect(nextActorSequence(actorSequence(UINT64_MAX - 1n))).toBe(UINT64_MAX);
  });

  it("rejects exhaustion of the 2^64 - 1 space instead of wrapping", async () => {
    expect(await codeOf(() => nextActorSequence(actorSequence(UINT64_MAX)))).toBe("OUT_OF_RANGE");
  });
});

describe("InMemoryActorSequenceReservation (test/dev only)", () => {
  it("scopes sequences per (Resource, Principal), starting at 1", async () => {
    const r = new InMemoryActorSequenceReservation();
    expect(await r.reserveNext(R, A)).toBe(1n);
    expect(await r.reserveNext(R, A)).toBe(2n);
    expect(await r.reserveNext(R, B)).toBe(1n);
    expect(await r.reserveNext(R2, A)).toBe(1n);
    expect(await r.reserveNext(R, A)).toBe(3n);
  });

  it("never hands out the same sequence to concurrent callers", async () => {
    const r = new InMemoryActorSequenceReservation();
    const got = await Promise.all(Array.from({ length: 100 }, () => r.reserveNext(R, A)));
    expect(new Set(got).size).toBe(100);
    expect([...got].sort((x, y) => (x < y ? -1 : 1))[99]).toBe(100n);
  });

  it("14. an epoch change does not reset the sequence", async () => {
    // The reservation is keyed by (Resource, Principal) only: it takes no
    // Data Epoch, so a rotation cannot restart it. A new epoch changes the
    // actor key instead (@openlfcp/crypto epoch tests, item 9).
    const r = new InMemoryActorSequenceReservation();
    const epoch0 = [await r.reserveNext(R, A), await r.reserveNext(R, A)];
    const afterRotation = await r.reserveNext(R, A);
    expect(epoch0).toEqual([1n, 2n]);
    expect(afterRotation).toBe(3n);
    expect(r.reserveNext.length).toBe(2);
  });
});

describe("SequenceReuseGuard", () => {
  it("13. rejects a second use of the same (Resource, Principal, seq)", async () => {
    const g = new SequenceReuseGuard();
    g.claim(R, A, actorSequence(1n));
    expect(await codeOf(() => g.claim(R, A, actorSequence(1n)))).toBe("SEQUENCE_REUSE");
    expect(g.has(R, A, actorSequence(1n))).toBe(true);
  });

  it("allows the same sequence for another Principal or Resource (§12)", () => {
    const g = new SequenceReuseGuard();
    g.claim(R, A, actorSequence(1n));
    expect(() => g.claim(R, B, actorSequence(1n))).not.toThrow();
    expect(() => g.claim(R2, A, actorSequence(1n))).not.toThrow();
  });

  it("rejects sequence 0 and values beyond 2^64 - 1", async () => {
    const g = new SequenceReuseGuard();
    expect(await codeOf(() => g.claim(R, A, 0n as never))).toBe("OUT_OF_RANGE");
    expect(await codeOf(() => g.claim(R, A, (2n ** 64n) as never))).toBe("OUT_OF_RANGE");
  });
});
