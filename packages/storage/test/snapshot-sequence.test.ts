import { dataEpoch, type LfcpError, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { InMemorySnapshotSequenceReservation, SnapshotSequenceGuard } from "../src/index.js";

const id = (b: number) => new Uint8Array(32).fill(b);
const R = resourceId(id(1));
const P = principalId(id(10));
const Q = principalId(id(11));
const E0 = dataEpoch(0n);
const E1 = dataEpoch(1n);

describe("InMemorySnapshotSequenceReservation (test/dev only)", () => {
  it("starts at 1 and increases per (resource, epoch, publisher)", async () => {
    const r = new InMemorySnapshotSequenceReservation();
    expect(await r.reserveNext(R, E0, P)).toBe(1n);
    expect(await r.reserveNext(R, E0, P)).toBe(2n);
    expect(await r.reserveNext(R, E1, P)).toBe(1n); // another epoch, another key
    expect(await r.reserveNext(R, E0, Q)).toBe(1n); // another publisher, another key
    expect(await r.reserveNext(R, E0, P)).toBe(3n);
  });
});

describe("17. SnapshotSequenceGuard", () => {
  it("refuses a (resource, epoch, publisher, sequence) used twice", () => {
    const g = new SnapshotSequenceGuard();
    g.claim(R, E0, P, 1n);
    g.claim(R, E1, P, 1n);
    g.claim(R, E0, Q, 1n);
    expect(() => g.claim(R, E0, P, 1n)).toThrow(
      expect.objectContaining({ code: "SEQUENCE_REUSE" }) as LfcpError,
    );
  });
});
