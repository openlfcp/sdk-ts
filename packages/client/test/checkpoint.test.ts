import { type ResourceId, resourceId } from "@openlfcp/core";
import { InMemoryLfcpStorage, type ProfileCheckpoint } from "@openlfcp/storage";
import { describe, expect, it } from "vitest";
import { ProfileCheckpointer } from "../src/index.js";

const PROFILE = "org.example.text.v1";
const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);

describe("ProfileCheckpointer", () => {
  it("writes a checkpoint only when changed and not more often than the interval", async () => {
    const storage = new InMemoryLfcpStorage();
    const R: ResourceId = resourceId(bytes32(9));
    let n = 0;
    const source = {
      checkpoint: (): ProfileCheckpoint => ({
        resourceId: R,
        dataProfile: PROFILE,
        state: Uint8Array.of(++n),
        actorSeq: n,
        units: [],
      }),
    };
    const cp = new ProfileCheckpointer(storage, source, { minIntervalMs: 1000 });
    expect(await cp.maybeFlush(0)).toBe(false);
    cp.noteChange();
    expect(await cp.maybeFlush(0)).toBe(true);
    cp.noteChange();
    expect(await cp.maybeFlush(500)).toBe(false);
    expect(cp.dirty).toBe(true);
    expect(await cp.maybeFlush(1000)).toBe(true);
    expect((await storage.profileState.checkpoint(R))?.actorSeq).toBe(2);
    // As part of another atomic batch (e.g. a local unit's commit).
    cp.noteChange();
    expect(await storage.commit([cp.write()])).toEqual({ ok: true });
    expect(cp.dirty).toBe(false);
    expect((await storage.profileState.checkpoint(R))?.actorSeq).toBe(3);
  });
});
