import { describe, expect, it } from "vitest";
import { initializeAutomerge, isAutomergeInitialized, SharedObjectsReplica } from "../src/index.js";

// Node resolves the self-initializing build, so initializeAutomerge is a
// no-op here; the /slim path is exercised by the Obsidian bundle (LFCP-059).
describe("initializeAutomerge", () => {
  it("is idempotent and leaves Automerge usable", async () => {
    expect(isAutomergeInitialized()).toBe(true);
    await initializeAutomerge();
    await initializeAutomerge();
    const { replica } = SharedObjectsReplica.create({
      resource: new Uint8Array(32).fill(1) as never,
      principal: new Uint8Array(32).fill(2) as never,
    });
    expect(replica.objectIds()).toEqual([]);
  });
});
