import { describe, expect, it } from "vitest";
import { initializeAutomerge, isAutomergeInitialized, SharedObjectsReplica } from "../src/index.js";
import { automergeInitializer, decodeBase64 } from "../src/wasm.js";

describe("initializeAutomerge", () => {
  // Node resolves the self-initializing build: a no-op here. The /slim path
  // runs in the Obsidian bundle (LFCP-059).
  it("is a no-op on the self-initializing build and leaves Automerge usable", async () => {
    expect(isAutomergeInitialized()).toBe(true);
    await initializeAutomerge();
    await initializeAutomerge();
    const { replica } = SharedObjectsReplica.create({
      resource: new Uint8Array(32).fill(1) as never,
      principal: new Uint8Array(32).fill(2) as never,
    });
    expect(replica.objectIds()).toEqual([]);
  });

  it("decodes standard base64 exactly", () => {
    expect(decodeBase64("AGFzbQEAAAA=")).toEqual(Uint8Array.of(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0));
    expect(decodeBase64("")).toEqual(new Uint8Array());
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(decodeBase64(btoa(String.fromCharCode(...all)))).toEqual(all);
  });

  it("shares one in-flight initialization between concurrent callers", async () => {
    let ready = false;
    let loads = 0;
    let release: () => void = () => undefined;
    const init = automergeInitializer({
      isInitialized: () => ready,
      loadBase64: async () => {
        loads++;
        return "AGFzbQ";
      },
      initialize: () =>
        new Promise<void>((r) => {
          release = () => {
            ready = true;
            r();
          };
        }),
    });
    const a = init();
    const b = init();
    expect(a).toBe(b);
    await Promise.resolve();
    await Promise.resolve();
    release();
    await Promise.all([a, b]);
    await init();
    expect(loads).toBe(1);
  });

  it("forgets a failed initialization so a later call retries", async () => {
    let ready = false;
    let attempts = 0;
    const init = automergeInitializer({
      isInitialized: () => ready,
      loadBase64: async () => "AGFzbQ",
      initialize: async () => {
        attempts++;
        if (attempts === 1) throw new Error("compile failed");
        ready = true;
      },
    });
    await expect(init()).rejects.toThrow("compile failed");
    await init();
    expect(attempts).toBe(2);
    expect(ready).toBe(true);
  });
});
