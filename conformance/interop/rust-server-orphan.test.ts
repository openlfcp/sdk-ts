// No Rust server outlives its test process. A test process that is SIGKILLed
// runs no afterAll and no exit handler; the watchdog started with each
// server (reaper.mjs) must still kill the server and remove its directory.
//
// Skipped (with the reason) when cargo or the server checkout is missing,
// and on Windows, which has no watchdog.

import { describe, expect, it } from "vitest";
import { checkOrphan } from "./rust-server-orphan.mjs";

declare const console: { warn(...a: unknown[]): void };
declare const process: { readonly platform: string };

describe("the Rust server harness (live)", () => {
  it("kills the server when the test process is SIGKILLed", async (ctx) => {
    if (process.platform === "win32") {
      console.warn("SKIPPED: orphan check (no watchdog on Windows)");
      ctx.skip();
      return;
    }
    const result = await checkOrphan(5000);
    if ("skip" in result) {
      console.warn(`SKIPPED: orphan check (${result.skip})`);
      ctx.skip();
      return;
    }
    expect(result).toEqual({ aliveBefore: true, serverAlive: false, dirExists: false });
  }, 600_000);
});
