// POST-017: a Resource the server does not host, live against the Rust
// reference server. The server answers RESOURCE_OPEN with
// NACK(RESOURCE_NOT_HOSTED) (WIRE-01 §41); the SyncClient must reach its
// terminal refusal (resource-refused, CLOSED) instead of waiting forever, and
// must not open it again on its own, while the connection stays up.
//
// Skipped (with the reason) when cargo or the server checkout is missing.

import { resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import { SharedObjectsDataProfile, SharedObjectsReplica } from "@openlfcp/shared-objects";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, party, Side, sleep, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(17);
const R = resourceId(bytes32(217));
const DEK0 = importResourceDEK(bytes32(97));

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

describe("a Resource the server does not host ↔ Rust reference server (live, POST-017)", () => {
  it("reaches the terminal RESOURCE_NOT_HOSTED refusal and does not retry", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: not-hosted interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    const { replica } = SharedObjectsReplica.create({
      resource: R,
      principal: OWNER.signer.descriptor.principalId,
    });
    // A Resource that exists on this device only: its Genesis was never
    // sent to the server (the same as a purged one, or a restored server).
    const owner = new Side({
      url,
      resource: R,
      who: OWNER,
      profile: new SharedObjectsDataProfile(replica),
    });
    await createResource(owner, url, DEK0);
    try {
      owner.start();
      await waitFor("the refusal", () => owner.client.resourceRefusal(R) !== null);
      expect(owner.client.resourceRefusal(R)).toEqual({
        code: "RESOURCE_NOT_HOSTED",
        url,
        request: "open",
      });
      expect(owner.client.resourceState(R)).toBe("CLOSED");
      expect(owner.events.filter((e) => e.type === "resource-refused")).toHaveLength(1);
      // The connection stays up, and the Resource is not opened again.
      await sleep(3000);
      expect(owner.client.connectionState).toBe("READY");
      expect(owner.events.filter((e) => e.type === "resource-refused")).toHaveLength(1);
      expect(
        owner.events.filter((e) => e.type === "resource-state" && e.state === "OPENING"),
      ).toHaveLength(1);
    } finally {
      await owner.stop();
    }
  }, 60_000);
});
