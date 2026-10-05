// LFCP-039a: the TypeScript client against the Rust reference server, live.
// The first TS↔Rust interop over a real WebSocket:
//
// 1. OWNER hosts a new Resource (RESOURCE_HOST), opens it, grants BOB
//    (CONTROL_PUT) and sends BOB a Key Package (KEY_PACKAGE_PUT), all
//    through the outbound queue;
// 2. BOB connects, opens the Resource, catches up Control, Keys and Data;
// 3. OWNER creates a Task (DATA_PUT); BOB receives the live push;
// 4. BOB goes offline and edits while OWNER edits too; BOB reconnects and
//    both replicas converge.
//
// Skipped (with the reason) when cargo or the server checkout is missing.

import { type ObjectId, resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(11);
const BOB = party(51);
const R = resourceId(bytes32(170));
const DEK0 = importResourceDEK(bytes32(90));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

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

describe("SyncClient ↔ Rust reference server (live)", () => {
  it("hosts, grants, catches up, pushes live, and converges after an offline edit", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: TS↔Rust interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      const { replica: ownerReplica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: OWNER.signer.descriptor.principalId,
      });
      const owner = new Side({
        url,
        resource: R,
        who: OWNER,
        profile: new SharedObjectsDataProfile(ownerReplica),
      });
      const genesis = await createResource(owner, url, DEK0);
      await owner.write(init);

      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      expect(await owner.client.host(genesis.bytes)).toBe(2n);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      await waitFor("OWNER init sent", () => owner.queueEmpty());

      await grantAndKey(owner, BOB, DEK0);
      await waitFor("grant and Key Package ACKed", () => owner.queueEmpty());
      await waitFor(
        "OWNER holds the grant",
        async () => (await owner.storage.control.head(R))?.controlSeq === 1n,
      );

      const bob = new Side({
        url,
        resource: R,
        who: BOB,
        profile: new SharedObjectsDataProfile(
          SharedObjectsReplica.empty({ resource: R, principal: BOB.signer.descriptor.principalId }),
        ),
      });
      bob.start();
      await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE");
      expect((await bob.storage.control.head(R))?.controlSeq).toBe(1n);
      expect(bob.profile.replica.root()).toEqual(owner.profile.replica.root());

      const task = (side: Side) => side.profile.replica.task(TASK)?.task as Task;
      await owner.write(
        owner.profile.replica.apply(
          createTask({
            id: TASK,
            title: "Prepare API contract",
            createdBy: OWNER.signer.descriptor.principalId,
          }).intent,
        ) as LocalChange,
      );
      await waitFor("BOB has the Task", () => task(bob)?.title === "Prepare API contract");

      await bob.client.stop();
      await bob.write(
        bob.profile.replica.apply(setTitle(task(bob), "Final API contract").intent) as LocalChange,
      );
      await owner.write(
        owner.profile.replica.apply(setStatus(task(owner), "in_progress").intent) as LocalChange,
      );
      await waitFor("OWNER edit ACKed", () => owner.queueEmpty());
      bob.start();
      await waitFor("BOB edit ACKed", () => bob.queueEmpty());
      await waitFor(
        "convergence",
        () =>
          task(owner)?.title === "Final API contract" &&
          task(bob)?.status === "in_progress" &&
          JSON.stringify(owner.profile.replica.root()) ===
            JSON.stringify(bob.profile.replica.root()),
      );
      expect(owner.errors()).toEqual([]);
      expect(bob.errors()).toEqual([]);
      await owner.stop();
      await bob.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 120_000);
});
