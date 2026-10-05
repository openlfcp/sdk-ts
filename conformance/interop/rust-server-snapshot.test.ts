// LFCP-039a follow-up: Snapshot catch-up against the Rust reference server,
// live. OWNER writes five units, publishes a Snapshot of its replica
// (SNAPSHOT_PUT), writes two more, and grants CAROL. CAROL, a fresh client,
// is offered the Snapshot in RESOURCE_OPENED, loads it (SNAPSHOT_GET,
// receiveSnapshot, loadSnapshot), accepts the frontier's last unit as
// covered, fetches only the two units beyond the frontier, and ends with a
// replica identical to OWNER's.

import { type ObjectId, resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setPriority,
  setStatus,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(12);
const CAROL = party(71);
const R = resourceId(bytes32(180));
const DEK0 = importResourceDEK(bytes32(92));
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

describe("Snapshot catch-up ↔ Rust reference server (live)", () => {
  it("a fresh client loads the published Snapshot and fetches only the tail", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: TS↔Rust Snapshot interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      const { replica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: OWNER.signer.descriptor.principalId,
      });
      const owner = new Side({
        url,
        resource: R,
        who: OWNER,
        profile: new SharedObjectsDataProfile(replica),
      });
      const genesis = await createResource(owner, url, DEK0);
      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");

      const task = (side: Side) => side.profile.replica.task(TASK)?.task as Task;
      const edit = (local: unknown) => owner.write(local as LocalChange);
      await edit(init); // 1
      await edit(
        owner.profile.replica.apply(
          createTask({ id: TASK, title: "Draft", createdBy: OWNER.signer.descriptor.principalId })
            .intent,
        ),
      ); // 2
      await edit(owner.profile.replica.apply(setTitle(task(owner), "Second").intent)); // 3
      await edit(owner.profile.replica.apply(setStatus(task(owner), "in_progress").intent)); // 4
      await edit(owner.profile.replica.apply(setPriority(task(owner), "high").intent)); // 5
      await waitFor("five units ACKed", () => owner.queueEmpty());
      await owner.client.publishSnapshot(R);
      await waitFor("Snapshot ACKed", () => owner.queueEmpty());
      await edit(owner.profile.replica.apply(setTitle(task(owner), "Final").intent)); // 6
      await edit(owner.profile.replica.apply(setStatus(task(owner), "done").intent)); // 7
      await grantAndKey(owner, CAROL, DEK0);
      await waitFor("tail, grant and Key Package ACKed", () => owner.queueEmpty());

      const carol = new Side({
        url,
        resource: R,
        who: CAROL,
        profile: new SharedObjectsDataProfile(
          SharedObjectsReplica.empty({
            resource: R,
            principal: CAROL.signer.descriptor.principalId,
          }),
        ),
      });
      carol.start();
      await waitFor("CAROL LIVE", () => carol.client.resourceState(R) === "LIVE");
      await waitFor(
        "CAROL converged",
        () =>
          JSON.stringify(carol.profile.replica.root()) ===
          JSON.stringify(owner.profile.replica.root()),
      );

      const loaded = carol.events.find((e) => e.type === "snapshot-loaded");
      expect(loaded?.type === "snapshot-loaded" && loaded.frontier).toEqual([
        { principalId: OWNER.signer.descriptor.principalId, contiguous: 5n, extras: [] },
      ]);
      const units = carol.events
        .filter((e) => e.type === "unit")
        .map((e) => (e.type === "unit" ? e.outcome.kind : ""));
      expect(units).toEqual(["covered", "applied", "applied"]);
      expect(task(carol)).toMatchObject({ title: "Final", status: "done", priority: "high" });
      expect(owner.errors()).toEqual([]);
      expect(carol.errors()).toEqual([]);
      await owner.stop();
      await carol.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 120_000);
});
