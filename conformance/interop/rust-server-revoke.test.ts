// LFCP-02-060: removing a member against the Rust reference server, live.
// OWNER grants BOB and CAROL and writes a Task. Offline, revokeAccess is
// refused and queues nothing. Live, OWNER revokes BOB: the server commits
// the revocation and the Key Epoch, CAROL receives the new DEK in a Key
// Package and reads what OWNER writes after it, and BOB never gets that
// edit.

import { type ObjectId, resourceId, toHex } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, sleep, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(13);
const BOB = party(53);
const CAROL = party(63);
const R = resourceId(bytes32(190));
const DEK0 = importResourceDEK(bytes32(94));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId;

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

const member = (url: string, who: typeof OWNER) =>
  new Side({
    url,
    resource: R,
    who,
    profile: new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: who.signer.descriptor.principalId }),
    ),
  });

describe("revokeAccess ↔ Rust reference server (live, LFCP-02-060)", () => {
  it("revokes a member, rotates the epoch, and keys only the remaining reader", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: revoke interop (${skip})`);
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
      await owner.write(init);
      // Not live yet: refused, nothing queued.
      expect(await owner.client.revokeAccess(R, BOB.signer.descriptor.principalId)).toMatchObject({
        kind: "refused",
        reason: "offline",
      });
      owner.start({ open: false });
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      await grantAndKey(owner, BOB, DEK0);
      await waitFor("BOB granted", () => owner.controlSettled(1n), 30_000);
      await grantAndKey(owner, CAROL, DEK0);
      await waitFor("CAROL granted", () => owner.controlSettled(2n), 30_000);
      const task = (side: Side) => side.profile.replica.task(TASK)?.task as Task;
      await owner.write(
        owner.profile.replica.apply(
          createTask({ id: TASK, title: "Before", createdBy: OWNER.signer.descriptor.principalId })
            .intent,
        ) as LocalChange,
      );
      const bob = member(url, BOB);
      const carol = member(url, CAROL);
      bob.start();
      carol.start();
      await waitFor("BOB has the Task", () => task(bob)?.title === "Before", 30_000);
      await waitFor("CAROL has the Task", () => task(carol)?.title === "Before", 30_000);

      const result = await owner.client.revokeAccess(R, BOB.signer.descriptor.principalId);
      expect(result).toMatchObject({ kind: "queued", epoch: 1n, remainingPaths: [] });
      if (result.kind !== "queued") throw new Error("not queued");
      expect(result.recordIds).toHaveLength(2);
      expect(result.recipients.map(toHex)).toEqual([toHex(CAROL.signer.descriptor.principalId)]);
      // The coordinator commits the revocation and the Key Epoch.
      await waitFor("OWNER at the new epoch", () => owner.controlSettled(4n), 30_000);
      const head = await owner.storage.control.epochs(R);
      expect(head.map((e) => e.epoch)).toContain(1n);

      await owner.write(
        owner.profile.replica.apply(setTitle(task(owner), "After").intent) as LocalChange,
      );
      await waitFor("OWNER edit ACKed", () => owner.queueEmpty(), 30_000);
      await waitFor("CAROL reads the new epoch", () => task(carol)?.title === "After", 30_000);
      // BOB is not keyed for epoch 1 (and no longer authorized): he never gets the edit.
      await sleep(1_500);
      expect(task(bob)?.title).toBe("Before");
      expect(
        (await bob.storage.control.epochs(R)).find((e) => e.epoch === 1n)?.dekRef ?? null,
      ).toBeNull();
      await owner.stop();
      await bob.stop();
      await carol.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 180_000);
});
