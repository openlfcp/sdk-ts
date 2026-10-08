// ADR 0008, live: recovery after server data loss against the Rust
// reference server (LFCP-WIRE-01 §41.1, §51.1, §68.1; LFCP-02-088). The
// server's store is replaced by an older copy of itself, as a restore from
// backup does, while the clients keep what they hold.
//
// 1. Lost unit (the 2026-10-06 drill): OWNER writes units 1..3, the store
//    is copied, OWNER writes 4 (acknowledged) and the copy is restored.
//    OWNER writes 5 while offline. On reconnect OWNER re-supplies 4 before
//    5, and BOB, joining afterwards, catches up on 1..5 with no
//    NO_PROGRESS.
// 2. Lost Resource: the store is copied before the Resource is hosted and
//    restored after OWNER hosted it, granted BOB and wrote. OWNER re-hosts
//    it from its Genesis and re-supplies the Control Records, units and
//    BOB's Key Package; BOB then joins and converges.

import { type ObjectId, resourceId } from "@openlfcp/core";
import { importResourceDEK } from "@openlfcp/crypto";
import {
  createTask,
  type LocalChange,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import { bytes32, createResource, grantAndKey, party, Side, waitFor } from "./harness.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const console: { warn(...a: unknown[]): void };

const OWNER = party(14);
const BOB = party(54);
const DEK0 = importResourceDEK(bytes32(94));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

/** OWNER's side for `R`, with its Genesis stored (not hosted yet). */
async function ownerOf(url: string, R: ReturnType<typeof resourceId>) {
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
  return { owner, genesis, init };
}

const bobOf = (url: string, R: ReturnType<typeof resourceId>) =>
  new Side({
    url,
    resource: R,
    who: BOB,
    profile: new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: BOB.signer.descriptor.principalId }),
    ),
  });

const task = (side: Side) => side.profile.replica.task(TASK)?.task as Task;
const edit = (side: Side, title: string) =>
  side.write(side.profile.replica.apply(setTitle(task(side), title).intent) as LocalChange);
const same = (a: Side, b: Side) =>
  JSON.stringify(a.profile.replica.root()) === JSON.stringify(b.profile.replica.root());
const noProgress = (side: Side) =>
  side.errors().filter((e) => e.type === "error" && e.code === "NO_PROGRESS");

async function withServer(
  ctx: { skip(): void },
  body: (server: RunningRustServer) => Promise<void>,
): Promise<void> {
  const started = await startRustServer();
  if ("skip" in started) {
    console.warn(`SKIPPED: ADR 0008 recovery interop (${started.skip})`);
    ctx.skip();
    return;
  }
  try {
    await body(started);
  } catch (e) {
    throw new Error(
      `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${started.log().slice(-4000)}`,
    );
  } finally {
    await started.stop();
  }
}

describe("recovery after server data loss ↔ Rust reference server (live, ADR 0008)", () => {
  it(
    "re-supplies an acknowledged unit the restored server lost; a new reader catches up",
    (ctx) =>
      withServer(ctx, async (server) => {
        const R = resourceId(bytes32(191));
        const { owner, genesis, init } = await ownerOf(server.url, R);
        owner.start({ open: false });
        await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
        await owner.client.host(genesis.bytes);
        owner.open();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
        await owner.write(init); // 1
        await owner.write(
          owner.profile.replica.apply(
            createTask({ id: TASK, title: "Draft", createdBy: OWNER.signer.descriptor.principalId })
              .intent,
          ) as LocalChange,
        ); // 2
        await edit(owner, "three"); // 3
        await grantAndKey(owner, BOB, DEK0);
        await waitFor("OWNER queue empty", () => owner.queueEmpty());
        const backup = server.files();
        await edit(owner, "four, lost by the server"); // 4
        await waitFor("unit 4 acknowledged", () => owner.queueEmpty());

        await owner.client.stop();
        await server.restore(backup);
        await edit(owner, "five, written offline"); // 5, names 4
        owner.start();
        await waitFor("OWNER LIVE again", () => owner.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("OWNER queue empty again", () => owner.queueEmpty(), 30_000);

        const bob = bobOf(server.url, R);
        bob.start();
        await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("BOB converges", () => same(owner, bob), 30_000);
        expect(task(bob)?.title).toBe("five, written offline");
        expect(noProgress(bob)).toEqual([]);
        expect(owner.errors()).toEqual([]);
        expect(bob.errors()).toEqual([]);
        await owner.stop();
        await bob.stop();
      }),
    120_000,
  );

  it(
    "re-hosts a Resource the restored server lost and re-supplies all of it",
    (ctx) =>
      withServer(ctx, async (server) => {
        const R = resourceId(bytes32(192));
        const empty = server.files(); // before the Resource is hosted
        const { owner, genesis, init } = await ownerOf(server.url, R);
        owner.start({ open: false });
        await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
        await owner.client.host(genesis.bytes);
        owner.open();
        await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
        await owner.write(init);
        await owner.write(
          owner.profile.replica.apply(
            createTask({
              id: TASK,
              title: "Hosted",
              createdBy: OWNER.signer.descriptor.principalId,
            }).intent,
          ) as LocalChange,
        );
        await grantAndKey(owner, BOB, DEK0);
        await waitFor("OWNER queue empty", () => owner.queueEmpty());

        await owner.client.stop();
        await server.restore(empty);
        owner.start();
        await waitFor(
          "OWNER re-hosted",
          () => owner.events.some((e) => e.type === "rehost" && e.outcome === "hosted"),
          30_000,
        );
        await waitFor("OWNER LIVE again", () => owner.client.resourceState(R) === "LIVE", 30_000);

        const bob = bobOf(server.url, R);
        bob.start();
        await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE", 30_000);
        await waitFor("BOB converges", () => same(owner, bob), 30_000);
        expect(task(bob)?.title).toBe("Hosted");
        expect((await bob.storage.control.head(R))?.controlSeq).toBe(1n);
        expect(owner.events.some((e) => e.type === "resource-refused")).toBe(false);
        expect(noProgress(bob)).toEqual([]);
        expect(bob.errors()).toEqual([]);
        await owner.stop();
        await bob.stop();
      }),
    120_000,
  );
});
